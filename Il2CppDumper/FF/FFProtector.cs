using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Il2CppDumper
{
    /// <summary>
    /// Desempacota o protector ELF usado pelo Free Fire (com.dts.freefireth /
    /// com.dts.freefiremax), pelo Call of Duty Mobile e por outros alvos
    /// empacotados com o mesmo stub.
    ///
    /// O stub e anexado no fim do .so (varios PT_LOAD apontando pro mesmo file
    /// offset) e roda via DT_INIT. Ele exporta "stub_decrypt_elf" e carrega um
    /// descritor com magic 0x12345678. O codigo que faz a transformacao nao
    /// esta no libil2cpp: o stub chama g_acf_array[1], um import resolvido do
    /// libanort.so.
    ///
    /// Esquema completo, reversado do libanort e validado byte a byte contra
    /// dump de memoria em Free Fire (arm32 e arm64) e contra o CRC do proprio
    /// descritor no Call of Duty Mobile:
    ///
    ///   TABELA. Uma tabela unica no fim do arquivo, achada pelo magic. O magic
    ///   so aparece na ENTRADA 0; a quantidade de entradas esta num u32 em
    ///   tabela+0x18C e as entradas vem de 0x30 em 0x30. Cada entrada tem a sua
    ///   secao, o seu CRC32 e o seu PT_LOAD - o Free Fire usa uma (.rodata), o
    ///   CoD Mobile usa tres (.rodata, .text, il2cpp).
    ///
    ///   CHAVES. K = uint32 big-endian em keyblob[12:16], onde keyblob e o
    ///   base64 do descritor+0x1A8 decodificado e XOR com uma constante de
    ///   ofuscacao. A constante e RESOLVIDA por arquivo (ver
    ///   <see cref="TrySolveObfuscation"/>), nao chumbada: 0x4F no Free Fire,
    ///   0x98 no CoD Mobile. Todo o material de chave sai de K: a chave XOR do
    ///   bulk e (K &gt;&gt; 16) &amp; 0xFF e a chave AES e o ASCII de
    ///   "%08x%08x" % (K, K).
    ///
    ///   REGIAO. A secao do descritor, comecando em (offset &amp; ~0xFFF) + 0x2000,
    ///   com 0x4000 bytes cifrados a cada 0x10000. A ultima janela nao e
    ///   cortada em 0x4000: ela vai ate o fim da secao.
    ///
    ///   Secao menor que 1 MB: XOR puro na regiao inteira, sem AES nem permuta.
    ///
    ///   Senao:
    ///     janela 0 (0x4000 bytes) = AES-128-CBC, IV fixo 02..11, em 8 blocos
    ///       independentes de 0x800 com o IV reiniciado a cada bloco;
    ///     da janela FirstGroupIndex ate o ultimo grupo de 8 completo = XOR de
    ///       1 byte + permutacao entre slots de 0x10000 (algo 1), ou XOR puro
    ///       sem permutacao (algo 2, descritor+0x188);
    ///     o que sobra no fim (a cauda que nao completa um grupo) = XOR puro.
    ///
    ///   FirstGroupIndex tambem e por build - 2 no Free Fire, 1 no CoD Mobile -
    ///   e tambem e DESCOBERTO aqui, varrendo os candidatos contra o CRC32 do
    ///   descritor, do mesmo jeito que a permutacao.
    ///
    /// O descritor carrega em +0x20 o CRC32 de cada secao em claro, entao o
    /// resultado se verifica sozinho, secao por secao.
    /// </summary>
    public static class FFProtector
    {
        public const uint Magic = 0x12345678;

        /// O que sabemos sobre a protecao depois de olhar o arquivo. O
        /// upstream decide isso por heuristica (tem DT_INIT? exporta
        /// JNI_OnLoad?), mas essas duas coisas estao em praticamente todo
        /// libil2cpp.so, empacotado ou nao - nas cinco amostras de Free Fire
        /// que temos, as duas batem em 100% delas, inclusive nas que nao usam
        /// packer nenhum. Entao a heuristica nao separa nada e o veredito real
        /// tem que vir daqui, onde de fato desempacotamos e conferimos o CRC.
        public enum State
        {
            /// Nenhum descritor 0x12345678: este packer nao esta no arquivo.
            NotDetected,

            /// Descritor presente, mas as secoes ja estao em claro - tipico de
            /// um .so tirado da memoria, que o loader ja desempacotou.
            AlreadyPlain,

            /// Desempacotado e o CRC32 do descritor fechou: byte-exato.
            Unpacked,

            /// Empacotado e NAO recuperado - seja porque o CRC32 nao fechou,
            /// seja porque nem deu pra confirmar a chave. A saida nao presta.
            Failed,

            /// Empacotado, mas o UnpackProtected do config.json esta desligado.
            Skipped,
        }

        public static State Status = State.NotDetected;

        /// O indicio fraco que o ELF encontrou (.init_proc, JNI_OnLoad...),
        /// guardado em vez de impresso. Sozinho ele nao quer dizer nada, mas
        /// se a busca automatica falhar la na frente ele vira uma pista util.
        public static string WeakIndicator;

        /// Atalho pra "nao ha nada empacotado atrapalhando daqui pra frente".
        public static bool Handled => Status == State.Unpacked || Status == State.AlreadyPlain;

        /// Registra o resultado pra quem for reportar protecao mais adiante.
        public static void Record(Result r)
        {
            Status = !r.Detected ? State.NotDetected
                   : r.SkippedByConfig ? State.Skipped
                   : r.LooksAlreadyPlain ? State.AlreadyPlain
                   : !r.Unpacked ? State.Failed        // detectado e desistimos no meio
                   : r.ChecksumVerified ? State.Unpacked
                   : State.Failed;
        }

        private const int WindowSize = 0x4000;
        private const int SlotStride = 0x10000;
        private const int FirstWindowPhase = 0x2000;

        /// Abaixo disso o packer nem usa AES nem permuta: XOR puro na regiao.
        private const long SmallSectionLimit = 0x100000;

        // --- campos da TABELA (relativos ao inicio dela, onde esta o magic) ---
        private const int KeyByteOffset = 0x186;    // chave XOR, ofuscada
        private const int AlgoOffset = 0x188;       // 1 = XOR + permuta, 2 = XOR
        private const int EntryCountOffset = 0x18c; // quantas secoes o packer cifrou
        private const int KeyBlobOffset = 0x1a8;    // base64 com o material de chave
        private const int TableSpan = 0x200;        // o quanto a tabela precisa caber
        private const int MaxEntries = 16;

        // --- campos de cada ENTRADA (stride 0x30) ---
        private const int EntryStride = 0x30;
        private const int EntryNameOffset = 0x04;   // char[0x10], terminado em NUL
        private const int EntryVaddrOffset = 0x14;  // endereco virtual da secao
        private const int EntryFileOffset = 0x18;   // OFFSET DE ARQUIVO da secao
        private const int EntrySizeOffset = 0x1c;
        private const int EntryCrcOffset = 0x20;    // CRC32 da secao em claro
        private const int EntrySegVaddrOffset = 0x24;
        private const int EntrySegFileSizeOffset = 0x28;
        private const int EntryKindOffset = 0x2c;   // p_flags do PT_LOAD da secao

        /// Chave XOR usada quando o byte correspondente de K e zero.
        private const byte FallbackXorKey = 0x87;

        private const int Window0ChunkSize = 0x800;
        private static readonly byte[] Window0Iv =
        {
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
        };

        /// Dentro de cada grupo as 8 janelas sao reordenadas por uma permutacao
        /// sigma, onde a janela na posicao p do grupo vem da posicao sigma[p].
        private const int GroupSize = 8;

        /// Em que janela a regiao permutada COMECA. E por build (2 no Free Fire,
        /// 1 no CoD Mobile), entao os candidatos sao varridos contra o CRC32 do
        /// descritor em <see cref="UnpackSection"/>. A janela 0 e AES e nao se
        /// move, entao 0 nao e candidato, e 1..8 ja cobre todas as fases
        /// possiveis de grupo.
        private const int FirstGroupCandidateMin = 1;
        private const int FirstGroupCandidateMax = GroupSize;

        /// Usado so quando o CRC nao fecha com nenhum candidato - nesse caso a
        /// saida vai ser recusada de qualquer jeito, mas deixar o buffer no
        /// formato dos builds conhecidos e o que da chance pro sidecar de
        /// janela 0 (<see cref="FFWindow0Patch"/>) resgatar o dump.
        private const int FirstGroupIndexFallback = 2;

        private static readonly int[] Identity = { 0, 1, 2, 3, 4, 5, 6, 7 };

        /// Sigma nao e fixa: cada build do packer usa a sua. Estas sao as ja
        /// vistas e servem de atalho; qualquer outra sai do solver, que usa o
        /// CRC32 do descritor como oraculo.
        private static readonly int[][] KnownPermutations =
        {
            new[] { 4, 0, 6, 2, 1, 3, 5, 7 },   // FF global 1.132.1, FF MAX 2.133.1
            new[] { 3, 4, 0, 2, 6, 1, 5, 7 },   // FF MAX 2.132.1 (arm32 e arm64)
            Identity,
        };

        public sealed class Descriptor
        {
            /// Onde comeca a TABELA (o magic), nao a entrada.
            public long FilePosition;

            /// Indice desta entrada dentro da tabela.
            public int Entry;

            public string Name;
            public uint Offset;            // tabela+0x18: offset de arquivo
            public uint VirtualAddress;    // tabela+0x14
            public uint Size;
            public uint Checksum;
            public uint SegmentVirtualAddress;
            public uint FirstLoadFileSize;
            public uint Kind;
            public uint Algo;

            public override string ToString() =>
                $"{Name} offset=0x{Offset:x} vaddr=0x{VirtualAddress:x} size=0x{Size:x}";
        }

        /// O que aconteceu com UMA secao do descritor.
        public sealed class SectionResult
        {
            public Descriptor Section;

            /// A secao ja estava em claro (CRC cru = CRC do descritor).
            public bool AlreadyPlain;

            /// A secao nao fecha o CRC do descritor, mas o conteudo tambem nao
            /// esta cifrado: e uma imagem de processo vivo, que difere do
            /// arquivo por patches feitos em runtime. Mexer nela seria estragar
            /// o que ja esta bom, entao ela fica como esta - e sem verificacao.
            public bool PlainUnverified;

            /// Quantas janelas tem como byte dominante a chave XOR e quantas
            /// tem 0x00. E isso que separa "cifrada" de "imagem viva": nas
            /// amostras a separacao e de 75-87% contra 0%.
            public int KeyDominatedWindows;
            public int ZeroDominatedWindows;

            /// A secao nao cabe no arquivo; nao ha o que fazer com ela.
            public bool PastEndOfFile;

            public string Window0Method = "not attempted";
            public int[] Permutation = Identity;
            public string PermutationSource = "";
            public int FirstGroupIndex;
            public int WindowsTotal;
            public int WindowsRecovered;
            public int WindowsSkipped;
            public uint ExpectedCrc;
            public uint ActualCrc;
            public bool ChecksumVerified;
            public long BytesUnrecovered;
            public string Window0PatchFrom;
        }

        public sealed class Result
        {
            public bool Detected;
            public bool Unpacked;

            /// Primeira secao do descritor, mantida pra quem so quer uma.
            public Descriptor Descriptor;

            /// Todas as secoes que o descritor declara.
            public List<Descriptor> Descriptors = new List<Descriptor>();

            /// As secoes cujo CRC32 TEM que fechar no buffer final. E igual a
            /// <see cref="Descriptors"/> menos as que ficaram
            /// <see cref="SectionResult.PlainUnverified"/>, que sao imagem de
            /// processo vivo e nao tem CRC pra fechar.
            public List<Descriptor> SectionsToVerify
            {
                get
                {
                    var list = new List<Descriptor>();
                    foreach (var sr in Sections)
                        if (!sr.PlainUnverified) list.Add(sr.Section);
                    if (Sections.Count == 0) list.AddRange(Descriptors);
                    return list;
                }
            }

            public List<SectionResult> Sections = new List<SectionResult>();

            public byte Key;
            public string KeySource = "";
            public byte ObfuscationConstant;
            public uint AesSeed;
            public uint BuildDate;

            /// Todas as secoes fecharam o CRC32 do descritor (ou ja estavam em claro).
            public bool ChecksumVerified;

            /// Descritor presente mas as secoes ja estao em claro (dump de memoria).
            public bool LooksAlreadyPlain;

            /// Nao tentamos desempacotar porque UnpackProtected esta desligado.
            public bool SkippedByConfig;

            public byte[] Data;
        }

        /// <summary>
        /// Procura a tabela do protector no arquivo inteiro. Devolve a posicao
        /// do magic ou -1.
        /// </summary>
        public static long FindTable(byte[] data)
        {
            for (long i = 0; i + TableSpan <= data.Length; i += 4)
            {
                if (BitConverter.ToUInt32(data, (int)i) != Magic) continue;

                // A entrada 0 tem que ter nome de secao legivel e a tabela tem
                // que declarar uma quantidade plausivel de entradas; senao e um
                // 0x12345678 qualquer dentro dos dados.
                if (ReadName(data, (int)i + EntryNameOffset) == null) continue;
                var count = BitConverter.ToUInt32(data, (int)i + EntryCountOffset);
                if (count < 1 || count > MaxEntries) continue;
                if (ReadEntries(data, i).Count == 0) continue;
                return i;
            }
            return -1;
        }

        /// <summary>
        /// Le as entradas da tabela. A quantidade vem de tabela+0x18C: so a
        /// entrada 0 carrega o magic, entao enumerar por magic acharia uma so.
        /// Entradas zeradas ou que nao cabem no arquivo sao descartadas - o
        /// Free Fire declara 3 e preenche 1.
        /// </summary>
        public static List<Descriptor> ReadEntries(byte[] data, long table)
        {
            var list = new List<Descriptor>();
            if (table < 0 || table + TableSpan > data.Length) return list;

            var count = BitConverter.ToUInt32(data, (int)table + EntryCountOffset);
            if (count < 1 || count > MaxEntries) return list;
            uint algo = BitConverter.ToUInt32(data, (int)table + AlgoOffset);

            for (int e = 0; e < count; e++)
            {
                long at = table + (long)e * EntryStride;
                if (at + EntryStride > data.Length) break;

                var d = new Descriptor
                {
                    FilePosition = table,
                    Entry = e,
                    Name = ReadName(data, (int)at + EntryNameOffset, requireDot: false) ?? "",
                    VirtualAddress = BitConverter.ToUInt32(data, (int)at + EntryVaddrOffset),
                    Offset = BitConverter.ToUInt32(data, (int)at + EntryFileOffset),
                    Size = BitConverter.ToUInt32(data, (int)at + EntrySizeOffset),
                    Checksum = BitConverter.ToUInt32(data, (int)at + EntryCrcOffset),
                    SegmentVirtualAddress = BitConverter.ToUInt32(data, (int)at + EntrySegVaddrOffset),
                    FirstLoadFileSize = BitConverter.ToUInt32(data, (int)at + EntrySegFileSizeOffset),
                    Kind = BitConverter.ToUInt32(data, (int)at + EntryKindOffset),
                    Algo = algo,
                };
                if (d.Size == 0 || d.Offset == 0) continue;
                if ((long)d.Offset + d.Size > data.Length) continue;
                list.Add(d);
            }
            return list;
        }

        /// <summary>Primeira secao do descritor, ou null se nao ha descritor.</summary>
        public static Descriptor FindDescriptor(byte[] data)
        {
            long table = FindTable(data);
            if (table < 0) return null;
            var entries = ReadEntries(data, table);
            return entries.Count > 0 ? entries[0] : null;
        }

        private static string ReadName(byte[] data, int at, bool requireDot = true)
        {
            var sb = new StringBuilder();
            for (int k = 0; k < 16; k++)
            {
                if (at + k >= data.Length) return null;
                byte b = data[at + k];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) return null;
                sb.Append((char)b);
            }
            if (sb.Length < 2) return null;
            // A entrada 0 sempre e uma secao do ELF (".rodata", ".text"), e exigir
            // o ponto e o que separa a tabela de verdade de um 0x12345678 solto.
            // As entradas seguintes nao: no CoD Mobile a terceira se chama "il2cpp".
            if (requireDot && sb[0] != '.') return null;
            return sb.ToString();
        }

        /// <summary>
        /// Detecta e, se o conteudo estiver mesmo embaralhado, desempacota todas
        /// as secoes que o descritor declara. Devolve sempre um Result; Data e o
        /// buffer a usar daqui pra frente.
        /// </summary>
        public static Result TryUnpack(byte[] data, bool enabled = true, string inputPath = null)
        {
            var r = new Result { Data = data };
            long table = FindTable(data);
            if (table < 0) return r;

            var entries = ReadEntries(data, table);
            if (entries.Count == 0) return r;

            r.Detected = true;
            r.Descriptors = entries;
            r.Descriptor = entries[0];
            if (!enabled) { r.SkippedByConfig = true; return r; }

            // Quem ja esta em claro se denuncia sozinho: o CRC32 gravado no
            // descritor fecha com a secao crua. Isso e exato e de graca, e
            // substitui o teste antigo ("o byte dominante das janelas e 0x00?"),
            // que so olhava a primeira secao e nao tinha nada a dizer sobre as
            // outras duas do CoD Mobile.
            var packed = new List<Descriptor>();
            foreach (var d in entries)
            {
                if (LooksPlain(data, d)) continue;
                packed.Add(d);
            }

            if (packed.Count == 0)
            {
                r.LooksAlreadyPlain = true;
                foreach (var d in entries)
                    r.Sections.Add(new SectionResult
                    {
                        Section = d, AlreadyPlain = true, ExpectedCrc = d.Checksum,
                        ActualCrc = d.Checksum, ChecksumVerified = d.Checksum != 0,
                    });
                return r;
            }

            var blob = ReadKeyBlob(data, table, out byte obf);
            r.ObfuscationConstant = obf;
            if (blob != null)
                r.BuildDate = (uint)((blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3]);

            if (!ResolveKey(data, table, obf, blob, packed[0], out byte key, out string keySource))
            {
                Console.WriteLine("WARNING: packed section detected but the key could not be confirmed; leaving it alone.");
                return r;
            }
            r.Key = key;
            r.KeySource = keySource;

            uint seed = blob != null
                ? (uint)((blob[12] << 24) | (blob[13] << 16) | (blob[14] << 8) | blob[15])
                : 0u;
            r.AesSeed = seed;

            // A copia do arquivo inteiro so e feita se alguma secao realmente
            // for decifrada - num dump de memoria de 250 MB nao ha por que
            // duplicar o buffer pra nao mexer em nada.
            byte[] outBuf = null;

            // FirstGroupIndex e por BUILD, nao por secao: o primeiro que fechar
            // o CRC vira o candidato preferido das secoes seguintes, mas cada
            // secao confirma por conta propria.
            int knownFirstGroup = 0;

            foreach (var d in entries)
            {
                var sr = new SectionResult { Section = d, ExpectedCrc = d.Checksum };
                r.Sections.Add(sr);

                if (!packed.Contains(d))
                {
                    sr.AlreadyPlain = true;
                    sr.ActualCrc = d.Checksum;
                    sr.ChecksumVerified = d.Checksum != 0;
                    continue;
                }

                long sectionEnd = (long)d.Offset + d.Size;
                ClassifyWindows(data, EnumerateWindows(d.Offset, sectionEnd), sectionEnd, key,
                                out int keyWindows, out int zeroWindows, out int windowCount);
                sr.KeyDominatedWindows = keyWindows;
                sr.ZeroDominatedWindows = zeroWindows;
                sr.WindowsTotal = windowCount;

                // Cifrada, o byte dominante das janelas e a chave; em claro, e
                // 0x00. Quando o CRC nao fecha mas as janelas dizem "em claro",
                // o arquivo e uma imagem de processo vivo: o loader ja
                // desempacotou e o que difere do arquivo sao patches de runtime
                // (no .text do CoD Mobile, 136 bytes em 19,7 MB). Decifrar em
                // cima disso so estragaria, entao a secao fica intacta e sem
                // CRC pra fechar - e o relatorio diz isso em voz alta.
                if (keyWindows * 2 <= windowCount && zeroWindows * 2 > windowCount)
                {
                    sr.PlainUnverified = true;
                    sr.ActualCrc = FFCrc32.Compute(data, d.Offset, d.Size);
                    continue;
                }

                outBuf ??= (byte[])data.Clone();
                UnpackSection(data, outBuf, d, key, seed, ref knownFirstGroup, sr);

                sr.ActualCrc = FFCrc32.Compute(outBuf, d.Offset, d.Size);
                sr.ChecksumVerified = d.Checksum != 0 && sr.ActualCrc == d.Checksum;

                // Rede de seguranca: se a cifra da janela 0 mudar num build
                // futuro, um sidecar capturado de dump de memoria ainda resolve.
                if (!sr.ChecksumVerified &&
                    FFWindow0Patch.TryApply(outBuf, d.Checksum, inputPath, out var patchFrom))
                {
                    sr.ActualCrc = FFCrc32.Compute(outBuf, d.Offset, d.Size);
                    sr.ChecksumVerified = sr.ActualCrc == d.Checksum;
                    if (sr.ChecksumVerified)
                    {
                        sr.Window0PatchFrom = patchFrom;
                        sr.BytesUnrecovered = 0;
                    }
                }
            }

            // "Desempacotado" e so se alguma secao foi de fato decifrada. Se
            // todas ficaram como estavam (em claro, verificaveis ou nao), o
            // veredito e o mesmo de sempre: ja vinha desempacotado.
            bool anyUnpacked = outBuf != null;
            r.ChecksumVerified = true;
            foreach (var sr in r.Sections)
            {
                if (sr.AlreadyPlain || sr.PlainUnverified) continue;
                if (!sr.ChecksumVerified) r.ChecksumVerified = false;
            }
            r.Unpacked = anyUnpacked;
            r.LooksAlreadyPlain = !anyUnpacked;
            r.Data = outBuf ?? data;
            return r;
        }

        /// <summary>
        /// A secao ja esta em claro? O CRC32 do descritor responde sozinho, sem
        /// heuristica de bytes: se ele fecha com o conteudo cru, o loader (ou
        /// quem produziu o arquivo) ja desempacotou.
        ///
        /// Num dump de memoria a secao mora no ENDERECO VIRTUAL, que no CoD
        /// Mobile e 0x4000 acima do offset de arquivo em .text e no blob
        /// il2cpp - por isso as duas posicoes sao conferidas. Sem isso um dump
        /// de memoria seria "desempacotado" em cima do que ja estava em claro.
        ///
        /// Quando a entrada nao carrega CRC nao ha o que conferir e sobra a
        /// heuristica antiga: num .rodata em claro o byte dominante e 0x00.
        /// </summary>
        private static bool LooksPlain(byte[] data, Descriptor d)
        {
            if (d.Checksum != 0)
            {
                if (FFCrc32.Compute(data, d.Offset, d.Size) == d.Checksum) return true;
                if (d.VirtualAddress != d.Offset &&
                    (long)d.VirtualAddress + d.Size <= data.Length &&
                    FFCrc32.Compute(data, d.VirtualAddress, d.Size) == d.Checksum) return true;
                return false;
            }

            long end = (long)d.Offset + d.Size;
            return MostFrequentByte(data, EnumerateWindows(d.Offset, end), end) == 0;
        }

        /// <summary>
        /// Desempacota uma secao dentro de <paramref name="outBuf"/>, varrendo
        /// FirstGroupIndex e a permutacao contra o CRC32 do descritor.
        /// </summary>
        private static void UnpackSection(byte[] data, byte[] outBuf, Descriptor d, byte key,
                                          uint seed, ref int knownFirstGroup, SectionResult sr)
        {
            long start = d.Offset;
            long end = start + d.Size;
            var windows = EnumerateWindows(start, end);
            sr.WindowsTotal = windows.Count;
            if (windows.Count == 0) return;

            if (d.Size < SmallSectionLimit)
            {
                // Secao pequena: o packer so faz XOR, sem AES e sem permuta.
                for (long i = windows[0].start; i < end; i++)
                    outBuf[i] = (byte)(data[i] ^ key);
                sr.WindowsRecovered = windows.Count;
                sr.Window0Method = "n/a (small section, plain XOR)";
                sr.PermutationSource = "n/a (small section)";
                return;
            }

            int n = windows.Count;

            // A ULTIMA janela nao e cortada em 0x4000: ela vai ate o fim da
            // secao. No .rodata do CoD Mobile isso e 0x5684 em vez de 0x4000, e
            // no build arm32 do Free Fire 0x9FEC.
            int WindowLength(int index) =>
                (int)(index == n - 1 ? end - windows[index].start
                                     : Math.Min(WindowSize, end - windows[index].start));

            // Janela 0: AES-128-CBC com a chave derivada de K.
            long w0 = windows[0].start;
            int w0Len = WindowLength(0);
            if (seed != 0 && TryDecryptWindow0(data, outBuf, w0, w0Len, seed))
            {
                sr.Window0Method = "AES-128-CBC";
                sr.WindowsRecovered++;
            }
            else
            {
                sr.Window0Method = "failed";
                sr.WindowsSkipped++;
                sr.BytesUnrecovered += w0Len;
            }

            // Janelas que nao entram na permuta: so XOR, sem depender de sigma.
            // Quais sao elas depende do candidato de FirstGroupIndex, entao isso
            // e reaplicado a cada tentativa (e barato: sao poucas janelas).
            void ApplyPlainWindows(int firstGroup, int lastGroupStart)
            {
                for (int index = 1; index < n; index++)
                {
                    if (index >= firstGroup && index < lastGroupStart) continue;
                    long dst = windows[index].start;
                    int len = WindowLength(index);
                    if (len <= 0) continue;
                    for (int i = 0; i < len; i++)
                        outBuf[dst + i] = (byte)(data[dst + i] ^ key);
                }
            }

            int[] sigma = null;
            string sigmaSource = null;
            int chosen = 0;

            foreach (int firstGroup in FirstGroupCandidates(knownFirstGroup))
            {
                int lastGroupStart = firstGroup + GroupSize * ((n - firstGroup) / GroupSize);
                ApplyPlainWindows(firstGroup, lastGroupStart);
                var candidate = SolvePermutation(data, outBuf, windows, start, end, firstGroup,
                                                 lastGroupStart, key, d.Checksum, out var src);
                if (candidate == null) continue;
                sigma = candidate;
                sigmaSource = src;
                chosen = firstGroup;
                // O oraculo fechou: este FirstGroupIndex e o do build, entao as
                // outras secoes do mesmo arquivo comecam por ele.
                if (knownFirstGroup == 0) knownFirstGroup = firstGroup;
                break;
            }

            if (sigma == null)
            {
                // Nenhuma combinacao fecha o CRC - quase sempre porque a janela
                // 0 nao foi decifrada. Deixar o resto no formato dos builds
                // conhecidos e o que da chance pro sidecar de janela 0.
                chosen = knownFirstGroup != 0 ? knownFirstGroup : FirstGroupIndexFallback;
                sigma = d.Algo != 2 ? KnownPermutations[0] : Identity;
                sigmaSource = d.Algo != 2 ? "fallback table" : "identity (algo 2)";
                ApplyPlainWindows(chosen, chosen + GroupSize * ((n - chosen) / GroupSize));
            }

            int lastGroup = chosen + GroupSize * ((n - chosen) / GroupSize);
            sr.FirstGroupIndex = chosen;
            sr.Permutation = sigma;
            sr.PermutationSource = sigmaSource;

            // Conta as janelas XOR puras (fora da faixa permutada) uma vez, ja
            // que ApplyPlainWindows pode ter rodado varias.
            for (int index = 1; index < n; index++)
            {
                if (index >= chosen && index < lastGroup) continue;
                if (WindowLength(index) <= 0) { sr.WindowsSkipped++; continue; }
                sr.WindowsRecovered++;
            }

            for (int index = chosen; index < lastGroup; index += GroupSize)
            {
                int groupEnd = Math.Min(index + GroupSize, lastGroup);
                for (int p = 0; p < groupEnd - index; p++)
                {
                    int member = index + p;
                    int source = index + sigma[p];
                    long dst = windows[member].start;
                    int len = WindowLength(member);
                    long srcPos = source < n ? windows[source].start : -1;

                    if (len <= 0 || srcPos < start || srcPos + len > end)
                    {
                        sr.WindowsSkipped++;
                        sr.BytesUnrecovered += Math.Max(len, 0);
                        continue;
                    }
                    for (int i = 0; i < len; i++)
                        outBuf[dst + i] = (byte)(data[srcPos + i] ^ key);
                    sr.WindowsRecovered++;
                }
            }
        }

        /// Candidatos de FirstGroupIndex, com o que ja fechou o CRC neste
        /// arquivo na frente. A janela 0 e AES e nao se move, entao 0 esta fora,
        /// e 1..8 cobre todas as fases de grupo possiveis.
        ///
        /// A ordem e so ordem de TENTATIVA - quem decide e o CRC32 do descritor,
        /// e um build com qualquer outro valor e achado do mesmo jeito. Os dois
        /// ja vistos vem primeiro (2 no Free Fire, 1 no CoD Mobile) porque isso
        /// economiza um solve por secao e, quando duas descricoes servem, faz o
        /// relatorio sair com a que foi medida no build.
        ///
        /// Duas descricoes podem servir mesmo: se sigma fixa a posicao 7 do
        /// grupo, "comeca na janela f" com essa sigma e "comeca na janela f-1"
        /// com sigma rotacionada mapeiam exatamente as mesmas janelas. E o caso
        /// do Free Fire, onde f=1 e f=2 dao bytes identicos.
        private static IEnumerable<int> FirstGroupCandidates(int known)
        {
            if (known >= FirstGroupCandidateMin && known <= FirstGroupCandidateMax) yield return known;
            foreach (int f in SeenInTheWild)
                if (f != known && f >= FirstGroupCandidateMin && f <= FirstGroupCandidateMax) yield return f;
            for (int f = FirstGroupCandidateMin; f <= FirstGroupCandidateMax; f++)
                if (f != known && Array.IndexOf(SeenInTheWild, f) < 0) yield return f;
        }

        private static readonly int[] SeenInTheWild = { 2, 1 };

        /// <summary>
        /// Chave XOR do bulk. As fontes sao o byte ofuscado da tabela (+0x186) e
        /// o blob de chave ((K &gt;&gt; 16) &amp; 0xFF, que e keyblob[13]); exigir que
        /// duas fontes independentes concordem evita corromper o arquivo se o
        /// layout do descritor mudar num build futuro. O histograma das janelas
        /// entra so como terceira fonte, porque em secao de codigo ele erra.
        /// </summary>
        private static bool ResolveKey(byte[] data, long table, byte obf, byte[] blob,
                                       Descriptor sample, out byte key, out string source)
        {
            byte fromByte = (byte)(data[table + KeyByteOffset] ^ obf);
            byte fromBlob = blob != null ? blob[13] : (byte)0;

            if (fromByte != 0 && fromByte == fromBlob)
            {
                key = fromByte;
                source = "descriptor";
                return true;
            }

            var windows = EnumerateWindows(sample.Offset, (long)sample.Offset + sample.Size);
            long end = (long)sample.Offset + sample.Size;
            byte hist = MostFrequentByte(data, windows, end);

            if (fromByte != 0 && fromByte == hist) { key = fromByte; source = "descriptor + histogram"; return true; }
            if (fromBlob != 0 && fromBlob == hist) { key = fromBlob; source = "key blob + histogram"; return true; }
            if (BestByTextScore(data, windows, end) == hist)
            {
                key = hist == 0 ? FallbackXorKey : hist;
                source = "histogram";
                return true;
            }

            key = 0;
            source = "";
            return false;
        }

        /// <summary>
        /// Descobre a permutacao de janelas usando o CRC32 em claro guardado no
        /// descritor como oraculo.
        ///
        /// <paramref name="outBuf"/> ja precisa ter a janela 0 decifrada e as
        /// janelas fora da regiao permutada aplicadas; as janelas permutadas
        /// ainda estao com o conteudo empacotado.
        ///
        /// Como o CRC32 e afim, o CRC final e "base XOR uma contribuicao por
        /// janela", e as contribuicoes de cada posicao p do grupo podem ser
        /// somadas de antemao. Sobram 8 XORs por candidata, entao varrer as
        /// 40320 permutacoes e instantaneo.
        /// </summary>
        private static int[] SolvePermutation(byte[] data, byte[] outBuf,
                                              List<(int index, long start)> windows,
                                              long start, long end, int firstGroupIndex,
                                              int lastGroupStart, byte key, uint target,
                                              out string source)
        {
            source = "";
            if (target == 0) return null;
            int count = lastGroupStart - firstGroupIndex;
            if (count <= 0) return null;
            int n = windows.Count;

            // Comprimento que o aplicador VAI escrever nesta janela. A ultima
            // janela da secao nao e cortada em 0x4000, entao quando ela cai
            // dentro da faixa permutada o solver tem que modelar o tamanho
            // real - senao o oraculo nunca fecha e caimos na tabela fixa.
            int LengthOf(int index) =>
                (int)(index == n - 1 ? end - windows[index].start
                                     : Math.Min(WindowSize, end - windows[index].start));

            // Uma origem so serve se couber no comprimento do DESTINO. Se
            // alguma nao couber o aplicador pula a janela e deixa cifrado, e
            // ai nenhum CRC fecha: melhor nem tentar resolver.
            for (int k = 0; k < count; k++)
            {
                int index = firstGroupIndex + k;
                int groupBase = firstGroupIndex + GroupSize * (k / GroupSize);
                int len = LengthOf(index);
                if (len <= 0) return null;
                for (int j = 0; j < GroupSize; j++)
                {
                    if (groupBase + j >= n) return null;
                    if (windows[groupBase + j].start + len > end) return null;
                }
            }

            long total = end - start;

            // So ha dois comprimentos possiveis (0x4000 e a cauda), entao um
            // cache minusculo evita recalcular os CRCs de apoio.
            var zeroCache = new Dictionary<int, uint>();
            var keyCache = new Dictionary<int, uint>();
            uint ZeroCrc(int len)
            {
                if (zeroCache.TryGetValue(len, out var v)) return v;
                return zeroCache[len] = FFCrc32.OfZeros(len);
            }
            uint KeyCrc(int len)
            {
                if (keyCache.TryGetValue(len, out var v)) return v;
                var block = new byte[len];
                for (int i = 0; i < len; i++) block[i] = key;
                return keyCache[len] = FFCrc32.Compute(block, 0, len);
            }

            // Base = CRC da secao com as janelas permutadas zeradas. Zerar e
            // remover a contribuicao do que esta la agora.
            uint baseCrc = FFCrc32.Compute(outBuf, start, total);
            var rests = new long[count];
            var lens = new int[count];
            for (int k = 0; k < count; k++)
            {
                long at = windows[firstGroupIndex + k].start;
                int len = LengthOf(firstGroupIndex + k);
                long rest = total - (at - start) - len;
                rests[k] = rest;
                lens[k] = len;
                uint present = FFCrc32.Compute(outBuf, at, len) ^ ZeroCrc(len);
                baseCrc ^= FFCrc32.Combine(present, 0, rest);
            }

            // Contribuicao de cada origem possivel, ja somada por posicao no grupo.
            var aggregate = new uint[GroupSize][];
            for (int p = 0; p < GroupSize; p++) aggregate[p] = new uint[GroupSize];
            for (int k = 0; k < count; k++)
            {
                int groupBase = firstGroupIndex + GroupSize * (k / GroupSize);
                int p = k % GroupSize;
                for (int j = 0; j < GroupSize; j++)
                {
                    long at = windows[groupBase + j].start;
                    uint term = FFCrc32.Compute(data, at, lens[k]) ^ KeyCrc(lens[k]);
                    aggregate[p][j] ^= FFCrc32.Combine(term, 0, rests[k]);
                }
            }

            uint Evaluate(int[] candidate)
            {
                uint acc = baseCrc;
                for (int p = 0; p < GroupSize; p++) acc ^= aggregate[p][candidate[p]];
                return acc;
            }

            foreach (var known in KnownPermutations)
            {
                if (Evaluate(known) != target) continue;
                source = known == Identity ? "identity, CRC32 verified" : "known table, CRC32 verified";
                return known;
            }

            var sigma = new int[GroupSize];
            var used = new bool[GroupSize];

            bool Search(int p, uint acc)
            {
                if (p == GroupSize) return acc == target;
                for (int j = 0; j < GroupSize; j++)
                {
                    if (used[j]) continue;
                    used[j] = true;
                    sigma[p] = j;
                    if (Search(p + 1, acc ^ aggregate[p][j])) return true;
                    used[j] = false;
                }
                return false;
            }

            if (!Search(0, baseCrc)) return null;
            source = "solved from CRC32";
            return sigma;
        }

        /// Janela 0: AES-128-CBC em blocos independentes de 0x800, IV fixo
        /// reiniciado a cada bloco, sem padding.
        private static bool TryDecryptWindow0(byte[] src, byte[] dst, long offset, int length, uint k)
        {
            try
            {
                if (length < Window0ChunkSize || offset + length > src.Length) return false;
                var key = Encoding.ASCII.GetBytes($"{k:x8}{k:x8}");
                if (key.Length != 16) return false;

                using var aes = Aes.Create();
                aes.Key = key;
                var chunk = new byte[Window0ChunkSize];
                for (int off = 0; off + Window0ChunkSize <= length; off += Window0ChunkSize)
                {
                    Buffer.BlockCopy(src, (int)offset + off, chunk, 0, Window0ChunkSize);
                    var plain = aes.DecryptCbc(chunk, Window0Iv, PaddingMode.None);
                    Buffer.BlockCopy(plain, 0, dst, (int)offset + off, Window0ChunkSize);
                }
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>
        /// Blob base64 da tabela, decodificado e desofuscado. Contem a data de
        /// build do packer, dois 1s e o material de chave.
        /// </summary>
        private static byte[] ReadKeyBlob(byte[] data, long table, out byte obfuscation)
        {
            obfuscation = 0;
            long at = table + KeyBlobOffset;
            if (at < 0 || at + 28 > data.Length) return null;

            var sb = new StringBuilder();
            for (long i = at; i < data.Length && i < at + 64; i++)
            {
                byte b = data[i];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) return null;
                sb.Append((char)b);
            }
            try
            {
                var raw = Convert.FromBase64String(sb.ToString());
                if (raw.Length < 16) return null;
                if (!TrySolveObfuscation(raw, out obfuscation)) return null;
                for (int i = 0; i < raw.Length; i++) raw[i] ^= obfuscation;
                return raw;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        /// <summary>
        /// Resolve a constante de ofuscacao do packer em vez de chumbar uma: ela
        /// e 0x4F no Free Fire e 0x98 no Call of Duty Mobile, e ninguem precisa
        /// saber de qual jogo o arquivo e.
        ///
        /// O blob em claro e "data de build BCD big-endian", depois DOIS 1s
        /// big-endian, depois K e K+1. Os dois 1s sao 8 bytes conhecidos em
        /// posicao conhecida, entao a constante e o unico X em 0..255 com
        /// raw[4:12] ^ X == 00000001 00000001. A data de build serve de
        /// conferencia: raw[0] ^ X tem que dar 0x20 ("20aammdd").
        /// </summary>
        private static bool TrySolveObfuscation(byte[] raw, out byte obfuscation)
        {
            obfuscation = 0;
            if (raw.Length < 16) return false;

            int found = -1;
            for (int x = 0; x < 256; x++)
            {
                if ((raw[0] ^ x) != 0x20) continue;
                bool ok = true;
                for (int i = 0; i < 8 && ok; i++)
                {
                    int expected = (i == 3 || i == 7) ? 1 : 0;   // 00 00 00 01 00 00 00 01
                    if ((raw[4 + i] ^ x) != expected) ok = false;
                }
                if (!ok) continue;
                if (found >= 0) return false;   // ambiguo: melhor nao adivinhar
                found = x;
            }
            if (found < 0) return false;
            obfuscation = (byte)found;
            return true;
        }

        private static List<(int index, long start)> EnumerateWindows(long sectionStart, long sectionEnd)
        {
            var list = new List<(int, long)>();
            long first = (sectionStart & ~0xfffL) + FirstWindowPhase;
            int i = 0;
            for (long w = first; w < sectionEnd; w += SlotStride, i++)
                list.Add((i, w));
            return list;
        }

        /// Byte mais frequente nas janelas empacotadas. A permutacao so
        /// reordena janelas inteiras, entao o histograma do conjunto nao depende
        /// dela e pode ser tirado das janelas no lugar em que estao.
        private static byte MostFrequentByte(byte[] data, List<(int index, long start)> windows,
                                             long end)
        {
            var hist = new long[256];
            foreach (var (_, at) in windows)
            {
                long len = Math.Min(WindowSize, end - at);
                for (long i = 0; i < len; i++) hist[data[at + i]]++;
            }
            byte best = 0;
            for (int i = 1; i < 256; i++) if (hist[i] > hist[best]) best = (byte)i;
            return best;
        }

        /// <summary>
        /// Conta quantas janelas tem a chave XOR como byte dominante e quantas
        /// tem 0x00. Numa secao cifrada o dominante e a chave (o 0x00 do texto
        /// claro XOR a chave); numa secao em claro e o proprio 0x00. Nas
        /// amostras a separacao e total: 75-87% contra 0% de um lado, 76-88%
        /// contra 0% do outro.
        /// </summary>
        private static void ClassifyWindows(byte[] data, List<(int index, long start)> windows,
                                            long end, byte key,
                                            out int keyDominated, out int zeroDominated,
                                            out int count)
        {
            keyDominated = zeroDominated = count = 0;
            var hist = new long[256];
            foreach (var (_, at) in windows)
            {
                long len = Math.Min(WindowSize, end - at);
                if (len <= 0) continue;
                Array.Clear(hist, 0, hist.Length);
                for (long i = 0; i < len; i++) hist[data[at + i]]++;
                int best = 0;
                for (int i = 1; i < 256; i++) if (hist[i] > hist[best]) best = i;
                count++;
                if (best == key) keyDominated++;
                else if (best == 0) zeroDominated++;
            }
        }

        /// Chave que maximiza NUL*4 + ASCII imprimivel, amostrando o inicio das janelas.
        private static byte BestByTextScore(byte[] data, List<(int index, long start)> windows,
                                            long end)
        {
            const int Sample = 512;
            byte best = 0;
            long bestScore = -1;
            for (int k = 0; k < 256; k++)
            {
                long score = 0;
                foreach (var (_, at) in windows)
                {
                    if (at + Sample > end) continue;
                    for (int i = 0; i < Sample; i++)
                    {
                        byte v = (byte)(data[at + i] ^ (byte)k);
                        if (v == 0) score += 4;
                        else if (v >= 0x20 && v <= 0x7e) score++;
                    }
                }
                if (score > bestScore) { bestScore = score; best = (byte)k; }
            }
            return best;
        }

        public static void Report(Result r)
        {
            if (!r.Detected) return;

            var names = new List<string>();
            foreach (var d in r.Descriptors) names.Add(d.ToString());
            Console.WriteLine($"Detected packed ELF (stub_decrypt_elf): {string.Join("; ", names)}");

            if (r.SkippedByConfig) return;

            if (r.LooksAlreadyPlain && r.Sections.Count == 0)
            {
                Console.WriteLine("  Section content already looks unpacked, leaving it alone.");
                return;
            }
            if (!r.Unpacked && r.Sections.Count == 0)
                return;

            if (r.LooksAlreadyPlain)
                Console.WriteLine("  Section content already looks unpacked, leaving it alone.");

            Console.WriteLine($"  Key 0x{r.Key:X2} (from {r.KeySource}), obfuscation constant " +
                              $"0x{r.ObfuscationConstant:X2} (derived)" +
                              (r.AesSeed != 0 ? $", AES seed 0x{r.AesSeed:x8}" : "") +
                              (r.BuildDate != 0 ? $", packer build 0x{r.BuildDate:x8}" : ""));

            foreach (var sr in r.Sections)
            {
                var d = sr.Section;
                if (sr.AlreadyPlain)
                {
                    Console.WriteLine($"  {d.Name}: already plain, CRC32 0x{d.Checksum:X8} matches the descriptor.");
                    continue;
                }
                if (sr.PlainUnverified)
                {
                    Console.WriteLine($"  {d.Name}: NOT encrypted ({sr.ZeroDominatedWindows} of " +
                                      $"{sr.WindowsTotal} windows dominated by 0x00, {sr.KeyDominatedWindows} " +
                                      $"by the key 0x{r.Key:X2}), but CRC32 0x{sr.ActualCrc:X8} " +
                                      $"!= descriptor 0x{sr.ExpectedCrc:X8}: this is a live-process image, " +
                                      "left exactly as it is. Its content is NOT verified.");
                    continue;
                }
                Console.WriteLine($"  {d.Name}: {sr.WindowsRecovered}/{sr.WindowsTotal} windows, " +
                                  $"window 0 via {sr.Window0Method}, first group {sr.FirstGroupIndex}, " +
                                  $"permutation {string.Join(",", sr.Permutation)} ({sr.PermutationSource})");
                if (sr.Window0PatchFrom != null)
                    Console.WriteLine($"    window 0 restored from {sr.Window0PatchFrom}");
                if (sr.ChecksumVerified)
                    Console.WriteLine($"    CRC32 matches the descriptor (0x{sr.ExpectedCrc:X8}) - section is byte-exact.");
                else
                    Console.WriteLine($"    CRC32 0x{sr.ActualCrc:X8} != descriptor 0x{sr.ExpectedCrc:X8}; " +
                                      $"{sr.BytesUnrecovered} byte(s) could not be recovered.");
            }

            if (!r.ChecksumVerified)
                Console.WriteLine("  Dump the library from memory instead (see tools/ffdump.py), or capture " +
                                  "window 0 once with tools/ffwindow0.py.");
        }
    }
}
