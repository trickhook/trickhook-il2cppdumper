using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Il2CppDumper
{
    /// <summary>
    /// Desempacota o protector ELF usado pelo Free Fire (com.dts.freefireth /
    /// com.dts.freefiremax) e por outros alvos empacotados com o mesmo stub.
    ///
    /// O stub e anexado no fim do .so (varios PT_LOAD apontando pro mesmo file
    /// offset) e roda via DT_INIT. Ele exporta "stub_decrypt_elf" e carrega um
    /// descritor com magic 0x12345678. O codigo que faz a transformacao nao
    /// esta no libil2cpp: o stub chama g_acf_array[1], um import resolvido do
    /// libanort.so.
    ///
    /// Esquema completo, reversado do libanort e validado byte a byte contra
    /// dump de memoria nas duas ABIs:
    ///
    ///   K = uint32 big-endian em keyblob[12:16], onde keyblob e o base64 do
    ///       descritor+0x1a8 decodificado e XOR 0x4F. Todo o material de chave
    ///       sai desse dword: a chave XOR do bulk e (K &gt;&gt; 16) &amp; 0xFF e a chave
    ///       AES e o ASCII de "%08x%08x" % (K, K).
    ///
    ///   Regiao = a secao do descritor, comecando em (inicio &amp; ~0xFFF) + 0x2000.
    ///
    ///   Secao menor que 1 MB: XOR puro na regiao inteira, sem AES nem permuta.
    ///
    ///   Senao:
    ///     janela 0 (0x4000 bytes) = AES-128-CBC, IV fixo 02..11, em 8 blocos
    ///       independentes de 0x800 com o IV reiniciado a cada bloco;
    ///     do +0x10000 em diante = XOR de 1 byte + permutacao entre slots de
    ///       0x10000, em grupos de 8 janelas de 0x4000 (algo 1), ou XOR puro
    ///       sem permutacao (algo 2, descritor+0x188).
    ///
    /// O descritor carrega em +0x20 o CRC32 da secao em claro, entao o
    /// resultado se verifica sozinho.
    /// </summary>
    public static class FFProtector
    {
        public const uint Magic = 0x12345678;

        /// Setado quando o desempacotamento rodou e o CRC32 do descritor
        /// fechou. A partir dai o aviso de "file may be protected" do upstream
        /// so confunde: a protecao ja foi tratada.
        public static bool Handled;

        /// Constante do packer que ofusca os parametros do descritor. Ela
        /// transforma o blob de chave em big-endian 0x20240829 (a data de build
        /// do packer) seguido de dois 1s - e a unica das 256 candidatas que faz
        /// isso, identicamente, em binarios com chaves diferentes.
        private const byte ObfuscationConstant = 0x4F;

        private const int WindowSize = 0x4000;
        private const int SlotStride = 0x10000;
        private const int FirstWindowPhase = 0x2000;

        /// Abaixo disso o packer nem usa AES nem permuta: XOR puro na regiao.
        private const long SmallSectionLimit = 0x100000;

        private const int KeyByteOffset = 0x186;   // chave XOR, ofuscada
        private const int AlgoOffset = 0x188;
        private const int KeyBlobOffset = 0x1a8;   // base64 com o material de chave

        /// Chave XOR usada quando o byte correspondente de K e zero.
        private const byte FallbackXorKey = 0x87;

        private const int Window0ChunkSize = 0x800;
        private static readonly byte[] Window0Iv =
        {
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
        };

        /// A regiao permutada comeca na janela 2 e vai ate o ultimo grupo de 8
        /// completo; dentro de cada grupo as 8 janelas sao reordenadas por uma
        /// permutacao sigma, onde a janela na posicao p do grupo vem da posicao
        /// sigma[p].
        private const int GroupSize = 8;
        private const int FirstGroupIndex = 2;

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
            public long FilePosition;
            public string Name;
            public uint Offset;
            public uint VirtualAddress;
            public uint Size;
            public uint Checksum;
            public uint FirstLoadFileSize;
            public uint Kind;
            public uint Algo;

            public override string ToString() =>
                $"{Name} offset=0x{Offset:x} vaddr=0x{VirtualAddress:x} size=0x{Size:x}";
        }

        public sealed class Result
        {
            public bool Detected;
            public bool Unpacked;
            public Descriptor Descriptor;
            public byte Key;
            public string KeySource = "";
            public uint AesSeed;
            public string Window0Method = "not attempted";
            public int[] Permutation = Identity;
            public string PermutationSource = "";
            public int WindowsTotal;
            public int WindowsRecovered;
            public int WindowsSkipped;
            public bool ChecksumVerified;
            public uint ExpectedCrc;
            public uint ActualCrc;
            public long BytesUnrecovered;
            public string Window0PatchFrom;
            public byte[] Data;
        }

        /// <summary>Procura o descritor do protector no arquivo inteiro.</summary>
        public static Descriptor FindDescriptor(byte[] data)
        {
            for (long i = 0; i + 0x34 <= data.Length; i += 4)
            {
                if (BitConverter.ToUInt32(data, (int)i) != Magic) continue;

                var name = ReadName(data, (int)i + 4);
                if (name == null) continue;

                var d = new Descriptor
                {
                    FilePosition = i,
                    Name = name,
                    Offset = BitConverter.ToUInt32(data, (int)i + 0x14),
                    VirtualAddress = BitConverter.ToUInt32(data, (int)i + 0x18),
                    Size = BitConverter.ToUInt32(data, (int)i + 0x1c),
                    Checksum = BitConverter.ToUInt32(data, (int)i + 0x20),
                    FirstLoadFileSize = BitConverter.ToUInt32(data, (int)i + 0x28),
                    Kind = BitConverter.ToUInt32(data, (int)i + 0x2c),
                };
                if (i + AlgoOffset + 4 <= data.Length)
                    d.Algo = BitConverter.ToUInt32(data, (int)i + AlgoOffset);

                if (d.Size == 0 || d.Offset == 0) continue;
                if ((long)d.Offset + d.Size > data.Length) continue;
                return d;
            }
            return null;
        }

        private static string ReadName(byte[] data, int at)
        {
            var sb = new StringBuilder();
            for (int k = 0; k < 16; k++)
            {
                byte b = data[at + k];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) return null;
                sb.Append((char)b);
            }
            if (sb.Length < 2 || sb[0] != '.') return null;   // nome de secao, ex ".rodata"
            return sb.ToString();
        }

        /// <summary>
        /// Detecta e, se o conteudo estiver mesmo embaralhado, desempacota.
        /// Devolve sempre um Result; Data e o buffer a usar daqui pra frente.
        /// </summary>
        public static Result TryUnpack(byte[] data, bool enabled = true, string inputPath = null)
        {
            var r = new Result { Data = data };
            var d = FindDescriptor(data);
            if (d == null) return r;

            r.Detected = true;
            r.Descriptor = d;
            if (!enabled) return r;

            long start = d.Offset;
            long end = start + d.Size;
            var windows = EnumerateWindows(start, end);
            r.WindowsTotal = windows.Count;
            if (windows.Count == 0) return r;

            // O byte mais frequente da regiao decide SE ha o que desempacotar:
            // no texto claro de um .rodata o mais comum e 0x00 com varias vezes
            // de folga, entao o byte dominante do ciphertext e a propria chave,
            // e 0x00 significa que a secao ja esta em claro (dump de memoria).
            byte hist = MostFrequentByte(data, windows, end);
            if (hist == 0) return r;

            var blob = ReadKeyBlob(data, d);
            byte fromByte = KeyFromDescriptorByte(data, d);
            byte fromBlob = blob != null ? blob[13] : (byte)0;

            // Exigir que duas fontes independentes concordem evita corromper o
            // arquivo se o layout do descritor mudar num build futuro.
            byte key;
            string src;
            if (fromByte != 0 && fromByte == fromBlob) { key = fromByte; src = "descriptor"; }
            else if (fromByte != 0 && fromByte == hist) { key = fromByte; src = "descriptor + histogram"; }
            else if (fromBlob != 0 && fromBlob == hist) { key = fromBlob; src = "key blob + histogram"; }
            else if (BestByTextScore(data, windows, end) == hist) { key = hist; src = "histogram"; }
            else
            {
                Console.WriteLine("WARNING: packed section detected but the key could not be confirmed; leaving it alone.");
                return r;
            }
            if (key == 0) key = FallbackXorKey;

            r.Key = key;
            r.KeySource = src;

            var outBuf = (byte[])data.Clone();

            if (d.Size < SmallSectionLimit)
            {
                // Secao pequena: o packer so faz XOR, sem AES e sem permuta.
                for (long i = windows[0].start; i < end; i++)
                    outBuf[i] = (byte)(data[i] ^ key);
                r.WindowsRecovered = windows.Count;
                r.Window0Method = "n/a (small section, plain XOR)";
                r.PermutationSource = "n/a (small section)";
            }
            else
            {
                // Janela 0: AES-128-CBC com a chave derivada de K.
                long w0 = windows[0].start;
                int w0Len = (int)Math.Min(WindowSize, end - w0);
                uint seed = blob != null
                    ? (uint)((blob[12] << 24) | (blob[13] << 16) | (blob[14] << 8) | blob[15])
                    : 0u;

                if (seed != 0 && TryDecryptWindow0(data, outBuf, w0, w0Len, seed))
                {
                    r.AesSeed = seed;
                    r.Window0Method = "AES-128-CBC";
                    r.WindowsRecovered++;
                }
                else
                {
                    r.Window0Method = "failed";
                    r.WindowsSkipped++;
                    r.BytesUnrecovered += w0Len;
                }

                // Resto: XOR + permutacao entre slots (algo 1) ou XOR puro (algo 2).
                int n = windows.Count;
                int lastGroupStart = FirstGroupIndex + GroupSize * ((n - FirstGroupIndex) / GroupSize);

                // A ULTIMA janela nao e cortada em 0x4000: ela vai ate o fim da
                // secao. No build arm32 isso e 0x9FEC em vez de 0x4000.
                int WindowLength(int index) =>
                    (int)(index == n - 1 ? end - windows[index].start
                                         : Math.Min(WindowSize, end - windows[index].start));

                // Janelas fora da regiao permutada: so XOR, sem depender de sigma.
                // Elas entram no buffer antes do solver porque o oraculo compara
                // o CRC da secao inteira.
                for (int index = 1; index < n; index++)
                {
                    if (index >= FirstGroupIndex && index < lastGroupStart) continue;
                    long dst = windows[index].start;
                    int len = WindowLength(index);
                    if (len <= 0) { r.WindowsSkipped++; continue; }
                    for (int i = 0; i < len; i++)
                        outBuf[dst + i] = (byte)(data[dst + i] ^ key);
                    r.WindowsRecovered++;
                }

                var sigma = SolvePermutation(data, outBuf, windows, start, end,
                                             lastGroupStart, key, d.Checksum, out var sigmaSource);
                if (sigma == null)
                {
                    sigma = d.Algo != 2 ? KnownPermutations[0] : Identity;
                    sigmaSource = d.Algo != 2 ? "fallback table" : "identity (algo 2)";
                }
                r.Permutation = sigma;
                r.PermutationSource = sigmaSource;

                for (int index = FirstGroupIndex; index < lastGroupStart; index += GroupSize)
                {
                    int groupEnd = Math.Min(index + GroupSize, lastGroupStart);
                    for (int p = 0; p < groupEnd - index; p++)
                    {
                        int member = index + p;
                        int source = index + sigma[p];
                        long dst = windows[member].start;
                        int len = WindowLength(member);
                        long srcPos = source < n ? windows[source].start : -1;

                        if (len <= 0 || srcPos < start || srcPos + len > end)
                        {
                            r.WindowsSkipped++;
                            r.BytesUnrecovered += Math.Max(len, 0);
                            continue;
                        }
                        for (int i = 0; i < len; i++)
                            outBuf[dst + i] = (byte)(data[srcPos + i] ^ key);
                        r.WindowsRecovered++;
                    }
                }
            }

            // descritor+0x20 e o CRC32 da secao em claro, entao da pra conferir
            // o resultado sem precisar de um dump de memoria pra comparar.
            r.ExpectedCrc = d.Checksum;
            r.ActualCrc = FFCrc32.Compute(outBuf, start, end - start);
            r.ChecksumVerified = r.ActualCrc == r.ExpectedCrc;

            // Rede de seguranca: se a cifra da janela 0 mudar num build futuro,
            // um sidecar capturado de dump de memoria ainda resolve.
            if (!r.ChecksumVerified &&
                FFWindow0Patch.TryApply(outBuf, d.Checksum, inputPath, out var patchFrom))
            {
                r.ActualCrc = FFCrc32.Compute(outBuf, start, end - start);
                r.ChecksumVerified = r.ActualCrc == r.ExpectedCrc;
                if (r.ChecksumVerified)
                {
                    r.Window0PatchFrom = patchFrom;
                    r.BytesUnrecovered = 0;
                }
            }

            r.Unpacked = true;
            r.Data = outBuf;
            return r;
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
                                              long start, long end, int lastGroupStart,
                                              byte key, uint target, out string source)
        {
            source = "";
            int count = lastGroupStart - FirstGroupIndex;
            if (count <= 0) return null;

            // O solver assume janelas inteiras; se a ultima permutada for curta,
            // deixa pro caminho normal com a tabela conhecida.
            if (windows[lastGroupStart - 1].start + WindowSize > end) return null;

            long total = end - start;
            uint zeroCrc = FFCrc32.OfZeros(WindowSize);

            var keyBlock = new byte[WindowSize];
            for (int i = 0; i < WindowSize; i++) keyBlock[i] = key;
            uint keyCrc = FFCrc32.Compute(keyBlock, 0, WindowSize);

            // Base = CRC da secao com as janelas permutadas zeradas. Zerar e
            // remover a contribuicao do que esta la agora.
            uint baseCrc = FFCrc32.Compute(outBuf, start, total);
            var rests = new long[count];
            for (int k = 0; k < count; k++)
            {
                long at = windows[FirstGroupIndex + k].start;
                long rest = total - (at - start) - WindowSize;
                rests[k] = rest;
                uint present = FFCrc32.Compute(outBuf, at, WindowSize) ^ zeroCrc;
                baseCrc ^= FFCrc32.Combine(present, 0, rest);
            }

            // Contribuicao de cada origem possivel, ja somada por posicao no grupo.
            var aggregate = new uint[GroupSize][];
            for (int p = 0; p < GroupSize; p++) aggregate[p] = new uint[GroupSize];
            for (int k = 0; k < count; k++)
            {
                int groupBase = FirstGroupIndex + GroupSize * (k / GroupSize);
                int p = k % GroupSize;
                for (int j = 0; j < GroupSize; j++)
                {
                    long at = windows[groupBase + j].start;
                    uint term = FFCrc32.Compute(data, at, WindowSize) ^ keyCrc;
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

        /// Blob base64 do descritor, decodificado e desofuscado. Contem a data de
        /// build do packer, dois 1s e o material de chave.
        private static byte[] ReadKeyBlob(byte[] data, Descriptor d)
        {
            long at = d.FilePosition + KeyBlobOffset;
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
                for (int i = 0; i < raw.Length; i++) raw[i] ^= ObfuscationConstant;
                if (raw[0] != 0x20) return null;   // data de build, sempre 20xx
                return raw;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        /// Chave XOR guardada como byte solto no descritor, ofuscada com 0x4F.
        private static byte KeyFromDescriptorByte(byte[] data, Descriptor d)
        {
            long at = d.FilePosition + KeyByteOffset;
            if (at < 0 || at >= data.Length) return 0;
            return (byte)(data[at] ^ ObfuscationConstant);
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
            Console.WriteLine($"Detected packed ELF (stub_decrypt_elf): {r.Descriptor}");
            if (!r.Unpacked)
            {
                Console.WriteLine("  Section content already looks unpacked, leaving it alone.");
                return;
            }
            Console.WriteLine($"  Unpacked with key 0x{r.Key:X2} (from {r.KeySource}), " +
                              $"window 0 via {r.Window0Method}" +
                              (r.AesSeed != 0 ? $" seed 0x{r.AesSeed:x8}" : "") +
                              $": {r.WindowsRecovered}/{r.WindowsTotal} windows recovered");
            Console.WriteLine($"  Window permutation {string.Join(",", r.Permutation)} ({r.PermutationSource})");
            if (r.Window0PatchFrom != null)
                Console.WriteLine($"  Window 0 restored from {r.Window0PatchFrom}");
            if (r.ChecksumVerified)
            {
                Console.WriteLine($"  CRC32 matches the descriptor (0x{r.ExpectedCrc:X8}) - section is byte-exact.");
            }
            else
            {
                Console.WriteLine($"  CRC32 0x{r.ActualCrc:X8} != descriptor 0x{r.ExpectedCrc:X8}; " +
                                  $"{r.BytesUnrecovered} byte(s) could not be recovered.");
                Console.WriteLine("  Dump the library from memory instead (see tools/ffdump.py), or capture " +
                                  "window 0 once with tools/ffwindow0.py.");
            }
        }
    }
}
