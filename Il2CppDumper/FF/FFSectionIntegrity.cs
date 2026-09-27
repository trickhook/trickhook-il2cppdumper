using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    /// <summary>
    /// Porteiro do buffer que o resto do dumper vai ler: se o binario carrega o
    /// descritor do stub_decrypt_elf, a secao protegida TEM que fechar com o
    /// CRC32 que o proprio descritor guarda em +0x20. Se nao fecha, recusamos o
    /// dump em vez de emitir field offsets e tamanhos de tipo errados.
    ///
    /// Por que isso nao pode ser decidido por heuristica de bytes: o
    /// <see cref="FFProtector"/> resolve "ja esta em claro?" pelo byte mais
    /// frequente das janelas, contando que num .rodata em claro o dominante seja
    /// 0x00. No Call of Duty Mobile o dominante do texto cifrado da 0x52, entao
    /// o protector nao diz "already plain": ele tenta desempacotar com o modelo
    /// do Free Fire, que nao e o modelo desse build (a permutacao real e
    /// 2,3,5,0,1,4,6,7 e a tabela de reserva e 4,0,6,2,1,3,5,7), e o resultado
    /// passa adiante. Como 100% dos alvos de fieldOffsets e de
    /// typeDefinitionsSizes e 48% dos Il2CppType moram dentro da regiao cifrada
    /// (16 KB de cada 64 KB), o dump sai com nomes e hierarquia perfeitos e ~25%
    /// dos offsets, instance sizes e tipos errados - o pior modo de falha que
    /// existe, porque nada na saida denuncia.
    ///
    /// O CRC do descritor resolve isso sem precisar conhecer a cifra: medido,
    /// `.rodata` em claro do CoD Mobile da exatamente 0xD49063CE, que e o valor
    /// gravado no descritor, e a mesma secao empacotada da 0x40EB0023. Entao a
    /// checagem honesta e recalcular o CRC do buffer que vai ser lido e comparar.
    /// Ela vale para os tres casos de entrada sem nenhum caso especial:
    ///   - arquivo em claro (dump de memoria, ou .so ja desempacotado): o CRC
    ///     bate sem ninguem mexer em nada;
    ///   - empacotado e desempacotado com sucesso: bate depois do unpack;
    ///   - empacotado e desempacotado errado (ou nem tentado): NAO bate.
    /// O terceiro caso e o unico que o histograma nao pega, e e justamente o que
    /// produz lixo plausivel.
    ///
    /// O Free Fire nao muda de comportamento: a fixture arm64 tem descritor com
    /// CRC 0x6876E3C7, esta empacotada (a secao crua da 0x607A46FA) e o unpack
    /// do FFProtector fecha o CRC - entao o porteiro aprova e a saida e a mesma
    /// byte a byte. Nada aqui altera <see cref="FFProtector"/>.
    /// </summary>
    public static class FFSectionIntegrity
    {
        public enum Verdict
        {
            /// Nenhum descritor do packer: nada para verificar.
            NoDescriptor,

            /// Descritor presente mas sem CRC gravado: nao da para verificar.
            NoChecksum,

            /// O CRC do buffer fecha com o do descritor: a secao e byte-exata.
            Verified,

            /// O CRC nao fecha: o conteudo da secao protegida nao presta.
            Mismatch,
        }

        public static Verdict Result { get; private set; } = Verdict.NoDescriptor;
        public static uint Expected { get; private set; }
        public static uint Actual { get; private set; }

        /// <summary>
        /// Confere a secao protegida no buffer que sera lido daqui pra frente e
        /// diz se e seguro continuar. Recusa (false) so quando existe CRC
        /// gravado e ele nao fecha; nesse caso ja imprimiu a explicacao.
        ///
        /// <paramref name="unpackDisabledByConfig"/> e o unico escape: quem
        /// desligou UnpackProtected no config.json pediu explicitamente o
        /// arquivo cru, entao dizemos o que esta errado e seguimos, em vez de
        /// tirar a opcao da pessoa.
        /// </summary>
        public static bool Check(byte[] image, FFProtector.Descriptor d, bool unpackDisabledByConfig)
        {
            Result = Verdict.NoDescriptor;
            Expected = 0;
            Actual = 0;
            return CheckOne(image, d, unpackDisabledByConfig);
        }

        /// <summary>
        /// Mesma checagem para TODAS as secoes que o descritor declara: o packer
        /// pode cifrar mais de uma (o CoD Mobile cifra .rodata, .text e o blob
        /// il2cpp) e cada entrada carrega o seu proprio CRC32. Uma secao que nao
        /// fecha reprova o arquivo inteiro - o veredito que sobra e o pior de
        /// todos, e nao o da ultima secao conferida.
        /// </summary>
        public static bool Check(byte[] image, IReadOnlyList<FFProtector.Descriptor> sections,
                                 bool unpackDisabledByConfig)
        {
            Result = Verdict.NoDescriptor;
            Expected = 0;
            Actual = 0;
            if (sections == null || sections.Count == 0) return true;

            bool ok = true;
            var worst = Verdict.NoDescriptor;
            uint expected = 0, actual = 0;
            foreach (var d in sections)
            {
                if (!CheckOne(image, d, unpackDisabledByConfig)) ok = false;
                if (Rank(Result) <= Rank(worst)) continue;
                worst = Result;
                expected = Expected;
                actual = Actual;
            }
            Result = worst;
            Expected = expected;
            Actual = actual;
            return ok;
        }

        private static int Rank(Verdict v) => v switch
        {
            Verdict.Mismatch => 3,
            Verdict.NoChecksum => 2,
            Verdict.Verified => 1,
            _ => 0,
        };

        private static bool CheckOne(byte[] image, FFProtector.Descriptor d, bool unpackDisabledByConfig)
        {
            Result = Verdict.NoDescriptor;
            Expected = 0;
            Actual = 0;

            // O descritor vem de quem ja varreu o arquivo; sem ele nao ha o que
            // conferir, porque este packer nao esta presente.
            if (d == null) return true;
            if ((long)d.Offset + d.Size > image.Length) return true;

            if (d.Checksum == 0)
            {
                Result = Verdict.NoChecksum;
                Console.WriteLine($"NOTE: the packed section {d.Name} carries no CRC32 in its descriptor, so the " +
                                  "content of the section cannot be verified. Field offsets and type sizes that " +
                                  "come from it are unchecked.");
                return true;
            }

            Expected = d.Checksum;
            Actual = FFCrc32.Compute(image, d.Offset, d.Size);
            if (Actual == Expected)
            {
                Result = Verdict.Verified;
                return true;
            }

            // Num dump de memoria o descritor pode apontar pelo endereco virtual
            // em vez do offset de arquivo. Nas amostras que temos os dois sao
            // iguais, mas conferir o outro antes de recusar custa um CRC e
            // elimina uma recusa injusta.
            if (d.VirtualAddress != d.Offset && (long)d.VirtualAddress + d.Size <= image.Length)
            {
                var alternative = FFCrc32.Compute(image, d.VirtualAddress, d.Size);
                if (alternative == Expected)
                {
                    Actual = alternative;
                    Result = Verdict.Verified;
                    return true;
                }
            }

            Result = Verdict.Mismatch;
            Console.WriteLine();
            Console.WriteLine($"ERROR: the protected section {d.Name} does not match the CRC32 in the packer's own " +
                              $"descriptor: it is 0x{Actual:X8} and the descriptor says 0x{Expected:X8}.");
            Console.WriteLine($"       The section is {d.Size:N0} bytes at file offset 0x{d.Offset:X}, and the " +
                              "packer encrypts 16 KB out of every 64 KB of it.");
            Console.WriteLine("       Everything the dump would say about MEMORY LAYOUT is read from inside that " +
                              "range: every fieldOffsets target, every typeDefinitionsSizes target, and about half " +
                              "of the Il2CppType array. Names and hierarchy would still look perfect, so a dump " +
                              "made from this file is wrong in a way nothing in the output reveals.");

            if (unpackDisabledByConfig)
            {
                Console.WriteLine("       UnpackProtected is off in config.json, so the file was deliberately left " +
                                  "as it is and the dump continues. The field offsets and type sizes below are " +
                                  "NOT trustworthy.");
                Console.WriteLine();
                return true;
            }

            Console.WriteLine("       Refusing to emit field offsets and type sizes from it. Nothing was written.");
            Console.WriteLine("       Give the dumper a binary whose section verifies instead:");
            Console.WriteLine("         - dump the library from memory, where the loader has already decrypted it " +
                              "(tools/ffdump.py), or");
            Console.WriteLine("         - unpack it with the packer's own algorithm for that build, or");
            Console.WriteLine("         - capture the first 16 KB window once and keep it as a sidecar " +
                              $"({Expected:x8}.w0, see tools/ffwindow0.py).");
            Console.WriteLine();
            return false;
        }
    }
}
