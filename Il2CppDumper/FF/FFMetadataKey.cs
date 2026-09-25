using System;

namespace Il2CppDumper
{
    /// <summary>
    /// Alguns builds do Free Fire (visto no com.dts.freefiremax 2.133.1) nao
    /// guardam o global-metadata.dat em claro: o arquivo inteiro vem com XOR de
    /// um byte so. Sem tratar isso o upstream recusa o arquivo logo no magic e
    /// diz "not found or encrypted".
    ///
    /// A chave se deduz sozinha: os 4 primeiros bytes tem que virar o magic
    /// 0xFAB11BAF, entao a chave e o XOR do primeiro byte com 0xAF. Aceitar so
    /// isso daria falso positivo demais, entao a chave candidata so passa se
    /// tambem explicar o resto do cabecalho - a versao cair na faixa suportada
    /// e todos os pares (offset, size) do header ficarem dentro do arquivo.
    /// </summary>
    public static class FFMetadataKey
    {
        /// Header do IL2CPP: sanity, version e dai em diante pares de int32
        /// (offset, size). 0x110 cobre o header inteiro em qualquer versao.
        private const int HeaderSize = 0x110;

        private const int MinVersion = 16;
        private const int MaxVersion = 31;

        private static readonly byte[] SanityBytes = { 0xAF, 0x1B, 0xB1, 0xFA };

        /// <summary>
        /// Devolve a chave XOR do arquivo, ou 0 se ele ja estiver em claro (ou
        /// se nao der pra explicar com uma chave de um byte).
        /// </summary>
        public static byte Detect(byte[] source)
        {
            if (source == null || source.Length < HeaderSize) return 0;

            byte key = (byte)(source[0] ^ SanityBytes[0]);
            if (key == 0) return 0;

            for (int i = 0; i < SanityBytes.Length; i++)
            {
                if ((byte)(source[i] ^ SanityBytes[i]) != key) return 0;
            }

            int version = ReadInt32(source, 4, key);
            if (version < MinVersion || version > MaxVersion) return 0;

            long highest = 0;
            for (int at = 8; at + 8 <= HeaderSize; at += 8)
            {
                int offset = ReadInt32(source, at, key);
                int size = ReadInt32(source, at + 4, key);
                if (offset < 0 || size < 0) return 0;
                if (offset > 0) highest = Math.Max(highest, (long)offset + size);
            }
            return highest >= 1 && highest <= source.LongLength ? key : (byte)0;
        }

        /// <summary>XOR no arquivo inteiro, no lugar.</summary>
        public static void Apply(byte[] source, byte key)
        {
            for (int i = 0; i < source.Length; i++) source[i] ^= key;
        }

        /// <summary>
        /// True se o buffer e um global-metadata.dat, em claro ou com XOR de um
        /// byte. Usado pra decidir qual dos argumentos e a metadata.
        /// </summary>
        public static bool LooksLikeMetadata(byte[] source)
        {
            if (source == null || source.Length < 4) return false;
            return BitConverter.ToUInt32(source, 0) == 0xFAB11BAF || Detect(source) != 0;
        }

        private static int ReadInt32(byte[] source, int at, byte key) =>
            (source[at] ^ key) |
            ((source[at + 1] ^ key) << 8) |
            ((source[at + 2] ^ key) << 16) |
            ((source[at + 3] ^ key) << 24);
    }
}
