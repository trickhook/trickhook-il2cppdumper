namespace Il2CppDumper
{
    /// <summary>
    /// CRC32 (IEEE, o mesmo do zlib) com as duas operacoes que o solver de
    /// permutacao precisa alem do calculo normal.
    ///
    /// O CRC32 e afim sobre GF(2): pra um comprimento fixo N vale
    /// crc(A ^ B) = crc(A) ^ crc(B) ^ crc(zeros de N bytes). E a parte
    /// puramente linear T(X) = crc(X) ^ crc(zeros) satisfaz
    /// T(A || B) = M_|B| * T(A) ^ T(B), onde M e o operador "avanca n bytes"
    /// que o crc32_combine do zlib aplica.
    ///
    /// Juntando as duas, o CRC de uma secao montada como "base XOR varias
    /// janelas posicionadas" vira um XOR de contribuicoes pre-calculadas, uma
    /// por (janela de destino, janela de origem). Dai testar uma permutacao
    /// custa 8 XORs em vez de reprocessar os 8 MB da secao.
    /// </summary>
    public static class FFCrc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                t[i] = c;
            }
            return t;
        }

        public static uint Compute(byte[] data, long offset, long length)
        {
            uint c = 0xFFFFFFFFu;
            for (long i = 0; i < length; i++)
                c = Table[(c ^ data[offset + i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        /// CRC32 de <paramref name="length"/> bytes zero.
        public static uint OfZeros(long length)
        {
            uint c = 0xFFFFFFFFu;
            for (long i = 0; i < length; i++)
                c = Table[c & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        /// CRC32 da concatenacao de A e B, dados crc(A), crc(B) e o tamanho de B.
        /// Mesma construcao do crc32_combine do zlib.
        public static uint Combine(uint first, uint second, long secondLength)
        {
            if (secondLength <= 0) return first;

            var odd = new uint[32];
            var even = new uint[32];

            odd[0] = 0xEDB88320u;
            uint row = 1;
            for (int i = 1; i < 32; i++)
            {
                odd[i] = row;
                row <<= 1;
            }

            Square(even, odd);
            Square(odd, even);

            uint crc = first;
            long len = secondLength;
            do
            {
                Square(even, odd);
                if ((len & 1) != 0) crc = Times(even, crc);
                len >>= 1;
                if (len == 0) break;

                Square(odd, even);
                if ((len & 1) != 0) crc = Times(odd, crc);
                len >>= 1;
            } while (len != 0);

            return crc ^ second;
        }

        private static uint Times(uint[] matrix, uint vector)
        {
            uint sum = 0;
            int index = 0;
            while (vector != 0)
            {
                if ((vector & 1) != 0) sum ^= matrix[index];
                vector >>= 1;
                index++;
            }
            return sum;
        }

        private static void Square(uint[] target, uint[] source)
        {
            for (int i = 0; i < 32; i++) target[i] = Times(source, source[i]);
        }
    }
}
