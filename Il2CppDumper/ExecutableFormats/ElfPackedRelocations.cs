using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    /// <summary>
    /// Uma relocacao ja desempacotada, no formato RELA (a variante REL de 32
    /// bits simplesmente ignora o Addend).
    /// </summary>
    internal struct PackedRelocation
    {
        public ulong Offset;
        public ulong Info;
        public ulong Addend;
    }

    internal sealed class PackedRelocationTable
    {
        public List<PackedRelocation> Entries;

        /// Algum grupo trouxe addend. Num .so de 32 bits isso nao deveria
        /// acontecer: o bionic recusa carregar a biblioteca nesse caso.
        public bool AnyAddend;

        /// Descricao do que ficou estranho, ou null se a leitura fechou limpa.
        /// Com Entries != null e um Problem != null, o que houve foi um aviso e
        /// nao uma falha - a tabela deu pra ler, mas nao bateu redondo.
        public string Problem;
    }

    /// <summary>
    /// Leitor das "Android packed relocations" (secao .rela.dyn comprimida,
    /// apontada por DT_ANDROID_RELA/DT_ANDROID_REL em vez de DT_RELA/DT_REL).
    ///
    /// O formato existe pra encolher a tabela de relocacoes de um .so PIE, que
    /// num binario IL2CPP grande e quase toda R_*_RELATIVE em enderecos
    /// consecutivos. Ele guarda a tabela como uma sequencia de grupos, e cada
    /// grupo pode fatorar os campos que se repetem: o passo do r_offset, o
    /// r_info, o addend. O que o grupo fatorou sai do cabecalho do grupo; o
    /// resto vem relocacao por relocacao. Todos os numeros sao sleb128, e todos
    /// os deltas podem ser negativos.
    ///
    /// Isto importa pra quem so tem o arquivo em disco: sem aplicar essas
    /// relocacoes, cada ponteiro em .data.rel.ro le como zero, porque o valor
    /// so aparece quando o loader roda. Foi o que travou o Call of Duty Mobile,
    /// cujo libunity.so tem DT_ANDROID_RELA e nenhum DT_RELA.
    ///
    /// Referencia: bionic/linker/linker_sleb128.h e
    /// bionic/linker/linker_relocs.h (packed_reloc_iterator), mais
    /// tools/relocation_packer do AOSP, que e quem escreve isto.
    /// </summary>
    internal static class ElfPackedRelocations
    {
        private const long RELOCATION_GROUPED_BY_INFO_FLAG = 1;
        private const long RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
        private const long RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
        private const long RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

        /// Teto de sanidade. A contagem declarada vem antes de qualquer byte de
        /// grupo, e um grupo totalmente fatorado nao gasta byte nenhum por
        /// relocacao, entao o tamanho do blob nao limita a contagem. Sem um
        /// teto, uma contagem corrompida viraria uma alocacao sem fim. O CODM,
        /// que e o maior caso real que temos, declara 2,18 milhoes.
        private const long SaneMaximum = 32_000_000;

        public static bool HasMagic(byte[] blob)
        {
            return blob != null && blob.Length >= 4
                && blob[0] == (byte)'A' && blob[1] == (byte)'P'
                && blob[2] == (byte)'S' && blob[3] == (byte)'2';
        }

        public static PackedRelocationTable Decode(byte[] blob)
        {
            var table = new PackedRelocationTable();
            if (!HasMagic(blob))
            {
                var head = blob == null || blob.Length == 0
                    ? "vazia"
                    : "comeca com " + BitConverter.ToString(blob, 0, Math.Min(4, blob.Length));
                table.Problem = $"nao e APS2 ({head})";
                return table;
            }

            var position = 4; // salta o "APS2"
            try
            {
                var total = (long)ReadSleb128(blob, ref position);
                if (total < 0 || total > SaneMaximum)
                {
                    table.Problem = $"a contagem declarada ({total}) nao faz sentido";
                    return table;
                }

                var offset = ReadSleb128(blob, ref position);
                ulong addend = 0;
                var entries = new List<PackedRelocation>((int)total);

                var done = 0L;
                while (done < total)
                {
                    var groupSize = (long)ReadSleb128(blob, ref position);
                    var groupFlags = (long)ReadSleb128(blob, ref position);
                    if (groupSize <= 0 || groupSize > total - done)
                    {
                        table.Problem = $"grupo de tamanho {groupSize} depois de " +
                                        $"{done} de {total} relocacoes";
                        return table;
                    }

                    var groupedByOffsetDelta = (groupFlags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
                    var groupedByInfo = (groupFlags & RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
                    var groupedByAddend = (groupFlags & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
                    var hasAddend = (groupFlags & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;

                    // A ordem aqui e a do formato e nao pode ser trocada.
                    var groupOffsetDelta = groupedByOffsetDelta ? ReadSleb128(blob, ref position) : 0ul;
                    var groupInfo = groupedByInfo ? ReadSleb128(blob, ref position) : 0ul;
                    if (hasAddend && groupedByAddend)
                    {
                        // Uma vez por grupo, nao uma vez por relocacao: quando o
                        // grupo fatora o addend, todas as relocacoes dele ficam
                        // com o mesmo valor. E o que o packed_reloc_iterator do
                        // bionic faz (o += esta em read_group_fields, fora do
                        // laco), e o que o empacotador do AOSP assume ao gravar.
                        addend += ReadSleb128(blob, ref position);
                    }

                    for (var i = 0L; i < groupSize; i++)
                    {
                        // So le o que o grupo nao fatorou, nesta mesma ordem.
                        offset += groupedByOffsetDelta ? groupOffsetDelta : ReadSleb128(blob, ref position);
                        var info = groupedByInfo ? groupInfo : ReadSleb128(blob, ref position);
                        if (hasAddend)
                        {
                            if (!groupedByAddend)
                            {
                                // Cumulativo entre relocacoes, e nao zerado a
                                // cada grupo: o que vem no stream e o passo em
                                // relacao ao addend anterior.
                                addend += ReadSleb128(blob, ref position);
                            }
                        }
                        else
                        {
                            addend = 0;
                        }
                        entries.Add(new PackedRelocation { Offset = offset, Info = info, Addend = addend });
                    }

                    table.AnyAddend |= hasAddend;
                    done += groupSize;
                }

                table.Entries = entries;
                if (position != blob.Length)
                {
                    // Nao e fatal, mas e o sinal mais barato de que a leitura
                    // saiu de sincronia: a contagem e o tamanho do blob sao dois
                    // testes independentes, e num arquivo saudavel os dois
                    // fecham no mesmo byte.
                    table.Problem = $"sobraram {blob.Length - position} byte(s) sem ler " +
                                    $"de {blob.Length}";
                }
                return table;
            }
            catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException or OutOfMemoryException)
            {
                table.Entries = null;
                table.Problem = $"a tabela acabou antes da contagem declarada " +
                                $"(byte {position} de {blob.Length})";
                return table;
            }
        }

        /// <summary>
        /// LEB128 com sinal, do jeito que o bionic le: acumula num inteiro de 64
        /// bits, o que significa que os bits acima do 63 somem. Nao e detalhe -
        /// um delta negativo faz a soma dar a volta, e sem descartar esses bits
        /// os enderecos saem com um bit alto sobrando e param de mapear.
        /// </summary>
        private static ulong ReadSleb128(byte[] blob, ref int position)
        {
            ulong value = 0;
            var shift = 0;
            byte current;
            do
            {
                current = blob[position++];
                if (shift < 64)
                {
                    value |= (ulong)(current & 0x7f) << shift;
                }
                shift += 7;
            } while ((current & 0x80) != 0);

            if (shift < 64 && (current & 0x40) != 0)
            {
                value |= ~0ul << shift; // == -(1 << shift), em 64 bits
            }
            return value;
        }
    }

    /// <summary>
    /// Conta o que a passagem de relocacoes fez, pra que ela possa dizer em voz
    /// alta em vez de nao fazer nada em silencio.
    /// </summary>
    internal sealed class RelocationTally
    {
        private readonly SortedDictionary<ulong, int> skippedByType = new();

        public int Applied;
        public string Note;
        public Exception Aborted;

        public int Skipped => skippedByType.Values.Sum();

        public void Skip(ulong type)
        {
            skippedByType.TryGetValue(type, out var count);
            skippedByType[type] = count + 1;
        }

        public string Describe(string source)
        {
            var text = new StringBuilder();
            text.Append(source).Append(": ").Append(Applied).Append(" applied");
            if (Skipped > 0)
            {
                text.Append(", ").Append(Skipped).Append(" skipped (unhandled type ");
                text.Append(string.Join(", ", skippedByType.Select(x => $"{x.Key} x{x.Value}")));
                text.Append(')');
            }
            if (Note != null)
            {
                text.Append(" [").Append(Note).Append(']');
            }
            if (Aborted != null)
            {
                text.Append(" - STOPPED EARLY: ").Append(Aborted.GetType().Name);
            }
            return text.ToString();
        }
    }
}
