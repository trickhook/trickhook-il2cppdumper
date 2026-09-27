using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Il2CppDumper
{
    /// <summary>
    /// Alguns jogos publicam um global-metadata.dat com o header padrao da
    /// versao mas com os *structs* encolhidos: campos que cabem em 16 bits
    /// viram u16, campos redundantes (token) desaparecem, e nada fica alinhado.
    ///
    /// O dialeto implementado aqui foi derivado do Call of Duty Mobile 1.0.57
    /// (metadata v23, 61.895.504 bytes) e esta verificado para AQUELE build: a
    /// Il2CppTypeDefinition tem 80 bytes em vez dos 104 que a versao pede, a
    /// Il2CppMethodDefinition 42 em vez de 56, a Il2CppParameterDefinition 10 em
    /// vez de 16. Nada garante que outro build use os mesmos offsets - e por
    /// isso a deteccao valida antes de ativar, em vez de confiar no nome do
    /// arquivo ou do pacote. O lado binario (libunity.so) NAO tem dialeto:
    /// Il2CppCodeRegistration, Il2CppMetadataRegistration e Il2CppType sao o
    /// v23 padrao. O dialeto vive so no global-metadata.dat.
    ///
    /// A estrategia e a mesma do FFMethodLayout: nao bifurcar o parser. Cada
    /// registro compacto e lido campo a campo e reempacotado no layout que a
    /// versao pede, e so entao entregue ao ReadClassArray existente. Assim o
    /// resto do dumper (Il2CppExecutor, Il2CppDecompiler, ScriptJson,
    /// DummyAssemblyGenerator) nao sabe que o dialeto existe, e quem nao e
    /// compacto - o Free Fire, por exemplo - nem chega a ser sondado.
    ///
    /// Adicionar uma tabela nova e adicionar UMA entrada em
    /// <see cref="CompactV23"/>. Enquanto o layout interno de uma tabela nao
    /// for conhecido, da pra declarar so o Stride: a contagem de entradas sai
    /// certa (que e o que impede indice fora de faixa no resto do dump) e os
    /// campos saem zerados, com aviso.
    /// </summary>
    public sealed class CompactMetadata
    {
        /// Bytes de padding de alinhamento que aceitamos no fim de uma secao.
        /// As secoes sao alinhadas em 4, e os structs sao packed, entao sobram
        /// ate 3 bytes. Por isso NUNCA se deriva contagem por divisibilidade
        /// exata.
        public const int MaxAlignmentSlack = 3;

        /// Quantos registros a sondagem valida antes de aceitar um stride.
        public const int ProbeSampleSize = 3000;

        private readonly CompactDialect dialect;
        private readonly HashSet<Type> warnedAboutMissingMap = new();
        private readonly HashSet<Type> warnedAboutStandardMismatch = new();
        private int[] typeTokenRid;

        private CompactMetadata(CompactDialect dialect)
        {
            this.dialect = dialect;
        }

        public string Name => dialect.Name;

        /// Se esta tabela e uma das que o dialeto sabe transcodificar.
        public bool Handles(Type standardStruct) => dialect.Structs.ContainsKey(standardStruct);

        // ------------------------------------------------------------------
        // Deteccao
        // ------------------------------------------------------------------

        /// <summary>
        /// Decide se este metadata e de um dialeto compacto conhecido. Retorna
        /// null quando nao e - e nesse caso nada no caminho padrao muda. A
        /// decisao sai do conteudo do arquivo: nao ha checagem de nome de
        /// arquivo, de pacote nem de hash.
        ///
        /// A ordem das checagens importa:
        ///   1. o dialeto tem que declarar a mesma versao de metadata (o mapa de
        ///      campos so e valido para o conjunto de campos daquela versao) e
        ///      strides MENORES que os da versao (compacto e sempre menor; um
        ///      struct maior e o caso do FFMethodLayout, que e outro problema);
        ///   2. se o stride PADRAO fecha (resto &lt;= 3, nomes 100% validos e a
        ///      soma dos method_count divide methodsSize), e um metadata normal
        ///      e paramos aqui;
        ///   3. so entao o stride compacto e sondado, com os mesmos criterios;
        ///   4. e a validacao cruzada final: methodsSize / soma(method_count)
        ///      tem que dar exatamente o stride de metodo que o dialeto declara.
        /// Falhando qualquer uma, seguimos no caminho padrao com aviso.
        ///
        /// A validacao cruzada nao e enfeite: validade de nameIndex sozinha NAO
        /// identifica stride nenhum, porque num stride que e multiplo do
        /// verdadeiro todo registro amostrado ainda cai em cima de um nameIndex
        /// valido. E a contagem que desempata.
        /// </summary>
        public static CompactMetadata TryDetect(Metadata metadata)
        {
            foreach (var candidate in Dialects)
            {
                if (metadata.Version != candidate.MetadataVersion)
                    continue;
                if (!candidate.Structs.TryGetValue(typeof(Il2CppTypeDefinition), out var compactTypeDef))
                    continue;

                var header = metadata.header;
                var standardStride = metadata.SizeOf(typeof(Il2CppTypeDefinition));
                var standardMethod = metadata.SizeOf(typeof(Il2CppMethodDefinition));
                if (candidate.TypeDefinitionStride >= standardStride ||
                    candidate.MethodDefinitionStride >= standardMethod)
                {
                    Console.WriteLine($"WARNING: dialect '{candidate.Name}' declares strides that are not smaller than " +
                                      $"the standard ones for metadata v{metadata.Version} " +
                                      $"({candidate.TypeDefinitionStride} vs {standardStride}, " +
                                      $"{candidate.MethodDefinitionStride} vs {standardMethod}). A compact record is " +
                                      "always smaller, so this is a bug in the dialect table; not activating it.");
                    continue;
                }

                var raw = ReadSection(metadata, header.typeDefinitionsOffset, header.typeDefinitionsSize);
                if (raw == null)
                    continue;

                var standardLayout = TypeDefProbeLayout(metadata, standardStride);
                if (standardLayout != null && Probe(metadata, raw, standardLayout, out _, out _))
                    return null;

                var compactLayout = TypeDefProbeLayout(compactTypeDef);
                if (compactLayout == null)
                    continue;
                if (!Probe(metadata, raw, compactLayout, out var typeCount, out var methodSum))
                {
                    Console.WriteLine($"WARNING: Il2CppTypeDefinition does not fit the standard {standardStride}-byte " +
                                      $"layout of metadata v{metadata.Version} and does not fit the known compact " +
                                      $"{candidate.TypeDefinitionStride}-byte one either. Using the standard layout; " +
                                      "the dump may be wrong.");
                    continue;
                }
                if (methodSum <= 0 || header.methodsSize <= 0 || header.methodsSize % methodSum != 0)
                {
                    Console.WriteLine($"WARNING: the {candidate.TypeDefinitionStride}-byte compact Il2CppTypeDefinition " +
                                      $"reads {typeCount:N0} valid types but their method counts sum to {methodSum:N0}, " +
                                      $"which does not divide the {header.methodsSize:N0}-byte method table. Not " +
                                      "activating the compact layout; using the standard one.");
                    continue;
                }
                var methodStride = header.methodsSize / methodSum;
                if (methodStride != candidate.MethodDefinitionStride)
                {
                    Console.WriteLine($"WARNING: the compact Il2CppTypeDefinition cross-check gives an " +
                                      $"Il2CppMethodDefinition stride of {methodStride}, but dialect " +
                                      $"'{candidate.Name}' declares {candidate.MethodDefinitionStride}. Not " +
                                      "activating the compact layout; using the standard one.");
                    continue;
                }

                Console.WriteLine($"Compact metadata dialect '{candidate.Name}' detected: Il2CppTypeDefinition is " +
                                  $"{candidate.TypeDefinitionStride} bytes instead of {standardStride} and " +
                                  $"Il2CppMethodDefinition {methodStride} instead of {standardMethod}; transcoding " +
                                  $"{typeCount:N0} types and {methodSum:N0} methods to the standard v{metadata.Version} layout.");
                return new CompactMetadata(candidate);
            }
            return null;
        }

        private static byte[] ReadSection(Metadata metadata, uint offset, int size)
        {
            if (size <= 0) return null;
            if (offset + (ulong)(uint)size > metadata.Length) return null;
            metadata.Position = offset;
            var raw = metadata.ReadBytes(size);
            return raw.Length == size ? raw : null;
        }

        /// Campos de que a sondagem precisa: os dois indices de string que se
        /// validam contra a tabela de strings, e o method_count que faz a
        /// validacao cruzada com methodsSize.
        private sealed class ProbeLayout
        {
            public int Stride;
            public CompactField NameIndex;
            public CompactField NamespaceIndex;
            public CompactField MethodCount;
        }

        private static ProbeLayout TypeDefProbeLayout(CompactStruct compact)
        {
            if (!compact.Fields.TryGetValue(nameof(Il2CppTypeDefinition.nameIndex), out var name)) return null;
            if (!compact.Fields.TryGetValue(nameof(Il2CppTypeDefinition.namespaceIndex), out var ns)) return null;
            if (!compact.Fields.TryGetValue(nameof(Il2CppTypeDefinition.method_count), out var mc)) return null;
            return new ProbeLayout { Stride = compact.Stride, NameIndex = name, NamespaceIndex = ns, MethodCount = mc };
        }

        /// O mesmo descritor, mas derivado do struct padrao da versao, para que
        /// as duas sondagens usem exatamente o mesmo criterio.
        private static ProbeLayout TypeDefProbeLayout(Metadata metadata, int standardStride)
        {
            var fields = StandardFields(typeof(Il2CppTypeDefinition), metadata.Version);
            if (fields == null) return null;
            var layout = new ProbeLayout { Stride = standardStride };
            var offset = 0;
            foreach (var field in fields)
            {
                var signed = field.Signed ? CompactSign.Signed : CompactSign.Unsigned;
                switch (field.Name)
                {
                    case nameof(Il2CppTypeDefinition.nameIndex):
                        layout.NameIndex = new CompactField(offset, field.Size, signed); break;
                    case nameof(Il2CppTypeDefinition.namespaceIndex):
                        layout.NamespaceIndex = new CompactField(offset, field.Size, signed); break;
                    case nameof(Il2CppTypeDefinition.method_count):
                        layout.MethodCount = new CompactField(offset, field.Size, signed); break;
                }
                offset += field.Size;
            }
            if (offset != standardStride) return null;
            if (layout.NameIndex == null || layout.NamespaceIndex == null || layout.MethodCount == null) return null;
            return layout;
        }

        private static bool Probe(Metadata metadata, byte[] raw, ProbeLayout layout,
                                  out int count, out long methodCountSum)
        {
            count = 0;
            methodCountSum = 0;
            if (layout.Stride <= 0) return false;
            count = raw.Length / layout.Stride;
            if (count <= 0) return false;
            if (raw.Length - count * layout.Stride > MaxAlignmentSlack) return false;

            // Nomes: exigir 100% numa amostra espalhada pela tabela inteira.
            // Um stride errado quase sempre erra ja no segundo registro, mas
            // amostrar so o comeco deixa passar strides que acertam por acaso
            // numa regiao.
            var step = Math.Max(1, count / ProbeSampleSize);
            for (var i = 0; i < count; i += step)
            {
                if (!LooksLikeString(metadata, Read(raw, i * layout.Stride, layout.NameIndex))) return false;
                if (!LooksLikeString(metadata, Read(raw, i * layout.Stride, layout.NamespaceIndex))) return false;
            }
            if (!LooksLikeString(metadata, Read(raw, (count - 1) * layout.Stride, layout.NameIndex))) return false;

            for (var i = 0; i < count; i++)
            {
                var value = Read(raw, i * layout.Stride, layout.MethodCount);
                if (value < 0) return false;
                methodCountSum += value;
            }
            return true;
        }

        /// Indice de string plausivel: dentro da tabela e precedido de um NUL
        /// (ou seja, e o comeco de uma string, nao o meio de outra).
        private static bool LooksLikeString(Metadata metadata, long index)
        {
            if (index < 0 || index >= metadata.header.stringSize) return false;
            if (index == 0) return true;
            metadata.Position = metadata.header.stringOffset + (ulong)index - 1;
            return metadata.ReadByte() == 0;
        }

        // ------------------------------------------------------------------
        // Transcodificacao
        // ------------------------------------------------------------------

        /// <summary>
        /// Se <typeparamref name="T"/> tem entrada no dialeto, le a tabela
        /// compacta e devolve um buffer no layout padrao, pronto para o
        /// ReadClassArray. Retorna false quando a tabela nao e compacta (ou
        /// nao da para transcodificar com seguranca), e nesse caso o chamador
        /// segue no caminho padrao.
        /// </summary>
        public bool TryTranscode<T>(Metadata metadata, uint addr, int size, int standardSize,
                                    out byte[] buffer, out int count) where T : new()
        {
            buffer = null;
            count = 0;
            if (!dialect.Structs.TryGetValue(typeof(T), out var compact)) return false;
            if (compact.Stride <= 0 || size < 0) return false;
            if (compact.Stride >= standardSize)
            {
                // Um registro compacto e sempre menor que o padrao. Se nao for,
                // o que esta acontecendo e outra coisa (campo extra, e ai o
                // caso e do FFMethodLayout) e transcodificar seria chute.
                Console.WriteLine($"WARNING: dialect '{dialect.Name}' declares a {compact.Stride}-byte " +
                                  $"{typeof(T).Name}, which is not smaller than the standard {standardSize} bytes. " +
                                  "Reading it with the standard layout instead.");
                return false;
            }

            count = size / compact.Stride;
            if (size - count * compact.Stride > MaxAlignmentSlack)
            {
                Console.WriteLine($"WARNING: the {typeof(T).Name} table is {size:N0} bytes, which is not a whole " +
                                  $"number of {compact.Stride}-byte compact records. Reading it with the standard " +
                                  $"{standardSize}-byte layout instead; the dump may be wrong.");
                count = 0;
                return false;
            }
            if (count == 0)
            {
                buffer = Array.Empty<byte>();
                return true;
            }

            // Validacao cruzada por tabela: quem tem uma contagem derivavel de
            // outra tabela ja lida tem que fechar com ela. E o unico criterio
            // que distingue um stride do seu multiplo - validade de nome passa
            // nos dois.
            if (compact.ExpectedCount != null)
            {
                var expected = compact.ExpectedCount(metadata);
                if (expected >= 0 && expected != count)
                {
                    Console.WriteLine($"WARNING: the compact {typeof(T).Name} table has {count:N0} entries at stride " +
                                      $"{compact.Stride}, but the tables that index it account for {expected:N0}. " +
                                      "The dialect may not match this build; continuing with the compact stride.");
                }
            }

            var fields = StandardFields(typeof(T), metadata.Version);
            if (fields == null || fields.Sum(x => x.Size) != standardSize)
            {
                // Se nao conseguimos reproduzir o layout padrao byte a byte, o
                // buffer sintetizado seria lido errado - melhor nao mexer.
                if (warnedAboutStandardMismatch.Add(typeof(T)))
                {
                    Console.WriteLine($"WARNING: cannot reproduce the standard layout of {typeof(T).Name} for " +
                                      $"metadata v{metadata.Version}, so the compact table cannot be transcoded. " +
                                      "Using the standard layout; the dump may be wrong.");
                }
                count = 0;
                return false;
            }

            var raw = ReadSection(metadata, addr, count * compact.Stride);
            if (raw == null)
            {
                count = 0;
                return false;
            }

            if (!compact.HasFieldMap && warnedAboutMissingMap.Add(typeof(T)))
            {
                Console.WriteLine($"WARNING: {typeof(T).Name} has a known compact stride ({compact.Stride}) but its " +
                                  $"field layout has not been reverse-engineered yet, so its {count:N0} entries will " +
                                  "be blank. The entry count is still correct, which is what keeps the rest of the " +
                                  "dump in range.");
            }

            var total = (long)count * standardSize;
            if (total > int.MaxValue)
                throw new InvalidOperationException($"{typeof(T).Name} table too large to transcode");
            buffer = new byte[total];

            for (var i = 0; i < count; i++)
            {
                var src = i * compact.Stride;
                var dst = i * standardSize;
                foreach (var field in fields)
                {
                    if (compact.Fields.TryGetValue(field.Name, out var mapped))
                    {
                        if (mapped.Sign == CompactSign.Raw)
                            Buffer.BlockCopy(raw, src + mapped.Offset, buffer, dst, Math.Min(mapped.Width, field.Size));
                        else
                            Write(buffer, dst, field.Size, Read(raw, src, mapped));
                    }
                    else if (compact.Synthesized.TryGetValue(field.Name, out var synthesize))
                    {
                        Write(buffer, dst, field.Size, synthesize(metadata, this, i));
                    }
                    // Sem mapa e sem sintese o campo fica zerado - ja e o
                    // conteudo do buffer novo.
                    dst += field.Size;
                }
            }
            return true;
        }

        private static long Read(byte[] raw, int recordStart, CompactField field)
        {
            var at = recordStart + field.Offset;
            switch (field.Width)
            {
                case 1:
                    return raw[at];
                case 2:
                    var u16 = (ushort)(raw[at] | (raw[at + 1] << 8));
                    return field.Sign switch
                    {
                        CompactSign.Signed => (short)u16,
                        CompactSign.NoneSentinel => u16 == ushort.MaxValue ? -1L : u16,
                        _ => u16,
                    };
                case 4:
                    var u32 = (uint)(raw[at] | (raw[at + 1] << 8) | (raw[at + 2] << 16) | (raw[at + 3] << 24));
                    return field.Sign switch
                    {
                        CompactSign.Signed => (int)u32,
                        CompactSign.NoneSentinel => u32 == uint.MaxValue ? -1L : u32,
                        _ => u32,
                    };
                default:
                    throw new NotSupportedException($"compact field width {field.Width} not supported");
            }
        }

        private static void Write(byte[] buffer, int at, int size, long value)
        {
            for (var i = 0; i < size; i++)
                buffer[at + i] = (byte)(value >> (8 * i));
        }

        // ------------------------------------------------------------------
        // Layout padrao (tem que casar com BinaryStream.ReadClass)
        // ------------------------------------------------------------------

        private sealed class StandardField
        {
            public string Name;
            public int Size;
            public bool Signed;
        }

        private static readonly Dictionary<(Type, double), List<StandardField>> standardFieldCache = new();

        /// <summary>
        /// Campos do struct padrao na MESMA ordem e com o MESMO filtro de
        /// [Version] que BinaryStream.ReadClass usa - e o ReadClass que vai ler
        /// o buffer que sintetizamos, entao qualquer divergencia aqui desalinha
        /// tudo. Structs aninhados entram achatados com nome pontuado
        /// ("aname.nameIndex").
        /// </summary>
        private static List<StandardField> StandardFields(Type type, double version)
        {
            var key = (type, version);
            if (standardFieldCache.TryGetValue(key, out var cached)) return cached;
            var fields = new List<StandardField>();
            if (!CollectStandardFields(type, version, "", fields)) fields = null;
            standardFieldCache[key] = fields;
            return fields;
        }

        private static bool CollectStandardFields(Type type, double version, string prefix, List<StandardField> into)
        {
            foreach (var field in type.GetFields())
            {
                var versionAttributes = field.GetCustomAttributes<VersionAttribute>().ToArray();
                if (versionAttributes.Length > 0)
                {
                    // ReadClass aceita o campo se QUALQUER [Version] casar.
                    if (!versionAttributes.Any(a => version >= a.Min && version <= a.Max)) continue;
                }
                var fieldType = field.FieldType;
                var name = prefix + field.Name;
                if (fieldType.IsPrimitive)
                {
                    var size = PrimitiveSize(fieldType.Name);
                    if (size == 0) return false;
                    into.Add(new StandardField { Name = name, Size = size, Signed = IsSigned(fieldType.Name) });
                }
                else if (fieldType.IsEnum)
                {
                    var underlying = fieldType.GetField("value__").FieldType.Name;
                    var size = PrimitiveSize(underlying);
                    if (size == 0) return false;
                    into.Add(new StandardField { Name = name, Size = size, Signed = IsSigned(underlying) });
                }
                else if (fieldType.IsArray)
                {
                    var length = field.GetCustomAttribute<ArrayLengthAttribute>();
                    if (length == null || fieldType.GetElementType() != typeof(byte)) return false;
                    into.Add(new StandardField { Name = name, Size = length.Length, Signed = false });
                }
                else
                {
                    if (!CollectStandardFields(fieldType, version, name + ".", into)) return false;
                }
            }
            return true;
        }

        private static int PrimitiveSize(string name) => name switch
        {
            "Int32" or "UInt32" => 4,
            "Int16" or "UInt16" => 2,
            "Byte" or "SByte" => 1,
            // Int64/UInt64 passam por ReadIntPtr e mudam de tamanho com a ABI:
            // nenhum struct que transcodificamos tem isso, e adivinhar seria
            // pior do que recusar.
            _ => 0,
        };

        private static bool IsSigned(string name) => name is "Int32" or "Int16" or "SByte";

        // ------------------------------------------------------------------
        // Sintese de campos ausentes
        // ------------------------------------------------------------------

        /// <summary>
        /// O dialeto compacto jogou fora o token da Il2CppTypeDefinition, mas o
        /// dumper usa ele para casar tipo com atributo e com RGCTX. O token de
        /// um TypeDef e 0x02000000 | rid, e o rid e a posicao do tipo DENTRO da
        /// imagem dele (1-based), que e exatamente como o il2cpp gera.
        /// </summary>
        private static long SynthesizeTypeDefToken(Metadata metadata, CompactMetadata compact, int index)
        {
            return 0x02000000L | (uint)compact.TypeDefRid(metadata, index);
        }

        private int TypeDefRid(Metadata metadata, int index)
        {
            if (typeTokenRid == null)
            {
                var images = metadata.imageDefs;
                var typeCount = metadata.header.typeDefinitionsSize / dialect.TypeDefinitionStride;
                var rids = new int[Math.Max(typeCount, index + 1)];
                var covered = 0;
                if (images != null)
                {
                    foreach (var image in images)
                    {
                        if (image.typeStart < 0) continue;
                        var end = (long)image.typeStart + image.typeCount;
                        if (end > rids.Length) end = rids.Length;
                        for (var i = image.typeStart; i < end; i++)
                        {
                            rids[i] = i - image.typeStart + 1;
                            covered++;
                        }
                    }
                }
                // TODO: se as imagens ainda nao tiverem mapa de campos no
                // dialeto, typeStart/typeCount saem zerados e nao cobrem a
                // tabela. Ai o rid global (index + 1) e o melhor palpite: erra
                // o token de todo tipo fora da primeira imagem, mas nao trava
                // o dump. Com o layout de Il2CppImageDefinition no dialeto -
                // que e o caso hoje - este ramo nao e usado.
                if (covered < rids.Length)
                {
                    for (var i = 0; i < rids.Length; i++)
                        if (rids[i] == 0) rids[i] = i + 1;
                }
                typeTokenRid = rids;
            }
            return index >= 0 && index < typeTokenRid.Length ? typeTokenRid[index] : index + 1;
        }

        /// <summary>
        /// Token de uma tabela de metadata cujo rid nao da para recuperar por
        /// imagem. No v23 o dumper so usa estes tokens para IMPRIMIR (o
        /// GetCustomAttributeIndex de v&lt;=24 vai pelo customAttributeIndex, nao
        /// pelo token), entao um rid global 1-based e honesto: unico por
        /// registro, da tabela certa, e sem fingir ser o rid original do
        /// assembly.
        /// </summary>
        private static Func<Metadata, CompactMetadata, int, long> GlobalRidToken(uint table)
            => (metadata, compact, index) => ((long)table << 24) | (uint)(index + 1);

        // ------------------------------------------------------------------
        // Dialetos
        // ------------------------------------------------------------------

        public static readonly CompactDialect[] Dialects = { CompactV23() };

        /// <summary>
        /// Dialeto compacto de metadata v23, derivado do Call of Duty Mobile
        /// 1.0.57. A regra de projeto observada, que vale para todas as tabelas:
        /// campo que precisa de mais de 16 bits continua int32 e e promovido
        /// para o inicio do struct; todo o resto vira u16 mantendo a ordem
        /// relativa do struct original. Nada e alinhado. Nos campos *Start de
        /// lista a sentinela "nenhum" e 0xFFFF (u16) ou -1 (int32); nos
        /// customAttributeIndex a sentinela e 0, porque o registro 0 de
        /// attributesInfo e um (start=0, count=0) proprio para isso.
        ///
        /// Estado das tabelas (medido em E:\codm\global-metadata.dat,
        /// 61.895.504 bytes):
        ///   typeDefinitions    80  52.237
        ///   methods            42 477.894
        ///   parameters         10 383.627
        ///   fields             10 354.693
        ///   properties         12  42.514
        ///   events             16     572
        ///   images             20      21
        ///   assemblies         66      21
        ///   genericContainers  12   1.622
        ///   genericParameters  14   2.087
        ///   attributesInfo      4  10.559
        ///   metadataUsageLists  6 266.725
        ///   fieldRefs           6     916
        ///
        /// Tabelas que NAO precisam de entrada:
        ///   nestedTypes, interfaces, vtableMethods, genericParameterConstraints,
        ///   attributeTypes  - arrays de int32 crus, stride 4 nos dois dialetos;
        ///   metadataUsagePairs (8), stringLiteral (8), fieldDefaultValues (12),
        ///   parameterDefaultValues (12), rgctxEntries (8) - identicos ao padrao,
        ///   verificados;
        ///   interfaceOffsets (6), fieldMarshaledSizes (10), referencedAssemblies
        ///   (2) e unresolvedVirtualCallParameterRanges (4) tambem encolheram,
        ///   mas este fork nao le nenhuma delas - se algum dia ler, os strides
        ///   estao aqui.
        ///
        /// Um campo do header mente: metadataUsagesCount da 266.725, e o array
        /// real tem 218.847 entradas. O Il2CppDumper ja ignora esse campo e
        /// deriva a contagem dos pares; nao comece a confiar nele.
        /// </summary>
        private static CompactDialect CompactV23()
        {
            var dialect = new CompactDialect
            {
                Name = "compact v23",
                MetadataVersion = 23,
                TypeDefinitionStride = 80,
                MethodDefinitionStride = 42,
            };

            dialect.Add<Il2CppTypeDefinition>(80, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("namespaceIndex", U32(4));
                s.Map("byvalTypeIndex", I32(8));
                s.Map("byrefTypeIndex", I32(12));
                s.Map("declaringTypeIndex", I32(16));
                s.Map("parentIndex", I32(20));
                s.Map("elementTypeIndex", I32(24));
                s.Map("flags", U32(28));
                s.Map("fieldStart", I32(32));
                s.Map("methodStart", I32(36));
                s.Map("vtableStart", I32(40));
                s.Map("customAttributeIndex", I16(44));
                s.Map("rgctxStartIndex", I16(46));
                s.Map("rgctxCount", I16(48));
                s.Map("genericContainerIndex", I16(50));
                s.Map("eventStart", I16(52));
                s.Map("propertyStart", N16(54));
                s.Map("nestedTypesStart", N16(56));
                s.Map("interfacesStart", N16(58));
                s.Map("interfaceOffsetsStart", N16(60));
                s.Map("method_count", U16(62));
                s.Map("property_count", U16(64));
                s.Map("field_count", U16(66));
                s.Map("event_count", U16(68));
                s.Map("nested_type_count", U16(70));
                s.Map("vtable_count", U16(72));
                s.Map("interfaces_count", U16(74));
                s.Map("interface_offsets_count", U16(76));
                s.Map("bitfield", U16(78));
                s.Synthesize("token", SynthesizeTypeDefToken);
            });

            dialect.Add<Il2CppMethodDefinition>(42, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("methodIndex", I32(4));
                s.Map("returnType", I32(8));
                s.Map("parameterStart", I32(12));
                s.Map("token", U32(16));
                s.Map("declaringType", U16(20));
                s.Map("customAttributeIndex", U16(22));
                s.Map("genericContainerIndex", N16(24));
                s.Map("invokerIndex", N16(26));
                s.Map("delegateWrapperIndex", N16(28));
                s.Map("rgctxStartIndex", N16(30));
                s.Map("rgctxCount", U16(32));
                s.Map("flags", U16(34));
                s.Map("iflags", U16(36));
                // slot e ushort tambem no struct padrao, e 0xFFFF ("sem slot")
                // e o valor que o resto do dumper espera - nao virar -1 aqui.
                s.Map("slot", U16(38));
                s.Map("parameterCount", U16(40));
                s.CrossCheck(m => Sum(m.typeDefs, t => t.method_count));
            });

            dialect.Add<Il2CppParameterDefinition>(10, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("customAttributeIndex", U16(4));
                s.Map("typeIndex", I32(6));
                s.Synthesize("token", GlobalRidToken(0x08));
                s.CrossCheck(m => Sum(m.methodDefs, x => x.parameterCount));
            });

            dialect.Add<Il2CppFieldDefinition>(10, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("typeIndex", I32(4));
                s.Map("customAttributeIndex", U16(8));
                s.Synthesize("token", GlobalRidToken(0x04));
                s.CrossCheck(m => Sum(m.typeDefs, t => t.field_count));
            });

            dialect.Add<Il2CppPropertyDefinition>(12, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("get", I16(4));
                s.Map("set", I16(6));
                // attrs e 0 em todos os 42.514 registros deste build (um
                // metadata v31 padrao tambem da 0 aqui), entao o rotulo e
                // inferido, nao provado. Nao vale assertar em cima dele.
                s.Map("attrs", U16(8));
                s.Map("customAttributeIndex", U16(10));
                s.Synthesize("token", GlobalRidToken(0x17));
                s.CrossCheck(m => Sum(m.typeDefs, t => t.property_count));
            });

            dialect.Add<Il2CppEventDefinition>(16, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("typeIndex", I32(4));
                s.Map("add", I16(8));
                s.Map("remove", I16(10));
                s.Map("raise", I16(12));
                s.Map("customAttributeIndex", U16(14));
                s.Synthesize("token", GlobalRidToken(0x14));
                s.CrossCheck(m => Sum(m.typeDefs, t => t.event_count));
            });

            dialect.Add<Il2CppImageDefinition>(20, s =>
            {
                s.Map("nameIndex", U32(0));
                s.Map("assemblyIndex", I32(4));
                s.Map("typeStart", I32(8));
                s.Map("typeCount", U32(12));
                s.Map("entryPointIndex", I32(16));
                // O token de imagem e sempre 1 no il2cpp (a unica Module row);
                // e o que o proprio Il2CppDumper usa para distinguir v24 de
                // v24.1, e nao ha nada mais informativo para sintetizar.
                s.Synthesize("token", (metadata, compact, index) => 1);
            });

            dialect.Add<Il2CppAssemblyDefinition>(66, s =>
            {
                s.Map("imageIndex", I32(0));
                s.Map("customAttributeIndex", I16(4));
                s.Map("referencedAssemblyStart", I32(6));
                s.Map("referencedAssemblyCount", I32(10));
                // Il2CppAssemblyNameDefinition nao encolheu: os 52 bytes a
                // partir de +14 sao exatamente o layout padrao.
                s.Map("aname.nameIndex", U32(14));
                s.Map("aname.cultureIndex", U32(18));
                s.Map("aname.hashValueIndex", U32(22));
                s.Map("aname.publicKeyIndex", U32(26));
                s.Map("aname.hash_alg", U32(30));
                s.Map("aname.hash_len", I32(34));
                s.Map("aname.flags", U32(38));
                s.Map("aname.major", I32(42));
                s.Map("aname.minor", I32(46));
                s.Map("aname.build", I32(50));
                s.Map("aname.revision", I32(54));
                s.Map("aname.public_key_token", Bytes(58, 8));
                s.CrossCheck(m => m.imageDefs?.Length ?? -1);
            });

            dialect.Add<Il2CppGenericContainer>(12, s =>
            {
                // Ordem trocada em relacao ao struct padrao (que e ownerIndex,
                // type_argc, is_method, genericParameterStart): o mapa e por
                // nome, entao a troca sai de graca.
                s.Map("ownerIndex", I32(0));
                s.Map("genericParameterStart", I32(4));
                s.Map("type_argc", U16(8));
                s.Map("is_method", U16(10));
            });

            dialect.Add<Il2CppGenericParameter>(14, s =>
            {
                s.Map("nameIndex", U32(0));
                // ownerIndex e u16 aqui, nao i32: ler 4 bytes funde ele com
                // constraintsStart e a validade cai para 60%.
                s.Map("ownerIndex", U16(4));
                s.Map("constraintsStart", U16(6));
                s.Map("constraintsCount", U16(8));
                s.Map("num", U16(10));
                s.Map("flags", U16(12));
            });

            dialect.Add<Il2CppCustomAttributeTypeRange>(4, s =>
            {
                s.Map("start", U16(0));
                s.Map("count", U16(2));
            });

            dialect.Add<Il2CppMetadataUsageList>(6, s =>
            {
                s.Map("start", U32(0));
                s.Map("count", U16(4));
            });

            dialect.Add<Il2CppFieldRef>(6, s =>
            {
                s.Map("typeIndex", I32(0));
                s.Map("fieldIndex", U16(4));
            });

            return dialect;
        }

        private static long Sum<T>(T[] table, Func<T, int> select)
        {
            if (table == null) return -1;
            var total = 0L;
            foreach (var item in table) total += select(item);
            return total;
        }

        private static CompactField U32(int offset) => new(offset, 4, CompactSign.Unsigned);
        private static CompactField I32(int offset) => new(offset, 4, CompactSign.Signed);
        private static CompactField U16(int offset) => new(offset, 2, CompactSign.Unsigned);
        private static CompactField I16(int offset) => new(offset, 2, CompactSign.Signed);
        /// u16 em que 0xFFFF quer dizer "nenhum" e o campo padrao e assinado:
        /// tem que virar -1, senao o dumper indexa 65535 e estoura.
        private static CompactField N16(int offset) => new(offset, 2, CompactSign.NoneSentinel);
        private static CompactField Bytes(int offset, int length) => new(offset, length, CompactSign.Raw);
    }

    public enum CompactSign
    {
        Unsigned,
        Signed,
        /// Valor todo-1 significa "nenhum" e vira -1 no campo padrao.
        NoneSentinel,
        /// Bytes copiados como estao (arrays fixos).
        Raw,
    }

    public sealed class CompactField
    {
        public readonly int Offset;
        public readonly int Width;
        public readonly CompactSign Sign;

        public CompactField(int offset, int width, CompactSign sign)
        {
            Offset = offset;
            Width = width;
            Sign = sign;
        }
    }

    public sealed class CompactStruct
    {
        public int Stride;
        /// Nome do campo no struct padrao -> onde ler no registro compacto.
        /// Structs aninhados usam nome pontuado ("aname.nameIndex").
        public readonly Dictionary<string, CompactField> Fields = new();
        /// Campos que o dialeto jogou fora e o dumper ainda usa.
        public readonly Dictionary<string, Func<Metadata, CompactMetadata, int, long>> Synthesized = new();
        /// Quantas entradas esta tabela deveria ter, deduzido de tabelas ja
        /// lidas. Negativo = nao da para dizer agora.
        public Func<Metadata, long> ExpectedCount;

        public bool HasFieldMap => Fields.Count > 0 || Synthesized.Count > 0;

        public void Map(string standardField, CompactField source) => Fields[standardField] = source;

        public void Synthesize(string standardField, Func<Metadata, CompactMetadata, int, long> value)
            => Synthesized[standardField] = value;

        public void CrossCheck(Func<Metadata, long> expectedCount) => ExpectedCount = expectedCount;
    }

    public sealed class CompactDialect
    {
        public string Name;
        public double MetadataVersion;
        public int TypeDefinitionStride;
        public int MethodDefinitionStride;
        public readonly Dictionary<Type, CompactStruct> Structs = new();

        public void Add<T>(int stride, Action<CompactStruct> build)
        {
            var compact = new CompactStruct { Stride = stride };
            build?.Invoke(compact);
            Structs[typeof(T)] = compact;
        }
    }
}
