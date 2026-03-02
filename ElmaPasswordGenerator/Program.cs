using Microsoft.Extensions.ObjectPool;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


namespace ElmaPasswordGenerator
{
    internal class Program
    {
        /// <summary>
        /// Пул для переиспользования экземпляров RNGCryptoServiceProvider
        /// </summary> <remarks>
        /// В .NET 6 и выше можно использовать RandomNumberGenerator.Shared
        /// </remarks>   
        private static readonly Microsoft.Extensions.ObjectPool.ObjectPool<RNGCryptoServiceProvider> RngCryptoServiceProviderPool = Microsoft.Extensions.ObjectPool.ObjectPool.Create<RNGCryptoServiceProvider>();
        /// <summary>     
        ///  Пул для переиспользования экземпляров SHA256Managed
        /// </summary>
        private static readonly Microsoft.Extensions.ObjectPool.ObjectPool<SHA256Managed> Sha256ManagedPool = Microsoft.Extensions.ObjectPool.ObjectPool.Create<SHA256Managed>();
        static int Main(string[] args)
        {
            try
            {
                var options = ParseArgs(args);
                if (options.ShowHelp)
                {
                    PrintUsage();
                    return 0;
                }

                ValidateOptions(options);

                string output;
                if (options.GenerateUniquePerExclId)
                {
                    var entries = BuildPerUserPasswordEntries(options);
                    output = BuildPerUserOutput(entries);
                }
                else
                {
                    var generatedPassword = GeneratePassword(options.Length, options.UseDigits, options.UseSpecial);
                    var salt = GenerateSalt();
                    var passwordHash = GetSha256Hash(generatedPassword, salt);

                    string sql = null;
                    if (options.GenerateSql)
                    {
                        sql = BuildSql(passwordHash, salt, options.ExcludedIds);
                    }

                    output = BuildOutput(generatedPassword, salt, passwordHash, sql);
                }

                Console.WriteLine(output);

                if (!string.IsNullOrWhiteSpace(options.OutputPath))
                {
                    var outputPath = ResolveOutputPath(options.OutputPath);
                    WriteOutputFile(outputPath, output);
                    Console.WriteLine($"Сохранено в: {outputPath}");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                PrintUsage();
                return 1;
            }
        }

        /// <summary>
        /// Генерация пароля с заданными параметрами
        /// </summary> <param name="length">Длина пароля</param>
        /// <param name="useDigits">Включать ли цифры</param>
        /// <param name="useSpecial">Включать ли специальные символы</param> 
        /// <returns>Сгенерированный пароль</returns>
        static string GeneratePassword(int length, bool useDigits = true, bool useSpecial = true)
        {
            const string lower = "abcdefghijklmnopqrstuvwxyz";
            const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string digits = "0123456789";
            const string special = "!@#$%^&*()-_=+[]{};:,.<>?";

            var requiredCategories = 2 + (useDigits ? 1 : 0) + (useSpecial ? 1 : 0);
            if (length < requiredCategories)
            {
                throw new ArgumentException($"Длина пароля должна быть не меньше {requiredCategories}.");
            }

            string allChars = lower + upper + (useDigits ? digits : "") + (useSpecial ? special : "");
            var result = new StringBuilder(length);
            result.Append(GetRandomChar(lower));
            result.Append(GetRandomChar(upper));
            if (useDigits)
            {
                result.Append(GetRandomChar(digits));
            }
            if (useSpecial)
            {
                result.Append(GetRandomChar(special));
            }
            for (int i = result.Length; i < length; i++)
            {
                result.Append(GetRandomChar(allChars));
            }
            return new string(result.ToString().OrderBy(_ => GetRandomInt()).ToArray());
        }

        /// <summary>
        /// Получить случайный символ из строки
        /// </summary> 
        /// <param name="chars">Строка с символами для выбора</param> 
        /// <returns>Случайный символ</returns>
        static char GetRandomChar(string chars)
        {
            return chars[GetRandomInt(chars.Length)];
        }

        /// <summary>
        /// Получить случайное целое число от 0 до max-1
        /// </summary> <param name="max">Верхняя граница (исключительно)</param>
         /// <returns>Случайное целое число</returns>
        static int GetRandomInt(int max = int.MaxValue)
        {
            byte[] buffer = new byte[4];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
            int value = BitConverter.ToInt32(buffer, 0);
            return Math.Abs(value % max);
        }

        /// <summary>
        /// Генерация соли для пароля
        /// </summary> 
        /// <param name="size">Размер соли в байтах</param>
         /// <returns>Сгенерированная соль в виде строки</returns>
        private static string GenerateSalt(int size = 16)
        {
            byte[] numArray = new byte[size];
            RNGCryptoServiceProvider cryptoServiceProvider = (RNGCryptoServiceProvider)null;
            try
            {
                cryptoServiceProvider = RngCryptoServiceProviderPool.Get();
                cryptoServiceProvider.GetBytes(numArray);
                return Convert.ToBase64String(numArray);
            }
            finally
            {
                RngCryptoServiceProviderPool.Return(cryptoServiceProvider);
            }
        }

        /// <summary>
        /// Получить SHA256 хеш от пароля с солью
        /// </summary> 
        /// <param name="input">Пароль</param>
        /// <param name="salt">Соль</param>
        /// <returns>Хеш пароля с солью в виде строки</returns> 
        public static string GetSha256Hash(string input, string salt)
        {
            input = input ?? "";
            salt = salt ?? "";
            SHA256Managed shA256Managed = (SHA256Managed)null;
            try
            {
                shA256Managed = Sha256ManagedPool.Get();
                int byteCount1 = Encoding.UTF8.GetByteCount(input);
                int byteCount2 = Encoding.UTF8.GetByteCount(salt);
                return ActionWithMemoryBuffer<byte, (SHA256Managed, string, string, int), string>(byteCount1 + byteCount2, (shA256Managed, input, salt, byteCount1), new ActionWithMemoryBufferAndParameterDelegate<byte, (SHA256Managed, string, string, int), string>(GetSha256HashAction));
            }
            finally
            {
                Sha256ManagedPool.Return(shA256Managed);
            }
        }

        /// <summary>
        /// Действие для получения SHA256 хеша от пароля с солью, использующее буфер памяти для оптимизации производительности и уменьшения количества выделений памяти
        /// </summary> 
        /// <param name="buffer">Буфер памяти для записи байтов пароля и соли</param>
        /// <param name="offset">Смещение в буфере для записи</param>
        /// <param name="length">Длина данных для хеширования (длина пароля + длина соли в байтах)</param>
        /// <param name="param">Параметр, содержащий экземпляр SHA256Managed, пароль, соль и длину пароля в байтах для правильного размещения в буфере</param>
        /// <returns>Хеш пароля с солью в виде строки</returns>
        private static string GetSha256HashAction(byte[] buffer, int offset, int length, (SHA256Managed, string, string, int) param)
        {
            (SHA256Managed shA256Managed, string s1, string s2, int num) = param;
            Encoding.UTF8.GetBytes(s1, 0, s1.Length, buffer, offset);
            Encoding.UTF8.GetBytes(s2, 0, s2.Length, buffer, offset + num);
            return Convert.ToBase64String(shA256Managed.ComputeHash(buffer, offset, length));
        }



        /// <summary>
        /// Вспомогательный метод для работы с буфером памяти, выделяемым из пула
        /// </summary> <typeparam name="T">Тип данных в буфере</typeparam>
        /// <typeparam name="TParam">Тип параметра для действия</typeparam>
        /// <typeparam name="TResult">Тип результата действия</typeparam>
        /// <param name="minimumBufferLength">Минимальная длина буфера</param>
        /// <param name="param">Параметр для действия</param>
        /// <param name="action">Действие, использующее буфер и параметр</param>
        /// <returns>Результат действия</returns>
        public static TResult ActionWithMemoryBuffer<T, TParam, TResult>(int minimumBufferLength, TParam param, ActionWithMemoryBufferAndParameterDelegate<T, TParam, TResult> action)
        {
            CheckArgument(minimumBufferLength > 0, "minimumBufferLength > 0");
            ArgumentNotNull((object)action, nameof(action));
            using (IMemoryOwner<T> memoryOwner = MemoryPool<T>.Shared.Rent(minimumBufferLength))
            {
                ArraySegment<T> segment;
                if (MemoryMarshal.TryGetArray<T>((ReadOnlyMemory<T>)memoryOwner.Memory.Slice(0, minimumBufferLength), out segment))
                    return action(segment.Array, segment.Offset, minimumBufferLength, param);
                throw new InvalidOperationException("Ошибка выделения буфера памяти");
            }
        }

        /// <summary>
        /// Проверка условия для аргумента и выброс исключения при нарушении
        /// </summary> <param name="condition">Условие для проверки</param> 
        /// <param name="conditionText">Текст условия для сообщения об ошибке</param>
        public static void CheckArgument(bool condition, string conditionText)
        {
            if (!condition)
                throw new ArgumentException("Неверное значение аргумента. Нарушено условие: {0}", conditionText);
        }

        /// <summary> Проверка на null для аргумента и выброс исключения при нарушении
        /// </summary> <param name="value">Значение аргумента для проверки</param> 
        /// <param name="argumentName">Имя аргумента для сообщения об ошибке</param> 
        public static void ArgumentNotNull(object value, string argumentName)
        {
            if (value == null)
                throw new ArgumentNullException(argumentName);
        }

        /// <summary> Делегат для действий, использующих буфер памяти и дополнительный параметр
        /// </summary> 
        /// <typeparam name="T">Тип данных в буфере</typeparam>
        /// <typeparam name="TParam">Тип дополнительного параметра</typeparam>
        /// <typeparam name="TResult">Тип результата действия</typeparam>
        public delegate TResult ActionWithMemoryBufferAndParameterDelegate<in T, in TParam, out TResult>(T[] buffer, int bufferOffset, int bufferLength, TParam param);

        /// <summary> 
        /// Класс для хранения параметров командной строки
        /// </summary> 
        /// <remarks>Используется для удобства передачи параметров между методами и улучшения читаемости кода</remarks>
        private sealed class CliOptions
        {
            public int Length { get; set; } = 12;
            public bool GenerateSql { get; set; }
            public List<int> ExcludedIds { get; set; } = new List<int>();
            public string OutputPath { get; set; }
            public bool UseDigits { get; set; } = true;
            public bool UseSpecial { get; set; } = true;
            public bool ShowHelp { get; set; }
            public bool GenerateUniquePerExclId { get; set; }
        }

        /// <summary>
        /// Данные для сгенерированного пароля конкретного пользователя
        /// </summary>
        private sealed class UserPasswordEntry
        {
            public int UserId { get; set; }
            public string Password { get; set; }
            public string Salt { get; set; }
            public string Hash { get; set; }
            public string Sql { get; set; }
        }

        /// <summary>
        /// Разбор аргументов командной строки и заполнение объекта CliOptions
        /// </summary> <param name="args">Массив аргументов командной строки</param>
        /// <returns>Заполненный объект CliOptions с параметрами из командной строки</returns> 
        private static CliOptions ParseArgs(string[] args)
        {
            var options = new CliOptions();

            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (string.IsNullOrWhiteSpace(arg))
                {
                    continue;
                }

                if (IsHelpArg(arg))
                {
                    options.ShowHelp = true;
                    continue;
                }

                if (!arg.StartsWith("-"))
                {
                    throw new ArgumentException($"Неизвестный аргумент: {arg}");
                }

                var key = arg.StartsWith("--") ? arg.Substring(2) : arg.Substring(1);
                string value = null;
                var eqIndex = key.IndexOf('=');
                if (eqIndex >= 0)
                {
                    value = key.Substring(eqIndex + 1);
                    key = key.Substring(0, eqIndex);
                }

                switch (key.ToLowerInvariant())
                {
                    case "pl":
                        value = value ?? GetNextValue(args, ref i, "pl");
                        options.Length = ParsePositiveInt(value, "pl");
                        break;
                    case "generatesql":
                        options.GenerateSql = ParseBool(value, args, ref i, "generateSQL", defaultIfMissing: true);
                        break;
                    case "exclid":
                        value = value ?? GetNextValue(args, ref i, "exclId");
                        options.ExcludedIds = ParseIdList(value);
                        break;
                    case "out":
                        value = value ?? GetNextValue(args, ref i, "out");
                        options.OutputPath = value;
                        break;
                    case "pd":
                        options.UseDigits = ParseBool(value, args, ref i, "pd", defaultIfMissing: true);
                        break;
                    case "ps":
                        options.UseSpecial = ParseBool(value, args, ref i, "ps", defaultIfMissing: true);
                        break;
                    case "uniqueperexclid":
                        options.GenerateUniquePerExclId = ParseBool(value, args, ref i, "uniquePerExclId", defaultIfMissing: true);
                        break;
                    default:
                        throw new ArgumentException($"Неизвестный аргумент: -{key}");
                }
            }

            return options;
        }

        /// <summary>
        /// Проверка, является ли аргумент запросом помощи
        /// </summary> <param name="arg">Аргумент для проверки</param>
        /// <returns>true, если аргумент является запросом помощи; иначе false</returns>
        private static bool IsHelpArg(string arg)
        {
            return string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "/?", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Получить следующее значение из массива аргументов, проверяя его наличие и корректность
        /// </summary> <param name="args">Массив аргументов командной строки</param> 
        /// <param name="index">Текущий индекс в массиве аргументов (будет увеличен на 1 после получения значения)</param>
        /// <param name="argName">Имя аргумента для сообщения об ошибке при отсутствии значения</param>
        /// <returns>Следующее значение из массива аргументов</returns>
        private static string GetNextValue(string[] args, ref int index, string argName)
        {
            if (index + 1 >= args.Length || args[index + 1].StartsWith("-"))
            {
                throw new ArgumentException($"Отсутствует значение для -{argName}");
            }
            index++;
            return args[index];
        }

        /// <summary>
        /// Разбор строки с разделителями и преобразование ее в список целых чисел для исключенных Id
        /// </summary> <param name="value">Строка с разделителями, содержащая Id для исключения</param>
        /// <returns>Список целых чисел, представляющих Id для исключения</returns>
        private static int ParsePositiveInt(string value, string argName)
        {
            if (!int.TryParse(value, out var parsed) || parsed <= 0)
            {
                throw new ArgumentException($"Неверное значение для -{argName}: {value}");
            }
            return parsed;
        }
        
        /// <summary>
        /// Разбор строки в булево значение, поддерживающий различные форматы (true/false, 1/0) и учитывающий отсутствие значения для флагов
        /// </summary> <param name="value">Строка для разбора в булево значение (может быть null для флагов)</param>
        /// <param name="args">Массив аргументов командной строки для получения следующего значения, если value равно null</param>
        /// <param name="index">Текущий индекс в массиве аргументов (будет увеличен на 1, если будет использовано следующее значение)</param>
        /// <param name="argName">Имя аргумента для сообщения об ошибке при неверном значении</param>
        /// <param name="defaultIfMissing">Значение по умолчанию, если value равно null и нет следующего значения (используется для флагов)</param>
        /// <returns>Разобранное булево значение</returns> 
        private static bool ParseBool(string value, string[] args, ref int index, string argName, bool defaultIfMissing)
        {
            if (value == null)
            {
                if (index + 1 < args.Length && !args[index + 1].StartsWith("-"))
                {
                    value = args[++index];
                }
                else
                {
                    return defaultIfMissing;
                }
            }

            if (bool.TryParse(value, out var parsed))
            {
                return parsed;
            }

            if (value == "1")
            {
                return true;
            }

            if (value == "0")
            {
                return false;
            }

            throw new ArgumentException($"Неверное значение для -{argName}: {value}");
        }

        /// <summary>
        /// Разбор строки с разделителями и преобразование ее в список целых чисел для исключенных Id
        /// </summary> <param name="value">Строка с разделителями, содержащая Id для исключения</param>
        /// <returns>Список целых  чисел, представляющих Id для исключения</returns>
        private static List<int> ParseIdList(string value)
        {
            var result = new List<int>();
            if (string.IsNullOrWhiteSpace(value))
            {
                return result;
            }

            foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = part.Trim();
                if (!int.TryParse(trimmed, out var id))
                {
                    throw new ArgumentException($"Неверный id в -exclId: {trimmed}");
                }
                result.Add(id);
            }

            return result.Distinct().ToList();
        }

        /// <summary>
        /// Проверка согласованности параметров перед генерацией
        /// </summary>
        private static void ValidateOptions(CliOptions options)
        {
            if (options.GenerateUniquePerExclId && (options.ExcludedIds == null || options.ExcludedIds.Count == 0))
            {
                throw new ArgumentException("Для -uniquePerExclId необходимо указать хотя бы один id через -exclId.");
            }
        }

        /// <summary>
        /// Генерация набора уникальных паролей для каждого указанного Id
        /// </summary>
        private static List<UserPasswordEntry> BuildPerUserPasswordEntries(CliOptions options)
        {
            var result = new List<UserPasswordEntry>(options.ExcludedIds.Count);

            foreach (var userId in options.ExcludedIds)
            {
                var password = GeneratePassword(options.Length, options.UseDigits, options.UseSpecial);
                var salt = GenerateSalt();
                var hash = GetSha256Hash(password, salt);

                result.Add(new UserPasswordEntry
                {
                    UserId = userId,
                    Password = password,
                    Salt = salt,
                    Hash = hash,
                    Sql = options.GenerateSql ? BuildSqlForUser(hash, salt, userId) : null
                });
            }

            return result;
        }

        /// <summary>
        /// Построение SQL запроса для обновления пароля с учетом исключенных Id
        /// </summary> <param name="passwordHash">Хеш пароля для установки</param>
        /// <param name="salt">Соль для установки</param>
        /// <param name="excludedIds">Список Id пользователей, которые не должны быть обновлены (будут исключены из условия WHERE)</param>
        /// <returns>Сформированный SQL запрос в виде строки</returns>
        private static string BuildSql(string passwordHash, string salt, IReadOnlyList<int> excludedIds)
        {
            var sb = new StringBuilder();
            sb.AppendLine("UPDATE \"usersecurityprofile\"");
            sb.AppendLine($"SET \"Password\" = '{passwordHash}', salt = '{salt}', forcedchangepassword = NULL, countfailedlogon = NULL");
            if (excludedIds != null && excludedIds.Count > 0)
            {
                sb.AppendLine($"WHERE \"User\" NOT IN ({string.Join(", ", excludedIds)});");
            }
            else
            {
                sb.AppendLine(";");
            }
            return sb.ToString().TrimEnd();
        }

        /// <summary>
        /// Построение SQL запроса для обновления пароля конкретного пользователя
        /// </summary>
        private static string BuildSqlForUser(string passwordHash, string salt, int userId)
        {
            var sb = new StringBuilder();
            sb.AppendLine("UPDATE \"usersecurityprofile\"");
            sb.AppendLine($"SET \"Password\" = '{passwordHash}', salt = '{salt}', forcedchangepassword = NULL, countfailedlogon = NULL");
            sb.AppendLine($"WHERE \"User\" = {userId};");
            return sb.ToString().TrimEnd();
        }

        /// <summary>
        /// Построение итогового вывода с информацией о пароле, соли, хеше и SQL запросе (если требуется)
        /// </summary> <param name="password">Сгенерированный пароль</param>
        /// <param name="salt">Соль для пароля</param>
        /// <param name="passwordHash">Хеш пароля с солью</param>
        /// <param name="sql">SQL запрос для обновления пароля (может быть null, если не требуется)</param>
        /// <returns>Сформированная строка для вывода в консоль и/или файл</returns>
        private static string BuildOutput(string password, string salt, string passwordHash, string sql)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Password: {password}");
            sb.AppendLine($"Salt: {salt}");
            sb.AppendLine($"Hash: {passwordHash}");
            if (!string.IsNullOrWhiteSpace(sql))
            {
                sb.AppendLine("SQL:");
                sb.Append(sql.TrimEnd());
            }
            return sb.ToString().TrimEnd();
        }

        /// <summary>
        /// Построение итогового вывода для режима отдельных паролей по Id
        /// </summary>
        private static string BuildPerUserOutput(IReadOnlyList<UserPasswordEntry> entries)
        {
            var sb = new StringBuilder();
            var sqlBuilder = new StringBuilder();

            for (int i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                sb.AppendLine($"UserId: {entry.UserId}");
                sb.AppendLine($"Password: {entry.Password}");
                sb.AppendLine($"Salt: {entry.Salt}");
                sb.AppendLine($"Hash: {entry.Hash}");

                if (i < entries.Count - 1)
                {
                    sb.AppendLine();
                }

                if (!string.IsNullOrWhiteSpace(entry.Sql))
                {
                    if (sqlBuilder.Length > 0)
                    {
                        sqlBuilder.AppendLine();
                    }

                    sqlBuilder.AppendLine(entry.Sql.TrimEnd());
                }
            }

            if (sqlBuilder.Length > 0)
            {
                sb.AppendLine();
                sb.AppendLine("SQL:");
                sb.Append(sqlBuilder.ToString().TrimEnd());
            }

            return sb.ToString().TrimEnd();
        }

        /// <summary>
        /// Разрешение пути для сохранения файла, поддерживающее как директории, так и полные пути к файлам, а также создание необходимых директорий
        /// </summary> <param name="outputPath">Путь, указанный пользователем для сохранения файла (может быть директорией или полным путем к файлу)</param>
        /// <returns>Разрешенный полный путь к файлу для сохранения</returns>
        private static string ResolveOutputPath(string outputPath)
        {
            var trimmed = outputPath?.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                throw new ArgumentException("Путь к файлу пуст.");
            }

            if (Directory.Exists(trimmed))
            {
                return Path.Combine(trimmed, "password.txt");
            }

            if (trimmed.EndsWith(Path.DirectorySeparatorChar.ToString()) || trimmed.EndsWith(Path.AltDirectorySeparatorChar.ToString()))
            {
                var dir = trimmed.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                Directory.CreateDirectory(dir);
                return Path.Combine(dir, "password.txt");
            }

            var directory = Path.GetDirectoryName(trimmed);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            return trimmed;
        }

        /// <summary>
        /// Запись содержимого в файл с использованием UTF-8 без BOM
        /// </summary> <param name="outputPath">Путь к файлу для сохранения</param>
        /// <param name="content">Содержимое для записи в файл</param>
        private static void WriteOutputFile(string outputPath, string content)
        {
            File.WriteAllText(outputPath, content, new UTF8Encoding(false));
        }

        /// <summary>
        /// Вывод справки по использованию программы в консоль
        /// </summary>
        private static void PrintUsage()
        {
            Console.WriteLine("Помощь:");
            Console.WriteLine("  ElmaPasswordGenerator -pl 12 -pd true -ps true -generateSQL -exclId 1,2,3 -out C:\\temp\\password.txt");
            Console.WriteLine("  ElmaPasswordGenerator -pl 12 -generateSQL -exclId 10,12 -uniquePerExclId");
            Console.WriteLine("Параметры:");
            Console.WriteLine("  -pl <length>        Длина пароля (12 по умолчанию)");
            Console.WriteLine("  -generateSQL        Генерировать SQL (flag or true/false)");
            Console.WriteLine("  -exclId <ids>       Id через запятую: для NOT IN или целевые пользователи в -uniquePerExclId");
            Console.WriteLine("  -out <path>         Директория куда будет сохранен файл (writes txt)");
            Console.WriteLine("  -pd [true|false]    Использовать ли числа в пароле (по умолчанию true)");
            Console.WriteLine("  -ps [true|false]    Использовать ли специальные символы в пароле (по умолчанию true)");
            Console.WriteLine("  -uniquePerExclId    Генерировать уникальный пароль для каждого id из -exclId");
        }
    }
}
