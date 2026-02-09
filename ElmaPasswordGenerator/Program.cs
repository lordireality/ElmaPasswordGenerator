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
        private static readonly Microsoft.Extensions.ObjectPool.ObjectPool<RNGCryptoServiceProvider> RngCryptoServiceProviderPool = Microsoft.Extensions.ObjectPool.ObjectPool.Create<RNGCryptoServiceProvider>();
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

                var generatedPassword = GeneratePassword(options.Length, options.UseDigits, options.UseSpecial);
                var salt = GenerateSalt();
                var passwordHash = GetSha256Hash(generatedPassword, salt);

                string sql = null;
                if (options.GenerateSql)
                {
                    sql = BuildSql(passwordHash, salt, options.ExcludedIds);
                }

                var output = BuildOutput(generatedPassword, salt, passwordHash, sql);
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

        static char GetRandomChar(string chars)
        {
            return chars[GetRandomInt(chars.Length)];
        }

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
                return ActionWithMemoryBuffer<byte, (SHA256Managed, string, string, int), string>(byteCount1 + byteCount2, (shA256Managed, input, salt, byteCount1), new MemoryHelper.ActionWithMemoryBufferAndParameterDelegate<byte, (SHA256Managed, string, string, int), string>(EncryptionHelper.GetSha256HashAction));
            }
            finally
            {
                Sha256ManagedPool.Return(shA256Managed);
            }
        }

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

        public static void CheckArgument(bool condition, string conditionText)
        {
            if (!condition)
                throw new ArgumentException("Неверное значение аргумента. Нарушено условие: {0}", conditionText);
        }

        public static void ArgumentNotNull(object value, string argumentName)
        {
            if (value == null)
                throw new ArgumentNullException(argumentName);
        }

        public delegate TResult ActionWithMemoryBufferAndParameterDelegate<in T, in TParam, out TResult>(T[] buffer, int bufferOffset, int bufferLength, TParam param);

        private sealed class CliOptions
        {
            public int Length { get; set; } = 12;
            public bool GenerateSql { get; set; }
            public List<int> ExcludedIds { get; set; } = new List<int>();
            public string OutputPath { get; set; }
            public bool UseDigits { get; set; } = true;
            public bool UseSpecial { get; set; } = true;
            public bool ShowHelp { get; set; }
        }

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
                    default:
                        throw new ArgumentException($"Неизвестный аргумент: -{key}");
                }
            }

            return options;
        }

        private static bool IsHelpArg(string arg)
        {
            return string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "/?", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetNextValue(string[] args, ref int index, string argName)
        {
            if (index + 1 >= args.Length || args[index + 1].StartsWith("-"))
            {
                throw new ArgumentException($"Отсутствует значение для -{argName}");
            }
            index++;
            return args[index];
        }

        private static int ParsePositiveInt(string value, string argName)
        {
            if (!int.TryParse(value, out var parsed) || parsed <= 0)
            {
                throw new ArgumentException($"Неверное значение для -{argName}: {value}");
            }
            return parsed;
        }

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

            return result;
        }

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

        private static void WriteOutputFile(string outputPath, string content)
        {
            File.WriteAllText(outputPath, content, new UTF8Encoding(false));
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Помощь:");
            Console.WriteLine("  ElmaPasswordGenerator -pl 12 -pd true -ps true -generateSQL -exclId 1,2,3 -out C:\\temp\\password.txt");
            Console.WriteLine("Параметры:");
            Console.WriteLine("  -pl <length>        Длина пароля (12 по умолчанию)");
            Console.WriteLine("  -generateSQL        Генерировать SQL (flag or true/false)");
            Console.WriteLine("  -exclId <ids>       разделенные запятой Id пользователей для NOT IN в SQL");
            Console.WriteLine("  -out <path>         Директория куда будет сохранен файл (writes txt)");
            Console.WriteLine("  -pd [true|false]    Использовать ли числа в пароле (по умолчанию true)");
            Console.WriteLine("  -ps [true|false]    Использовать ли специальные символы в пароле (по умолчанию true)");
        }
    }
}
