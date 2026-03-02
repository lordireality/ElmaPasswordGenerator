# ElmaPasswordGenerator

Утилита для генерации пароля ELMA3/4. Поддерживает вызов из командной строки и опциональную генерацию SQL.

## Сборка (CLI)

## Требования

- .NET 5 SDK (target `net5.0`).

Проверка установленной версии:

```powershell
dotnet --version
```

## Сборка (CLI)

```powershell
dotnet build
```

Запуск без установки:

```powershell
dotnet run -- -pl 12 -pd true -ps true -generateSQL -exclId 1,2,3 -out C:\temp\password.txt
```

## Параметры командной строки

- `-pl <length>` — длина пароля (по умолчанию `12`).
- `-generateSQL` — генерировать SQL (флаг). Можно передать `true|false` или `1|0`.
- `-exclId <ids>` — список `id` через запятую.
  - В обычном режиме используется для `NOT IN` в SQL.
  - В режиме `-uniquePerExclId` становится списком целевых пользователей, для каждого из которых генерируется отдельный пароль.
- `-out <path>` — путь для сохранения результата в файл.
  - Если указан каталог, будет создан файл `password.txt`.
- `-pd [true|false]` — использовать ли цифры в пароле (по умолчанию `true`).
- `-ps [true|false]` — использовать ли спецсимволы в пароле (по умолчанию `true`).
- `-uniquePerExclId [true|false]` — генерировать уникальный `Password/Salt/Hash` для каждого `id` из `-exclId`.
- `-h`, `--help`, `/?` — показать справку.

Поддерживаются формы:
- `-key value`
- `-key=value`
- для флагов можно просто `-generateSQL`, `-pd`, `-ps`, `-uniquePerExclId` (эквивалент `true`)

## Примеры

Минимальный запуск (пароль 16 символов, без цифр и спецсимволов):

```powershell
dotnet run -- -pl 16 -pd false -ps false
```

Генерация SQL и запись в файл:

```powershell
dotnet run -- -pl 20 -generateSQL -exclId 10,12,15 -out C:\temp\password.txt
```

Уникальный пароль для каждого пользователя из списка:

```powershell
dotnet run -- -pl 20 -generateSQL -exclId 10,12,15 -uniquePerExclId -out C:\temp\password.txt
```

## Вывод

В консоль (и в файл, если указан `-out`) выводятся:
- `Password`
- `Salt`
- `Hash`
- `SQL` (если включен `-generateSQL`)

При `-uniquePerExclId` вывод формируется отдельным блоком для каждого `UserId`:
- `UserId`
- `Password`
- `Salt`
- `Hash`
- `SQL` (если включен `-generateSQL`)
