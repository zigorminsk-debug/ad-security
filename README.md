# AD Trust Repair

GUI-программа для Windows: проверяет компьютер в домене Active Directory и **восстанавливает
доверительные отношения** (secure channel) с доменом, если они нарушены.

Типичный симптом проблемы: при входе появляется сообщение
«Доверительные отношения между этой рабочей станцией и основным доменом не установлены»
(The trust relationship between this workstation and the primary domain failed) — вход в домен
невозможен, групповые политики не применяются. Приложение находит причину и чинит её.

![Иконка](src/AdTrustRepair/assets/app-256.png)

## Что делает программа

### 1. Диагностика

| Проверка | Что выясняет |
|---|---|
| Операционная система и права | версия Windows, наличие PowerShell, запуск от администратора |
| Членство в домене | `NetGetJoinInformation` — домен, рабочая группа или без членства |
| DNS | SRV-записи `_ldap._tcp.dc._msdcs.<домен>`, разрешение имени домена |
| Контроллер домена | `nltest /dsgetdc`, имя DC, ICMP-доступность |
| Защищённый канал | `Test-ComputerSecureChannel` (+ резервно `nltest /sc_query`) |
| Kerberos | получение билета `klist get krbtgt/<REALM>` |
| Время | расхождение часов с контроллером (`w32tm /stripchart`, порог Kerberos 5 минут) |
| Службы | Netlogon, LanmanWorkstation, LanmanServer, Dnscache, W32Time |
| Политики | `DisablePasswordChange`, `MaximumPasswordAge`, подпись/шифрование канала |
| Protected Users | не входит ли учётная запись компьютера в группу Protected Users |
| Устройство | `dsregcmd /status` (AD/Azure AD, ключ устройства, TPM) |
| Журналы | события NETLOGON за 7 дней (5719, 5722, 5723, 5783 и др.) |

По результатам выдаётся итоговый статус («Доверие в порядке» / «Доверие нарушено»),
список проверок с подробностями и рекомендации. Отчёт можно скопировать или сохранить в файл.

### 2. Восстановление

Перед изменением состояния программа показывает подтверждение и список действий.
Способы (по умолчанию — первый, при неудаче автоматически пробуются следующие):

1. **`Reset-ComputerMachinePassword` (рекомендуется)** — штатный способ Windows:
   новый пароль учётной записи компьютера записывается в AD и в локальный секрет,
   после чего восстанавливается защищённый канал. Нужны учётные данные администратора домена
   (или вход под доменной учётной записью с правами на сброс пароля компьютера).
   Пароль передаётся дочернему PowerShell через переменные окружения, а не через командную строку.
2. **`Test-ComputerSecureChannel -Repair`** — штатное восстановление канала
   (с указанными учётными данными или от текущей учётной записи).
3. **`netdom resetpwd`** — утилита Microsoft; пароль передаётся через stdin
   (`/passwordd:*`) и не попадает в командную строку и журнал.
4. **Экспертный: локальный сброс LSA + `NetUserSetInfo`** — без пароля администратора домена.
   В контексте SYSTEM читается секрет `$MACHINE.ACC`, расшифровывается DPAPI,
   задаётся новый пароль компьютера через `NetUserSetInfo`, затем оба секрета
   (`$MACHINE.ACC` и `SECRETS\MACHINE.ACC`) перезаписываются заново — уже корректно
   зашифрованным DPAPI-блобом (контекст машины) в формате `DOMAIN\COMPUTER$` + перевод строки + пароль.
   Способ работает, если у текущей учётной записи есть права на сброс пароля компьютера;
   исходный блоб сохраняется в резервную копию.
5. **`ksetup /setcomputerpassword`** — только по явному выбору оператора (при необходимости после
   `dsregcmd /leave`), автоматически не запускается: способ может нарушить ключ устройства (TPM/Intune).

Дополнительно: очистка кэша Kerberos (`klist purge`), сброс кэша DNS,
перезапуск службы Netlogon (чтобы LSA/Netlogon перечитали секрет),
`nltest /sc_verify` и `nltest /sc_reset`, при желании `gpupdate /force`.

В конце выполняется повторная проверка: `Test-ComputerSecureChannel` и получение билета Kerberos.
Результат, шаги, способ и возникшие ошибки отображаются в окне и пишутся в журнал.
Если Windows сгенерировала новый пароль компьютера, он не показывается; пароль, созданный
программой (экспертный способ), можно посмотреть в окне результата.

## Безопасность и предостережения

* Запуск **только от имени администратора** (манифест `requireAdministrator`).
* Сброс пароля компьютера — операция, изменяющая объект в AD. Не применяйте её
  «на всякий случай»: если доверие работает, программа это покажет.
* Исходный секрет LSA перед перезаписью сохраняется в
  `%ProgramData%\AdTrustRepair\Backups\MACHINE.ACC.<дата>.bin`.
* Пароли не пишутся в журнал. Пароль администратора домена не сохраняется на диск.
* Программа не отправляет данные в сеть, кроме штатных обращений к контроллеру домена
  (DNS, LDAP, Kerberos, RPC) — тем же, что делает сама Windows.
* Журнал: `%ProgramData%\AdTrustRepair\Logs\adtrustrepair-*.log`.
* Средство рассчитано на легитимное администрирование собственных компьютеров и домена.

## Сборка

Приложение собирается **в GitHub Actions** (workflow `.github/workflows/build.yml`,
раннер `windows-latest`) — установленный .NET SDK локально не нужен:

* на каждый push в `main`, в ветки `arena/**`, на pull request и вручную (`workflow_dispatch`)
  собирается self-contained single-file `AdTrustRepair.exe` (win-x64) и публикуется
  артефакт `AdTrustRepair-win-x64-<версия>.zip`;
* при push тега вида `v1.0.0` дополнительно создаётся GitHub Release с этим архивом.

Скачать готовую сборку: вкладка **Actions** → последний запуск **Build Windows app** →
артефакт **AdTrustRepair-win-x64-dev** (или релиз, если есть тег).

Локальная сборка (на Windows с .NET 8 SDK):

```powershell
dotnet publish src/AdTrustRepair/AdTrustRepair.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

## Требования

* Windows 10/11, Windows Server 2016+ (x64).
* Microsoft .NET 8 Desktop Runtime **не нужен** для self-contained сборки из CI.
* Учётная запись локального администратора; для способа `netdom` — администратор домена.
* Сетевой доступ к контроллеру домена (DNS 53, Kerberos 88, LDAP 389, SMB 445, RPC 135/49152+).

## Структура проекта

```
src/AdTrustRepair/
  Program.cs                 вход, проверка прав, перезапуск с повышением
  app.manifest               requireAdministrator, PerMonitorV2 DPI
  app.ico                    иконка
  Models/                    CheckResult, ScanReport, RepairOptions, RepairReport
  Native/                    P/Invoke: netapi32, advapi32 (LSA, токены), crypt32 (DPAPI), kernel32
  Services/
    DiagnosticsService.cs    все проверки
    RepairService.cs         стратегии восстановления
    ProcessRunner.cs         запуск утилит с захватом вывода и таймаутом
    AppLog.cs, ReportWriter.cs, PasswordGenerator.cs
  UI/                        MainForm, RepairForm, тема и виджеты (owner-draw)
```

## Как это работает «под капотом»

Пароль учётной записи компьютера хранится в LSA-секрете `$MACHINE.ACC`
в виде DPAPI-блоба (контекст машины) и содержит `DOMAIN\COMPUTER$` и пароль.
Изменить пароль в AD и синхронно обновить локальный секрет — значит восстановить
согласованность учётных данных, из которой и складывается «доверие» компьютера домену.
После этого Netlogon перезапускается, кэш билетов очищается, канал переустанавливается
(`nltest /sc_verify` / `/sc_reset`), и Windows снова может аутентифицироваться в домене.

## Лицензия

MIT — см. [LICENSE](LICENSE).
