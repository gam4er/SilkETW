Сначала важная терминологическая поправка: в NTLM **challenge отправляет не клиентское приложение**, а сервер. Клиент отправляет **NEGOTIATE / Type 1**, сервер отвечает **CHALLENGE / Type 2**, клиент отправляет **AUTHENTICATE / Type 3**. Поэтому если приложение «отправляет NTLM на внешний ресурс», то локально тебе надо доказать одно из двух: либо что клиент **получил Type 2 challenge** от внешнего ресурса, либо что после challenge он отправил **Type 3 response**. Сам NTLM — это SSP/SSPI security package, а не отдельный сетевой протокол; он может ехать внутри HTTP, SMB, RPC, LDAP, WinRM, SQL-клиентов и вообще любого приложения, которое гоняет SSPI-токены. Microsoft прямо описывает NTLM как challenge/response-пакет через SSPI, а Negotiate выбирает Kerberos, если может, и падает в NTLM, если Kerberos невозможен. ([learn.microsoft.com][1]) ([learn.microsoft.com][2])

## Самый короткий ответ для твоего кейса

Если это **HTTP/HTTPS внешний ресурс**, я бы включал минимум:

| Задача                                                          | Провайдеры / журналы                                                                                                                                                                                                          |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Понять, что вообще был NTLM, какой процесс, куда, почему NTLM   | **Microsoft-Windows-NTLM** + `Microsoft-Windows-NTLM/Operational`                                                                                                                                                             |
| Понять HTTP-аутентификационный обмен 401/407, server/proxy auth | **Microsoft-Windows-WinHttp**, **Microsoft-Windows-WinINet**, **Microsoft-Windows-WebIO** — в зависимости от стека приложения                                                                                                 |
| Увидеть сетевой обмен / привязать к IP/соединению               | `netsh trace capture=yes`, **Microsoft-Windows-TCPIP**, System Network provider                                                                                                                                               |
| Доказать именно Type 2 challenge в HTTP                         | В cleartext HTTP искать `WWW-Authenticate: NTLM TlRMTVNTUAAC...` или `Proxy-Authenticate: NTLM TlRMTVNTUAAC...`; для HTTPS — только клиентские ETW/логирование стека, MITM-debug proxy в lab, либо instrumentation приложения |
| Если это SMB                                                    | **Microsoft-Windows-SMBClient**, **Microsoft-Windows-SMBServer**, `Microsoft-Windows-SMBServer/Security`, Security 4624/4625                                                                                                  |
| Если это DC/pass-through validation                             | **Microsoft-Windows-Security-Netlogon**, `Microsoft-Windows-NTLM/Operational`, Security 4776                                                                                                                                  |

На Windows 11 24H2 / Windows Server 2025 появилась особенно полезная enhanced NTLM audit telemetry: `Microsoft-Windows-NTLM/Operational` пишет client-side outgoing attempts, server-side incoming attempts и DC-side validations с полями вроде process name/PID, user, target machine/resource/IP, negotiated flags, NTLM version, session key presence, channel binding, service binding, MIC и AV flags. Для client-side это события **4020/4021**, для server-side **4022/4023**, для DC — **4030/4031/4032/4033**. Это сейчас самый ценный встроенный источник для «кто, куда и почему пошёл по NTLM», но он не всегда даёт сырой NTLMSSP Type 2 blob. ([support.microsoft.com][3]) ([support.microsoft.com][3]) ([support.microsoft.com][3]) ([support.microsoft.com][3])

---

# 1. Что именно доказывать: Type 1 / Type 2 / Type 3

Для HTTP это выглядит так:

```text
Client  -> Server: GET /resource
Server  -> Client: 401 Unauthorized
                  WWW-Authenticate: NTLM

Client  -> Server: GET /resource
                  Authorization: NTLM <Type1 NEGOTIATE>

Server  -> Client: 401 Unauthorized
                  WWW-Authenticate: NTLM <Type2 CHALLENGE>

Client  -> Server: GET /resource
                  Authorization: NTLM <Type3 AUTHENTICATE>

Server  -> Client: 200 OK / 403 / etc
```

Для proxy-auth аналогично, но вместо `WWW-Authenticate` / `Authorization` будут `Proxy-Authenticate` / `Proxy-Authorization`, а HTTP status будет **407**. WinHTTP-документация прямо описывает 401/407 и то, что NTLM/Negotiate являются challenge-response схемами, причём NTLM требует нескольких обменов на одном соединении. ([learn.microsoft.com][4])

Практический маркер в HTTP-заголовках:

```text
TlRMTVNTUAAB...  -> NTLMSSP Type 1 / NEGOTIATE
TlRMTVNTUAAC...  -> NTLMSSP Type 2 / CHALLENGE
TlRMTVNTUAAD...  -> NTLMSSP Type 3 / AUTHENTICATE
```

Если у тебя **HTTPS**, то обычный packet capture увидит TCP/TLS, но не увидит `WWW-Authenticate: NTLM ...`. Тогда остаются: ETW провайдеры клиентского HTTP-стека, логирование приложения, Fiddler/mitmproxy в controlled lab с доверенным root CA, либо instrumentation на уровне SSPI/HTTP library.

---

# 2. Главные NTLM-релевантные провайдеры

## Core NTLM / SSPI / Netlogon

| Провайдер / журнал                         | GUID / имя                               | Когда нужен                                      | Что даёт                                                                                                                    |
| ------------------------------------------ | ---------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| **Microsoft-Windows-NTLM**                 | `{AC43300D-5FCC-4800-8E99-1BD3F85F0320}` | Первый кандидат почти всегда                     | Факт NTLM, client/server/DC audit, target, process, NTLM version, negotiated security fields; на новых ОС события 4020–4033 |
| **Microsoft-Windows-NTLM/Operational**     | Event Log channel                        | Самый удобный operational view                   | Outgoing/incoming/DC NTLM events; особенно полезно на Windows 11 24H2 / Server 2025                                         |
| **Microsoft-Windows-Security-Netlogon**    | `{E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC}` | DC validation, pass-through auth, secure channel | Помогает понять, как NTLM дошёл до DC / trusted domain                                                                      |
| **Microsoft-Windows-Security-Auditing**    | Security.evtx                            | Не ETW-trace в обычном смысле, но must-have      | 4624/4625: Logon Process `NtLmSsp`, Authentication Package `NTLM`; 4776 на DC                                               |
| **LSA / LSA Operational**                  | зависит от версии ОС                     | Контекст security package / logon                | Вспомогательно, не всегда богато по NTLM                                                                                    |
| **Microsoft-Windows-Security-Kerberos**    | Kerberos provider                        | Не NTLM, но нужен для fallback analysis          | Показывает, почему Kerberos не состоялся и почему ушли в NTLM                                                               |
| **Microsoft-Windows-NegoExts / Negotiate** | зависит от ОС                            | SPNEGO / Negotiate                               | Полезно, если приложение говорит `Negotiate`, а не явно `NTLM`                                                              |

Архитектурно важный момент: NTLM SSP загружен в LSA, приложения ходят через SSPI-функции вроде `InitializeSecurityContext` / `AcceptSecurityContext`, а протокол-носитель уже решает, как именно переслать токен. Поэтому один только `Microsoft-Windows-NTLM` часто отвечает на вопрос «был ли NTLM», но для вопроса «где именно в протоколе был Type 2 challenge» нужен provider транспорта. ([learn.microsoft.com][5])

---

# 3. HTTP / HTTPS / proxy auth

Для внешнего ресурса это, вероятно, самый релевантный блок.

| Сценарий                              | Провайдеры                                                                  | Комментарий                                                                     |
| ------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Приложение использует WinHTTP         | **Microsoft-Windows-WinHttp** `{7D44233D-3055-4B9C-BA64-0D47CA40A232}`      | Серверная/служебная HTTP-аутентификация, proxy auth, 401/407, retries           |
| Приложение использует WinINet         | **Microsoft-Windows-WinINet** `{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}`      | Типично GUI/user-context приложения, IE/legacy components                       |
| Дополнительный WinINet capture/config | **Microsoft-Windows-WinINet-Capture**, **Microsoft-Windows-WinINet-Config** | Может помочь с headers/config/proxy, если доступно на системе                   |
| HTTP stack below WinINet/WinHTTP      | **Microsoft-Windows-WebIO** `{50B3E73C-9370-461D-BB9F-26F32D68887D}`        | Часто полезен как нижний слой HTTP-клиента                                      |
| HTTP.sys / server-side                | **Microsoft-Windows-HttpService**, legacy **HTTP Service Trace**            | Если ты контролируешь принимающую сторону или локальный IIS/HTTP.sys            |
| IIS                                   | IIS WWW / IIS Logging / W3SVC providers                                     | Если NTLM принимается IIS-сервером                                              |
| Managed .NET client                   | `System.Net.Http` EventSource + core NTLM/HTTP providers                    | Для .NET Core/5+/6+/8+ приложение может не идти через WinHTTP как основной стек |

Для WinHTTP особенно важно различать: server auth `401 + WWW-Authenticate` и proxy auth `407 + Proxy-Authenticate`; WinHTTP умеет обнаруживать схемы через auth headers и затем устанавливать credentials. Для NTLM/Negotiate это challenge-response, а Negotiate может fallback’нуться в NTLM, если Kerberos не сработал. ([learn.microsoft.com][4])

**Что я бы включил для HTTP-кейса:**

```powershell
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true

$providers = @(
  "Microsoft-Windows-NTLM",
  "Microsoft-Windows-WinHttp",
  "Microsoft-Windows-WinINet",
  "Microsoft-Windows-WebIO",
  "Microsoft-Windows-TCPIP",
  "Microsoft-Windows-Security-Netlogon"
)

$providers | ForEach-Object {
  logman query providers $_ 2>$null
}
```

Потом трасса:

```powershell
mkdir C:\Temp -Force | Out-Null

logman start NtLmHttpTrace -ets `
  -o C:\Temp\ntlm-http.etl `
  -nb 16 64 -bs 1024 `
  -p "Microsoft-Windows-NTLM" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WinHttp" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WinINet" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WebIO" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-TCPIP" 0xFFFFFFFFFFFFFFFF 0x5
```

Остановить:

```powershell
logman stop NtLmHttpTrace -ets
```

И отдельно operational events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" |
  Where-Object Id -in 4020,4021,4022,4023,4030,4031,4032,4033 |
  Select-Object TimeCreated, Id, ProviderName, Message |
  Format-List
```

Для сетевого уровня:

```powershell
netsh trace start scenario=InternetClient capture=yes report=no correlation=yes tracefile=C:\Temp\ntlm-netsh.etl
# воспроизвести проблему
netsh trace stop
```

`netsh trace` удобен тем, что сценарии включают наборы системных providers и могут дополнительно писать packet capture в ETL. Сами системные providers Microsoft описывает как kernel/system providers, которые включаются через системный logger и дают process/network/file/context, но не декодируют NTLM-семантику сами по себе. ([learn.microsoft.com][6])

---

# 4. SMB: лучший случай для доказательства NTLM challenge/response

Если NTLM идёт через SMB, то ETW намного богаче.

| Провайдер / журнал                       | GUID / канал                             | Что даёт                                                  |
| ---------------------------------------- | ---------------------------------------- | --------------------------------------------------------- |
| **Microsoft-Windows-SMBClient**          | `{988C59C5-0A1C-45B6-A555-0C62276E327D}` | Client-side SMB session setup, transport, auth failures   |
| **Microsoft-Windows-SMBServer**          | `{D48CE617-33A2-4BC3-A5C7-11AA4F29619E}` | Server-side SMB auth flow; очень ценный для входящих NTLM |
| **Microsoft-Windows-SMBServer/Security** | Event Log channel                        | SMB auth/security events                                  |
| **Security 4624/4625**                   | Security.evtx                            | Logon type 3, NTLM package, source IP, account            |
| **Microsoft-Windows-NTLM**               | core                                     | Общий NTLM context                                        |

Почему SMB особенно интересен: есть публичные исследования и tooling, показывающие, что `Microsoft-Windows-SMBServer` содержит достаточно данных, чтобы пассивно наблюдать NetNTLMv2-материал во входящих SMB-аутентификациях. Например, ETWHash прямо потребляет `Microsoft-Windows-SMBServer` и извлекает NetNTLMv2 из входящего SMB auth flow; это полезно как индикатор того, насколько богат этот provider для forensic/debug целей. ([GitHub][7]) ([LRQA][8])

Для штатного event log SMB есть, например, событие **551** в `Microsoft-Windows-SMBServer/Security`: SMB Session Authentication Failure, с client IP, username и error code. Это не заменяет полный NTLMSSP blob, но отлично коррелирует failed SMB NTLM. ([artefacts.help][9])

SMB troubleshooting-документация Microsoft также прямо показывает, что в SMB `SESSION_SETUP` есть security blob; именно там живёт SPNEGO/NTLMSSP/Kerberos обмен. ([learn.microsoft.com][10])

---

# 5. RPC / DCOM / WMI / SCM / named pipes

NTLM через RPC — это не отдельный «NTLM protocol», а SSPI security context поверх RPC binding/auth. Поэтому надо включать core NTLM + RPC providers.

| Сценарий                                 | Провайдеры                                                                                            |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| DCOM/WMI/SCM/Scheduler remote operations | **Microsoft-Windows-RPC**, **Microsoft-Windows-RPCSS**, **Microsoft-Windows-WMI-Activity**, core NTLM |
| RPC over SMB named pipes                 | RPC providers + **SMBClient/SMBServer**                                                               |
| RPC over TCP                             | RPC providers + TCPIP                                                                                 |
| Coerce/relay/debug auth attempts         | RPC + SMB + NTLM + Security 4624/4625 + Netlogon on DC                                                |

Релевантные провайдеры:

```text
Microsoft-Windows-RPC
Microsoft-Windows-RPCSS
Microsoft-Windows-RPC-Events
Microsoft-Windows-WMI-Activity
Microsoft-Windows-SMBClient
Microsoft-Windows-SMBServer
Microsoft-Windows-NTLM
Microsoft-Windows-Security-Netlogon
```

NTLM SSP официально описывается как пакет, который используется в том числе там, где приложения используют SSPI, включая SMB/CIFS, HTTP Negotiate и RPC. Поэтому для RPC-трассы без `Microsoft-Windows-NTLM` ты увидишь RPC context, endpoint/interface/opnum, но не всегда поймёшь, что именно была NTLM-аутентификация. ([learn.microsoft.com][1])

---

# 6. LDAP / AD / SASL bind

Для LDAP важно разделять:

```text
LDAP simple bind       -> не NTLM
LDAP SASL Negotiate    -> может быть Kerberos или NTLM
LDAP over SSPI         -> через Negotiate/NTLM/Kerberos
LDAPS                  -> TLS снаружи, auth внутри LDAP bind
```

Провайдеры:

| Провайдер                                        | Когда включать                                        |
| ------------------------------------------------ | ----------------------------------------------------- |
| **Microsoft-Windows-LDAP-Client**                | Client-side LDAP bind/search/connect troubleshooting  |
| **DirectoryServices-DS** / AD DS diagnostic logs | DC-side LDAP/KDC/Directory context                    |
| **Microsoft-Windows-NTLM**                       | Факт NTLM                                             |
| **Microsoft-Windows-Security-Kerberos**          | Проверить, была ли попытка Kerberos и почему fallback |
| **Microsoft-Windows-Security-Netlogon**          | Если DC валидирует NTLM                               |
| Security 4624/4625/4776                          | Итоговая аутентификация                               |

Microsoft прямо приводит LDAP среди сервисов, где Windows authentication через SSPI/Kerberos применяется штатно; если Kerberos невозможен, через Negotiate возможен fallback в NTLM. ([learn.microsoft.com][5])

---

# 7. IIS / HTTP.sys / inbound NTLM на сервере

Если ты контролируешь сервер, принимающий NTLM, то включал бы:

```text
Microsoft-Windows-NTLM
Microsoft-Windows-HttpService
Microsoft-Windows-IIS-Logging
IIS WWW / W3SVC providers
Microsoft-Windows-WinINet / WinHTTP только если на этой же машине есть client-side call
Security 4624/4625
```

Для IIS классический pattern:

| Что ищем                            | Где                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------- |
| HTTP 401.1 / 401.2 / 401.x          | IIS logs / HTTP.sys                                                              |
| `WWW-Authenticate: Negotiate, NTLM` | HTTP trace                                                                       |
| Type 1 / Type 2 / Type 3 headers    | HTTP trace, если не TLS или если server-side provider/logging раскрывает headers |
| Logon Process `NtLmSsp`             | Security 4624/4625                                                               |
| NTLM audit 4022/4023                | `Microsoft-Windows-NTLM/Operational` на новых ОС                                 |

---

# 8. WinRM / PowerShell Remoting

WinRM — это HTTP(S) + SPNEGO/Negotiate/CredSSP/Kerberos/NTLM depending configuration.

Провайдеры:

```text
Microsoft-Windows-WinRM
Microsoft-Windows-NTLM
Microsoft-Windows-WinHttp
Microsoft-Windows-WebIO
Microsoft-Windows-HttpService
Microsoft-Windows-Security-Kerberos
Microsoft-Windows-Security-Netlogon
Security 4624/4625
```

Если это client-side `Enter-PSSession`, `Invoke-Command`, remote management tooling — смотри WinRM + WinHTTP/WebIO. Если server-side — WinRM Operational + HTTP.sys + Security.

---

# 9. RDP / CredSSP / NLA

RDP NLA использует CredSSP/SPNEGO, внутри может быть Kerberos или NTLM.

Провайдеры:

```text
Microsoft-Windows-TerminalServices-RemoteConnectionManager
Microsoft-Windows-TerminalServices-LocalSessionManager
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS
Microsoft-Windows-CredSSP, если присутствует
Microsoft-Windows-NTLM
Microsoft-Windows-Security-Kerberos
Security 4624/4625
```

Что будет полезно:

| Источник           | Что покажет                                    |
| ------------------ | ---------------------------------------------- |
| TerminalServices-* | RDP connection/session lifecycle               |
| Security 4624      | Logon type 10 / 3 depending path, auth package |
| NTLM Operational   | Факт NTLM и target context на новых ОС         |
| Kerberos provider  | Почему не Kerberos                             |

---

# 10. Print Spooler / remote printer / spoolss

Print часто тянет за собой RPC + SMB + Kerberos/NTLM.

Провайдеры:

```text
Microsoft-Windows-PrintService
Microsoft-Windows-Spooler
Microsoft-Windows-RPC
Microsoft-Windows-RPCSS
Microsoft-Windows-SMBClient
Microsoft-Windows-SMBServer
Microsoft-Windows-NTLM
Security 4624/4625
```

Microsoft в списке Windows-сервисов, использующих Kerberos/SSPI, прямо упоминает print services; при невозможности Kerberos через Negotiate возможен NTLM. ([learn.microsoft.com][5])

---

# 11. SQL Server / ODBC / OLE DB / SSPI

Для SQL Server Windows Authentication тоже идёт через SSPI, но transport/provider уже не «универсально Windows NTLM», а application-specific.

Провайдеры:

```text
Microsoft-Windows-NTLM
Microsoft-Windows-Security-Kerberos
Microsoft-Windows-Security-Netlogon
Security 4624/4625
SQL Server ETW / Extended Events / SQL audit
Microsoft-Windows-TCPIP
```

Тут логика такая: SQL provider скажет, что было подключение/login, Security/NTLM/Kerberos скажут, каким auth package оно стало. Если нужен именно challenge blob, чаще проще смотреть сетевой TDS/SPNEGO в lab capture или SQL-side diagnostic logs.

---

# 12. WebDAV / WebClient / Office / Explorer to HTTP shares

WebDAV часто маскируется под «просто Windows куда-то лезет HTTP’ом», но auth может быть NTLM.

Провайдеры:

```text
Microsoft-Windows-WebClnt, если есть на системе
Microsoft-Windows-WinHttp
Microsoft-Windows-WinINet
Microsoft-Windows-WebIO
Microsoft-Windows-NTLM
Security 4624/4625
TCPIP
```

Для Office/Explorer/legacy Windows components часто приходится включать и WinINet, и WinHTTP, потому что заранее не всегда очевидно, какой стек реально используется.

---

# 13. AD CS / CertEnroll / enterprise services

AD CS enrollment, auto-enrollment, web enrollment, RPC/DCOM enrollment могут использовать Kerberos/NTLM через SSPI.

Провайдеры:

```text
Microsoft-Windows-CertificateServicesClient
Microsoft-Windows-CAPI2
Microsoft-Windows-CertEnroll
Microsoft-Windows-RPC
Microsoft-Windows-WinHttp / WinINet / WebIO, если HTTP endpoint
Microsoft-Windows-NTLM
Microsoft-Windows-Security-Kerberos
Microsoft-Windows-Security-Netlogon
```

Здесь NTLM обычно лучше ловить через core NTLM + transport, а не через CAPI2 alone. CAPI2 даст крипто/cert context, но не всегда auth negotiation.

---

# 14. Полезный «ультимативный» набор providers по категориям

Я бы держал такой allowlist для локального enumeration:

```powershell
$ProviderHints = @(
  # Core auth
  "Microsoft-Windows-NTLM",
  "Microsoft-Windows-Security-Netlogon",
  "Microsoft-Windows-Security-Kerberos",
  "Microsoft-Windows-LSA",

  # HTTP client/server
  "Microsoft-Windows-WinHttp",
  "Microsoft-Windows-WinINet",
  "Microsoft-Windows-WinINet-Capture",
  "Microsoft-Windows-WinINet-Config",
  "Microsoft-Windows-WebIO",
  "Microsoft-Windows-HttpService",

  # SMB
  "Microsoft-Windows-SMBClient",
  "Microsoft-Windows-SMBServer",

  # RPC / WMI / DCOM
  "Microsoft-Windows-RPC",
  "Microsoft-Windows-RPCSS",
  "Microsoft-Windows-RPC-Events",
  "Microsoft-Windows-WMI-Activity",

  # LDAP / AD
  "Microsoft-Windows-LDAP-Client",
  "Microsoft-Windows-DirectoryServices-DS",

  # WinRM / PSRemoting
  "Microsoft-Windows-WinRM",
  "Microsoft-Windows-PowerShell",

  # RDP / CredSSP
  "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
  "Microsoft-Windows-TerminalServices-LocalSessionManager",
  "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
  "Microsoft-Windows-CredSSP",

  # Print
  "Microsoft-Windows-PrintService",
  "Microsoft-Windows-Spooler",

  # Network/process correlation
  "Microsoft-Windows-TCPIP",
  "Microsoft-Windows-Winsock-AFD",
  "Microsoft-Windows-Kernel-Process",
  "Microsoft-Windows-Kernel-Network"
)

$ProviderHints | ForEach-Object {
  $name = $_
  $exists = logman query providers $name 2>$null
  if ($LASTEXITCODE -eq 0) {
    [PSCustomObject]@{ Provider = $name; Present = $true }
  } else {
    [PSCustomObject]@{ Provider = $name; Present = $false }
  }
}
```

Для event channels:

```powershell
wevtutil el | findstr /i "NTLM Netlogon Kerberos SMB WinHttp WinINet WebIO HTTP RPC LDAP WinRM Terminal CredSSP Print"
```

Для manifest dump:

```powershell
$providers = @(
  "Microsoft-Windows-NTLM",
  "Microsoft-Windows-WinHttp",
  "Microsoft-Windows-WinINet",
  "Microsoft-Windows-WebIO",
  "Microsoft-Windows-SMBClient",
  "Microsoft-Windows-SMBServer",
  "Microsoft-Windows-RPC",
  "Microsoft-Windows-Security-Netlogon"
)

foreach ($p in $providers) {
  $safe = $p -replace '[\\/:*?"<>|]', '_'
  wevtutil gp $p /ge:true /gm:true > "C:\Temp\$safe.manifest.txt" 2>$null
}
```

---

# 15. Как использовать Windows10EtwEvents / jdu2600

Репозиторий `Windows10EtwEvents` полезен как большая статическая база manifest/MOF ETW events по версиям Windows 10: в README указаны выгрузки по версиям, например для Windows 10 21H2 там десятки тысяч events и сотни manifest providers. ([GitHub][11])

Но я бы не использовал его как единственный источник истины для современной NTLM telemetry, потому что enhanced NTLM audit 4020–4033 — это уже Windows 11 24H2 / Windows Server 2025 история, а не Windows 10 21H2 baseline. Microsoft прямо пишет, что новые NTLM events улучшают существующие NTLM logs и появляются через Controlled Feature Rollout. ([support.microsoft.com][3])

Практически: репозиторий хорош, чтобы быстро понять, что у провайдера есть события и какие поля потенциально бывают, но для конкретной машины всегда делай:

```powershell
wevtutil gp Microsoft-Windows-NTLM /ge:true /gm:true
logman query providers Microsoft-Windows-NTLM
```

---

# 16. Мой recommended trace profile

## Вариант A: HTTP/HTTPS client отправляет NTLM наружу

```powershell
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true

logman start NtLmExternalHttp -ets `
  -o C:\Temp\NtLmExternalHttp.etl `
  -nb 16 64 -bs 1024 `
  -p "Microsoft-Windows-NTLM" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WinHttp" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WinINet" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WebIO" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-TCPIP" 0xFFFFFFFFFFFFFFFF 0x5

# reproduce

logman stop NtLmExternalHttp -ets
```

Параллельно:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" |
  Sort-Object TimeCreated -Descending |
  Select-Object -First 30 TimeCreated, Id, Message |
  Format-List
```

Что будет считаться сильным доказательством:

| Уровень доказательства   | Что увидел                                                                                                                    |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Сильнейшее               | В HTTP headers есть `WWW-Authenticate: NTLM TlRMTVNTUAAC...` или `Proxy-Authenticate: NTLM TlRMTVNTUAAC...`                   |
| Сильное                  | WinHTTP/WinINet/WebIO показывает 401/407 NTLM exchange, а NTLM Operational показывает outgoing NTLM к тому же host/IP/process |
| Косвенное, но нормальное | NTLM Operational 4020/4021 + после него успешный HTTP response / application success                                          |
| Слабое                   | Только Security 4624/4625 где-то на сервере без client-side correlation                                                       |

## Вариант B: SMB NTLM

```powershell
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true
wevtutil sl Microsoft-Windows-SMBServer/Security /e:true

logman start NtLmSmb -ets `
  -o C:\Temp\NtLmSmb.etl `
  -nb 16 64 -bs 1024 `
  -p "Microsoft-Windows-NTLM" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-SMBClient" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-SMBServer" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-TCPIP" 0xFFFFFFFFFFFFFFFF 0x5

# reproduce

logman stop NtLmSmb -ets
```

## Вариант C: RPC/WMI/DCOM подозрение

```powershell
logman start NtLmRpc -ets `
  -o C:\Temp\NtLmRpc.etl `
  -nb 16 64 -bs 1024 `
  -p "Microsoft-Windows-NTLM" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-RPC" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-RPCSS" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-WMI-Activity" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-SMBClient" 0xFFFFFFFFFFFFFFFF 0x5 `
  -p "Microsoft-Windows-TCPIP" 0xFFFFFFFFFFFFFFFF 0x5
```

---

# 17. Что точно не стоит ожидать от одного ETW provider

Я бы не рассчитывал, что один provider даст тебе универсально:

```text
process.exe -> target.example.com -> NTLM Type 1 raw blob -> Type 2 raw challenge -> Type 3 raw response
```

Причины:

1. **NTLM — SSPI package**, а не transport. Один и тот же NTLMSSP token может быть внутри HTTP header, SMB Session Setup security blob, RPC auth trailer, LDAP SASL bind, TDS login packet или кастомного протокола.

2. **TLS скрывает HTTP-заголовки** от сетевого capture.

3. **Microsoft-Windows-NTLM audit больше про факт/контекст/security properties**, чем про полный сырой NTLMSSP blob.

4. **SMBServer — исключение в хорошую сторону**: там ETW historically даёт очень богатый auth material, что видно по ETWHash/NetNTLMv2 research. ([GitHub][7])

5. **Windows build matters**: события и поля реально зависят от версии ОС; новые NTLM audit events появились в Windows 11 24H2 / Server 2025, а старые Windows 10 manifest dumps не будут полным отражением новых возможностей. ([support.microsoft.com][3])

---

# 18. Мой итоговый выбор

Для твоей конкретной формулировки — «приложение отправляет NTLM на внешний ресурс, надо убедиться, что challenge отправлен» — я бы делал так:

1. **Уточнил семантику в голове:** Type 2 challenge отправляет внешний сервер, клиент его получает. Если надо доказать именно Type 2 — ищем inbound HTTP `WWW-Authenticate/Proxy-Authenticate: NTLM <Type2>`.

2. **Включил `Microsoft-Windows-NTLM/Operational`** и смотрел 4020/4021: process/PID, target, IP/resource, reason, NTLM version, flags.

3. **Включил HTTP-stack providers:** WinHTTP + WinINet + WebIO, потому что заранее не всегда очевидно, чем пользуется приложение.

4. **Снял `netsh trace capture=yes`** для корреляции TCP/IP и, если HTTP без TLS, для прямого evidence по headers.

5. **Если это SMB/RPC/LDAP/WinRM**, добавил соответствующий transport provider, а не пытался выжать всё из `Microsoft-Windows-NTLM`.

Если нужен один «главный» provider — это **Microsoft-Windows-NTLM**.
Если нужен provider, который с наибольшей вероятностью покажет сам обмен на уровне протокола — это **provider транспорта**: для HTTP `WinHTTP/WinINet/WebIO`, для SMB `SMBClient/SMBServer`, для RPC `RPC/RPCSS`, для LDAP `LDAP-Client`.
А если нужен наиболее криминалистически сильный SMB NTLM evidence — **Microsoft-Windows-SMBServer** плюс Security/SMBServer-Security/NTLM Operational.

[1]: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture "Security Support Provider Interface Architecture | Microsoft Learn"
[2]: https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate "Microsoft Negotiate - Win32 apps | Microsoft Learn"
[3]: https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b "Overview of NTLM auditing enhancements in Windows 11, version 24H2 and Windows Server 2025 - Microsoft Support"
[4]: https://learn.microsoft.com/en-us/windows/win32/winhttp/authentication-in-winhttp "Authentication in WinHTTP - Win32 apps | Microsoft Learn"
[5]: https://learn.microsoft.com/en-us/windows/win32/secauthn/using-security-packages "Using Security Packages - Win32 apps | Microsoft Learn"
[6]: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers "System Providers - Win32 apps | Microsoft Learn"
[7]: https://github.com/nettitude/ETWHash "GitHub - nettitude/ETWHash: C# POC to extract NetNTLMv1/v2 hashes from ETW provider · GitHub"
[8]: https://www.lrqa.com/en/cyber-labs/etwhash-he-who-listens-shall-receive/ "ETWHash - \"He who listens, shall receive\""
[9]: https://artefacts.help/windows_etw_authentication_dst_host.html "ETW - Authentication - Destination host | artifacts.help"
[10]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/negotiate-session-setup-tree-connect-fails "Negotiate, Session Setup, and Tree Connect failures - Windows Server | Microsoft Learn"
[11]: https://github.com/jdu2600/Windows10EtwEvents "GitHub - jdu2600/Windows10EtwEvents: Events from all manifest-based and mof-based ETW providers across Windows 10 versions · GitHub"
