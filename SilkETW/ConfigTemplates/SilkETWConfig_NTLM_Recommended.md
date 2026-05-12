# SilkETWConfig_NTLM_Recommended — Provider Reference

## Purpose

Recommended NTLM-investigation profile. Targets the full client-side NTLM authentication surface with **balanced** levels and **event-id filters** so the capture remains useful in real environments without drowning the analyst in noise. Pairs naturally with `SilkETWConfig_NTLM_Ultimate` (its Verbose, no-filter sibling) for high-fidelity short captures.

Output: `./Logs/ntlm_client_recommended.ndjson`.

NTLMSSP message markers (Base64 prefixes seen in payload bodies and HTTP `Authorization`/`WWW-Authenticate` headers):

- `TlRMTVNTUAAB...` → NTLMSSP **Type 1 — NEGOTIATE**
- `TlRMTVNTUAAC...` → NTLMSSP **Type 2 — CHALLENGE**
- `TlRMTVNTUAAD...` → NTLMSSP **Type 3 — AUTHENTICATE**

## Provider catalog (28 providers in 9 groups)

### Group A — Core NTLM / SSPI / LSASS (7 providers)

| Provider                            | GUID                                   | Level         | Notes                                  |
| ----------------------------------- | -------------------------------------- | ------------- | -------------------------------------- |
| Microsoft-Windows-NTLM              | `AC43300D-5FCC-4800-8E99-1BD3F85F0320` | Verbose       | NTLM authentication events             |
| Microsoft-Windows-Authentication    | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | Informational | High-level auth pipeline               |
| Microsoft-Windows-Security-Auditing | `54849625-5478-4994-A5BA-3E3B0328C30D` | Informational | Security log channel                   |
| Microsoft-Windows-Security-Kerberos | `98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1` | Informational | Falls back to NTLM when Kerberos fails |
| Microsoft-Windows-LSA               | `CC85922F-DB41-11D2-9244-006008269001` | Warning       | LSASS internals                        |
| Microsoft-Windows-CAPI2             | `5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB` | Informational | CryptoAPI / chain validation           |
| Microsoft-Windows-SChannel-Events   | `8F0DB3A8-299B-4D64-A4ED-907B409D4584` | Informational | TLS/SSL via SChannel                   |

### Group B — HTTP stack (5 providers)

| Provider                          | GUID                                   | Level         | Filter                                                      |
| --------------------------------- | -------------------------------------- | ------------- | ----------------------------------------------------------- |
| Microsoft-Windows-WinINet         | `43D1A55C-76D6-4F7E-995C-64C711E5CAFE` | Informational | `EventIdFilter=200,201,203,210,211,601,602,603,604,605,606` |
| Microsoft-Windows-WinHttp         | `7D44233D-3055-4B9C-BA64-0D47CA40A232` | Informational | (no filter)                                                 |
| Microsoft-Windows-WinINet-Capture | `A70FF94F-570B-4979-BA5C-E59C9FEAB61B` | Informational | Captures request/response bodies — handle with care         |
| Microsoft-Windows-WebIO           | `50B3E73C-9370-461D-BB9F-26F32D68887D` | Warning       | Lower-level HTTP I/O                                        |
| Microsoft-Windows-HttpService     | `DD5EF90A-6398-47A4-AD34-4DCECDEF795F` | Informational | Server-side HTTP.sys                                        |

### Group C — SMB client (1 provider)

| Provider                    | GUID                                   | Level         | Filter                                                                                                                                                                                                                                        |
| --------------------------- | -------------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Microsoft-Windows-SMBClient | `988C59C5-0A1C-45B6-A555-0C62276E327D` | Informational | `EventIdFilter=30800,30801,30802,30803,30804,30805,30806,30807,30808,30809,30810,30811,30812,30813,30814,30815,31000,31001,31002,31003,31004,31005,31006,31007,31008,31009,31010,31011,31012,31013,31014,31015,31016,31017,31018,31019,31020` |

### Group D — RPC / WMI (3 providers)

| Provider                       | GUID                                   | Level         |
| ------------------------------ | -------------------------------------- | ------------- |
| Microsoft-Windows-RPC          | `6AD52B32-D609-4BE9-AE07-CE8DAE937E39` | Warning       |
| Microsoft-Windows-RPCSS        | `D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C` | Warning       |
| Microsoft-Windows-WMI-Activity | `1418EF04-B0B4-4623-BF7E-D74AB47BBDAA` | Informational |

### Group E — LDAP (1 provider)

| Provider                      | GUID                                   | Level   |
| ----------------------------- | -------------------------------------- | ------- |
| Microsoft-Windows-LDAP-Client | `099614A5-5DD7-4788-8BC9-E29F43DB28FC` | Warning |

### Group F — WinRM / PowerShell (2 providers)

| Provider                     | GUID                                   | Level         |
| ---------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-WinRM      | `A7975C8F-AC13-49F1-87DA-5A984A4AB417` | Informational |
| Microsoft-Windows-PowerShell | `A0C1853B-5C40-4B15-8766-3CF1C58F985A` | Informational |

### Group G — RDP / NLA (4 providers)

| Provider                                            | GUID                                   | Level         |
| --------------------------------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-TerminalServices-ClientUSBDevices | `28AA95BB-D444-4719-A36F-40462168127E` | Informational |
| Microsoft-Windows-TerminalServices-RDPClient        | `52739D4E-ADC9-4F52-9A45-99D6E0CE4A1F` | Informational |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV  | `1ABCAFE2-1F25-47EE-8D17-F4E08A7DC10E` | Informational |
| Microsoft-Windows-CredUI                            | `5A24FCDB-1CF3-477B-B422-EF4909D51223` | Informational |

### Group H — Print spooler (1 provider)

| Provider                       | GUID                                   | Level   |
| ------------------------------ | -------------------------------------- | ------- |
| Microsoft-Windows-PrintService | `747EF6FD-E535-4D16-B510-42C90F6873A1` | Warning |

### Group I — Network / process context (4 providers)

| Provider                         | GUID                                   | Level         |
| -------------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-TCPIP          | `2F07E2EE-15DB-40F1-90EF-9D7BA282188A` | Warning       |
| Microsoft-Windows-DNS-Client     | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | Informational |
| Microsoft-Windows-Kernel-Process | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` | Informational |
| Microsoft-Windows-Kernel-Network | `7DD42A49-5329-4832-8DFD-43D979153A88` | Informational |

## EventIdFilter rationales

- **WinINet** `200-211` — request/response lifecycle; `601-606` — auth challenge / negotiate / cred-cache events where NTLMSSP tokens surface.
- **SMBClient** `30800-30815` — connection / negotiate / session-setup; `31000-31020` — tree-connect / create / read / write — covers the entire SMB session-setup and tree-connect flows where NTLM appears.

## Notes

- `Microsoft-Windows-DNS-Client` GUID `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` collides with `Microsoft-Windows-Authentication` in Group A — they are distinct providers sharing a GUID by historical accident. Resolve by name on capture if necessary.
- For environments where you can spend the volume, switch to `SilkETWConfig_NTLM_Ultimate` (all Verbose, no filters).

## Operational notes

- Volume: medium — workable for hour-scale captures on a single endpoint.
- Privilege: SilkETW must run elevated.
- Downstream: filter on `LogonType=3` / `AuthenticationPackageName=NTLM` / NTLMSSP markers above for fast triage.

---

## Russian version / Русская версия

## Назначение

Рекомендуемый профиль для расследования NTLM. Покрывает всю клиентскую поверхность NTLM-аутентификации со **сбалансированными** уровнями и **event-id фильтрами**, чтобы захват оставался применим в реальных окружениях, не утопая аналитика в шуме. Естественно сочетается с `SilkETWConfig_NTLM_Ultimate` (его Verbose, без фильтров sibling) для коротких high-fidelity захватов.

Вывод: `./Logs/ntlm_client_recommended.ndjson`.

Маркеры NTLMSSP (Base64-префиксы, видны в payload и HTTP-заголовках `Authorization`/`WWW-Authenticate`):

- `TlRMTVNTUAAB...` → NTLMSSP **Type 1 — NEGOTIATE**
- `TlRMTVNTUAAC...` → NTLMSSP **Type 2 — CHALLENGE**
- `TlRMTVNTUAAD...` → NTLMSSP **Type 3 — AUTHENTICATE**

## Каталог провайдеров (28 провайдеров в 9 группах)

### Группа A — Core NTLM / SSPI / LSASS (7 провайдеров)

| Провайдер                           | GUID                                   | Уровень       | Заметка                                |
| ----------------------------------- | -------------------------------------- | ------------- | -------------------------------------- |
| Microsoft-Windows-NTLM              | `AC43300D-5FCC-4800-8E99-1BD3F85F0320` | Verbose       | События NTLM-аутентификации            |
| Microsoft-Windows-Authentication    | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | Informational | Высокоуровневый auth pipeline          |
| Microsoft-Windows-Security-Auditing | `54849625-5478-4994-A5BA-3E3B0328C30D` | Informational | Канал Security log                     |
| Microsoft-Windows-Security-Kerberos | `98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1` | Informational | Откатывается на NTLM при сбое Kerberos |
| Microsoft-Windows-LSA               | `CC85922F-DB41-11D2-9244-006008269001` | Warning       | Внутренности LSASS                     |
| Microsoft-Windows-CAPI2             | `5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB` | Informational | CryptoAPI / валидация цепочек          |
| Microsoft-Windows-SChannel-Events   | `8F0DB3A8-299B-4D64-A4ED-907B409D4584` | Informational | TLS/SSL через SChannel                 |

### Группа B — HTTP-стек (5 провайдеров)

| Провайдер                         | GUID                                   | Уровень       | Фильтр                                                      |
| --------------------------------- | -------------------------------------- | ------------- | ----------------------------------------------------------- |
| Microsoft-Windows-WinINet         | `43D1A55C-76D6-4F7E-995C-64C711E5CAFE` | Informational | `EventIdFilter=200,201,203,210,211,601,602,603,604,605,606` |
| Microsoft-Windows-WinHttp         | `7D44233D-3055-4B9C-BA64-0D47CA40A232` | Informational | (без фильтра)                                               |
| Microsoft-Windows-WinINet-Capture | `A70FF94F-570B-4979-BA5C-E59C9FEAB61B` | Informational | Захватывает тела запроса/ответа — осторожно                 |
| Microsoft-Windows-WebIO           | `50B3E73C-9370-461D-BB9F-26F32D68887D` | Warning       | Низкоуровневый HTTP I/O                                     |
| Microsoft-Windows-HttpService     | `DD5EF90A-6398-47A4-AD34-4DCECDEF795F` | Informational | Server-side HTTP.sys                                        |

### Группа C — SMB-клиент (1 провайдер)

| Провайдер                   | GUID                                   | Уровень       | Фильтр                                     |
| --------------------------- | -------------------------------------- | ------------- | ------------------------------------------ |
| Microsoft-Windows-SMBClient | `988C59C5-0A1C-45B6-A555-0C62276E327D` | Informational | `EventIdFilter=30800..30815, 31000..31020` |

### Группа D — RPC / WMI (3 провайдера)

| Провайдер                      | GUID                                   | Уровень       |
| ------------------------------ | -------------------------------------- | ------------- |
| Microsoft-Windows-RPC          | `6AD52B32-D609-4BE9-AE07-CE8DAE937E39` | Warning       |
| Microsoft-Windows-RPCSS        | `D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C` | Warning       |
| Microsoft-Windows-WMI-Activity | `1418EF04-B0B4-4623-BF7E-D74AB47BBDAA` | Informational |

### Группа E — LDAP (1 провайдер)

| Провайдер                     | GUID                                   | Уровень |
| ----------------------------- | -------------------------------------- | ------- |
| Microsoft-Windows-LDAP-Client | `099614A5-5DD7-4788-8BC9-E29F43DB28FC` | Warning |

### Группа F — WinRM / PowerShell (2 провайдера)

| Провайдер                    | GUID                                   | Уровень       |
| ---------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-WinRM      | `A7975C8F-AC13-49F1-87DA-5A984A4AB417` | Informational |
| Microsoft-Windows-PowerShell | `A0C1853B-5C40-4B15-8766-3CF1C58F985A` | Informational |

### Группа G — RDP / NLA (4 провайдера)

| Провайдер                                           | GUID                                   | Уровень       |
| --------------------------------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-TerminalServices-ClientUSBDevices | `28AA95BB-D444-4719-A36F-40462168127E` | Informational |
| Microsoft-Windows-TerminalServices-RDPClient        | `52739D4E-ADC9-4F52-9A45-99D6E0CE4A1F` | Informational |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV  | `1ABCAFE2-1F25-47EE-8D17-F4E08A7DC10E` | Informational |
| Microsoft-Windows-CredUI                            | `5A24FCDB-1CF3-477B-B422-EF4909D51223` | Informational |

### Группа H — Print spooler (1 провайдер)

| Провайдер                      | GUID                                   | Уровень |
| ------------------------------ | -------------------------------------- | ------- |
| Microsoft-Windows-PrintService | `747EF6FD-E535-4D16-B510-42C90F6873A1` | Warning |

### Группа I — Сеть / контекст процесса (4 провайдера)

| Провайдер                        | GUID                                   | Уровень       |
| -------------------------------- | -------------------------------------- | ------------- |
| Microsoft-Windows-TCPIP          | `2F07E2EE-15DB-40F1-90EF-9D7BA282188A` | Warning       |
| Microsoft-Windows-DNS-Client     | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | Informational |
| Microsoft-Windows-Kernel-Process | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` | Informational |
| Microsoft-Windows-Kernel-Network | `7DD42A49-5329-4832-8DFD-43D979153A88` | Informational |

## Обоснование EventIdFilter

- **WinINet** `200-211` — lifecycle запроса/ответа; `601-606` — auth challenge / negotiate / cred-cache, где видны NTLMSSP-токены.
- **SMBClient** `30800-30815` — connection / negotiate / session-setup; `31000-31020` — tree-connect / create / read / write — покрывает весь SMB session-setup и tree-connect, где появляется NTLM.

## Заметки

- `Microsoft-Windows-DNS-Client` GUID `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` коллизирует с `Microsoft-Windows-Authentication` из группы A — это разные провайдеры с одинаковым GUID по историческому совпадению. Разрешайте по имени при capture при необходимости.
- В окружениях, где можно потратить объём, переходите на `SilkETWConfig_NTLM_Ultimate` (всё Verbose, без фильтров).

## Операционные заметки

- Объём: средний — пригоден для часовых захватов на одном endpoint.
- Привилегии: SilkETW должен запускаться с повышенными правами.
- Downstream: фильтруйте по `LogonType=3` / `AuthenticationPackageName=NTLM` / NTLMSSP-маркерам выше для быстрой триажи.
