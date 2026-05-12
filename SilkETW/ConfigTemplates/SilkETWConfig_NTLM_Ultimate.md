# SilkETWConfig_NTLM_Ultimate — Provider Reference

## Purpose

"Ultimate" NTLM-investigation profile: same 28-provider catalog as `SilkETWConfig_NTLM_Recommended`, but **all collectors at `Verbose`** with **all keywords** (`0xffffffffffffffff`) and **no `EventIdFilter`s**. Designed for short, high-fidelity forensic captures where event volume is acceptable in exchange for not missing a single NTLM-relevant hint.

Output: `./Logs/ntlm_client_ultimate.ndjson`.

NTLMSSP message markers (Base64 prefixes seen in payload bodies and HTTP `Authorization`/`WWW-Authenticate` headers):

- `TlRMTVNTUAAB...` → NTLMSSP **Type 1 — NEGOTIATE**
- `TlRMTVNTUAAC...` → NTLMSSP **Type 2 — CHALLENGE**
- `TlRMTVNTUAAD...` → NTLMSSP **Type 3 — AUTHENTICATE**

## Provider catalog

The same 28 providers in 9 groups as `SilkETWConfig_NTLM_Recommended`:

- **A** Core NTLM / SSPI / LSASS — Microsoft-Windows-NTLM, Authentication, Security-Auditing, Security-Kerberos, LSA, CAPI2, SChannel-Events
- **B** HTTP — WinINet, WinHttp, WinINet-Capture, WebIO, HttpService
- **C** SMB — SMBClient
- **D** RPC / WMI — RPC, RPCSS, WMI-Activity
- **E** LDAP — LDAP-Client
- **F** WinRM / PS — WinRM, PowerShell
- **G** RDP / NLA — TerminalServices-ClientUSBDevices, TerminalServices-RDPClient, RemoteDesktopServices-RdpCoreCDV, CredUI
- **H** Print — PrintService
- **I** Network / process — TCPIP, DNS-Client, Kernel-Process, Kernel-Network

For full GUIDs, group breakdown, and event-ID rationales, see [SilkETWConfig_NTLM_Recommended.md](SilkETWConfig_NTLM_Recommended.md).

## Differences vs `_Recommended`

| Aspect          | Recommended                                                                                     | Ultimate                        |
| --------------- | ----------------------------------------------------------------------------------------------- | ------------------------------- |
| Levels          | mixed Verbose / Informational / Warning                                                         | **all Verbose**                 |
| Keywords        | `0xffffffffffffffff` everywhere                                                                 | `0xffffffffffffffff` everywhere |
| `EventIdFilter` | applied to WinINet (`200,201,203,210,211,601-606`) and SMBClient (`30800-30815`, `31000-31020`) | **none**                        |
| Output file     | `ntlm_client_recommended.ndjson`                                                                | `ntlm_client_ultimate.ndjson`   |

## Operational notes

- **Volume warning:** at Verbose with no event-id filtering, providers like WinINet-Capture, WMI-Activity, PowerShell, TCPIP and HttpService are extremely chatty. Use only for short, targeted captures (minutes, not hours).
- Privilege: SilkETW must run elevated.
- Some sub-providers (e.g. PowerShell ScriptBlock logging) may pull in payloads with sensitive content — handle the resulting NDJSON as confidential.
- Downstream: filter on `LogonType=3` / `AuthenticationPackageName=NTLM` / NTLMSSP markers above for fast triage.

---

## Russian version / Русская версия

## Назначение

«Ultimate» профиль расследования NTLM: тот же каталог из 28 провайдеров, что и в `SilkETWConfig_NTLM_Recommended`, но **все коллекторы на `Verbose`** со **всеми keywords** (`0xffffffffffffffff`) и **без `EventIdFilter`**. Рассчитан на короткие high-fidelity форензик-захваты, где объём приемлем в обмен на гарантию не упустить ни одной NTLM-релевантной подсказки.

Вывод: `./Logs/ntlm_client_ultimate.ndjson`.

Маркеры NTLMSSP (Base64-префиксы, видны в payload и HTTP-заголовках `Authorization`/`WWW-Authenticate`):

- `TlRMTVNTUAAB...` → NTLMSSP **Type 1 — NEGOTIATE**
- `TlRMTVNTUAAC...` → NTLMSSP **Type 2 — CHALLENGE**
- `TlRMTVNTUAAD...` → NTLMSSP **Type 3 — AUTHENTICATE**

## Каталог провайдеров

Те же 28 провайдеров в 9 группах, что и в `SilkETWConfig_NTLM_Recommended`:

- **A** Core NTLM / SSPI / LSASS — Microsoft-Windows-NTLM, Authentication, Security-Auditing, Security-Kerberos, LSA, CAPI2, SChannel-Events
- **B** HTTP — WinINet, WinHttp, WinINet-Capture, WebIO, HttpService
- **C** SMB — SMBClient
- **D** RPC / WMI — RPC, RPCSS, WMI-Activity
- **E** LDAP — LDAP-Client
- **F** WinRM / PS — WinRM, PowerShell
- **G** RDP / NLA — TerminalServices-ClientUSBDevices, TerminalServices-RDPClient, RemoteDesktopServices-RdpCoreCDV, CredUI
- **H** Print — PrintService
- **I** Сеть / процессы — TCPIP, DNS-Client, Kernel-Process, Kernel-Network

Полные GUID, разбивку по группам и обоснование event-ID см. в [SilkETWConfig_NTLM_Recommended.md](SilkETWConfig_NTLM_Recommended.md).

## Отличия vs `_Recommended`

| Аспект          | Recommended                                                                                   | Ultimate                      |
| --------------- | --------------------------------------------------------------------------------------------- | ----------------------------- |
| Уровни          | смешанные Verbose / Informational / Warning                                                   | **все Verbose**               |
| Keywords        | `0xffffffffffffffff` везде                                                                    | `0xffffffffffffffff` везде    |
| `EventIdFilter` | применён к WinINet (`200,201,203,210,211,601-606`) и SMBClient (`30800-30815`, `31000-31020`) | **отсутствует**               |
| Файл вывода     | `ntlm_client_recommended.ndjson`                                                              | `ntlm_client_ultimate.ndjson` |

## Операционные заметки

- **Предупреждение об объёме:** на Verbose без event-id фильтрации провайдеры вроде WinINet-Capture, WMI-Activity, PowerShell, TCPIP и HttpService крайне шумные. Применяйте только для коротких целевых захватов (минуты, не часы).
- Привилегии: SilkETW должен запускаться с повышенными правами.
- Некоторые под-провайдеры (например, PowerShell ScriptBlock logging) могут содержать чувствительные payload — обращайтесь с полученным NDJSON как с конфиденциальным.
- Downstream: фильтруйте по `LogonType=3` / `AuthenticationPackageName=NTLM` / NTLMSSP-маркерам выше для быстрой триажи.
