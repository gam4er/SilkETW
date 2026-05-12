# SilkETWConfig_Network_Telemetry — Provider Reference

## Purpose

This template enables a broad, investigation-oriented capture of network-related ETW providers on Windows 10/11. It is intended for incident response, threat hunting, and offline forensics where the analyst wants the full picture of name resolution, transport (TCP/UDP/QUIC/HTTP/3), HTTP client stacks, TLS/crypto operations, wireless and VPN state, NDIS-level traffic events, file-sharing exposure, and managed runtime network activity in a single NDJSON stream.

All collectors are configured at `Verbose` level with all keywords (`0xffffffffffffffff`) and **no `EventIdFilter`** so that nothing is dropped at the source. This is deliberately maximal — see _Operational notes_ below for production trimming guidance.

## Provider catalog

| #   | Group | Provider                                       | GUID                                   | Status               |
| --- | ----- | ---------------------------------------------- | -------------------------------------- | -------------------- |
| 1   | A     | Microsoft-Windows-Network-ExecutionContext     | `0075E1AB-E1D1-5D1F-35F5-DA36FB4F41B1` | **NEW (2026-05-12)** |
| 2   | A     | Microsoft-Windows-Privacy-Auditing-CPSS        | `15F4CD44-CA53-5422-DB17-4E76821B5A69` | **NEW (2026-05-12)** |
| 3   | B     | Microsoft-Windows-DNS-Client                   | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | **NEW (2026-05-12)** |
| 4   | B     | Microsoft-Windows-Winsock-NameResolution       | `55404E71-4DB9-4DEB-A5F5-8F86E46DDE56` | **NEW (2026-05-12)** |
| 5   | C     | Microsoft-Quic                                 | `FF15E657-4F26-570E-88AB-0796B258D11C` | **NEW (2026-05-12)** |
| 6   | C     | Microsoft-Windows-Winsock-Sockets              | `BDE46AEA-2357-51FE-7367-D5296F530BD1` | **NEW (2026-05-12)** |
| 7   | C     | Microsoft-Windows-Websocket-Protocol-Component | `CBA5F63C-E2CF-4B36-8305-BDE1311924FC` | **NEW (2026-05-12)** |
| 8   | D     | Microsoft-Windows-WinHttp-Pca                  | `D071CE03-0D7B-5B27-E817-B9C12961934E` | **NEW (2026-05-12)** |
| 9   | D     | Microsoft-Windows-WinINet-Pca                  | `4860EA43-3F05-5FB8-20CE-7BA346A44747` | **NEW (2026-05-12)** |
| 10  | E     | Microsoft-Windows-CAPI2                        | `5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB` | **NEW (2026-05-12)** |
| 11  | E     | Microsoft-Windows-Crypto-CNG                   | `E3E0E2F0-C9C5-11E0-8AB9-9EBC4824019B` | **NEW (2026-05-12)** |
| 12  | E     | Microsoft-Windows-Crypto-NCrypt                | `E8ED09DC-100C-45E2-9FC8-B53399EC1F70` | **NEW (2026-05-12)** |
| 13  | F     | Microsoft-Windows-WLAN-AutoConfig              | `9580D7DD-0379-4658-9870-D5BE7D52D6DE` | **NEW (2026-05-12)** |
| 14  | F     | Microsoft-Windows-WLAN-Driver                  | `DAA6A96B-F3E7-4D4D-A0D6-31A350E6A445` | **NEW (2026-05-12)** |
| 15  | F     | Microsoft-Windows-VPN-Client                   | `3C088E51-65BE-40D1-9B90-62BFEC076737` | **NEW (2026-05-12)** |
| 16  | G     | Microsoft-Windows-NDIS                         | `CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9` | **NEW (2026-05-12)** |
| 17  | G     | Microsoft-Windows-Network-Setup                | `A111F1C2-5923-47C0-9A68-D0BAFB577901` | **NEW (2026-05-12)** |
| 18  | G     | Microsoft-Windows-SMBServer                    | `D48CE617-33A2-4BC3-A5C7-11AA4F29619E` | **NEW (2026-05-12)** |
| 19  | H     | Microsoft-Windows-DotNETRuntime                | `E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4` | **NEW (2026-05-12)** |

`NEW` = provider not previously referenced by any `SilkETWConfig_*.xml` template in this repository.

## Group A — User context & privacy

### 1. Microsoft-Windows-Network-ExecutionContext

Emits the user/app execution context attached to outbound network calls (token, package family name, AppContainer SID, capability set). Critical for attributing network activity to a specific UWP package, AppContainer-confined process, or impersonated identity.

- Typical value: distinguishing per-app traffic on multi-user / kiosk / EDR-instrumented hosts.
- Noise: low — only fires on context establishment.

### 2. Microsoft-Windows-Privacy-Auditing-CPSS

**CPSS = Capability Privacy-Sensitive State.** Records which apps requested or were granted access to capability-protected resources (microphone, camera, location, contacts, broad filesystem access, clipboard history, etc.). Not strictly network, but extremely relevant for exfil-style investigations and consent-bypass detection.

- Typical events: capability check granted/denied, package + capability + invoking process.
- Noise: low–medium depending on user activity.

## Group B — Name resolution

### 3. Microsoft-Windows-DNS-Client

The standard manifested DNS client provider. Substituted in for `Microsoft-Windows-DNS-Client-DiagTrack` (which is absent on this Win11 build). Captures `DnsQuery*` requests, results, cache hits/misses, and protocol selection (Do53 / DoH / DoT where applicable).

- Typical events: 3006 (query sent), 3008/3010 (response), 3018 (cache update), 3020 (DoH negotiation), 1014/1015 (NRPT policy match).
- Noise: medium–high on busy hosts.

### 4. Microsoft-Windows-Winsock-NameResolution

Lower-level resolver pipeline (`getaddrinfo` / `GetAddrInfoEx` / NSPI providers). Sees calls that bypass the DNS Client cache or use alternate name providers (mDNS, hosts file, NRPT, NSPv2 plug-ins).

- Use to detect resolver-bypass behavior or unusual NSP activity.

## Group C — Transport

### 5. Microsoft-Quic

The msquic.dll provider. Captures QUIC connection lifecycle, stream open/close, packet number ranges, ACK and loss events, TLS handshake within QUIC, and connection IDs. This is the primary signal for HTTP/3 traffic since HTTP/3 events surface here (the WinHTTP / WinINet stacks are increasingly thin wrappers over QUIC for HTTP/3).

- Typical hunts: detection of HTTP/3 C2, identifying server SNI/ALPN selection, QUIC version negotiation anomalies.

### 6. Microsoft-Windows-Winsock-Sockets

User-mode Winsock 2 (`Ws2_32.dll`) socket API instrumentation: `socket`, `connect`, `send/recv`, `WSA*` calls, address family and protocol choice, error codes.

- Pair with Group A to attribute sockets to package/AppContainer.

### 7. Microsoft-Windows-Websocket-Protocol-Component

WinHTTP WebSocket layer (`websocket.dll`). Logs WebSocket handshake upgrade, frame send/receive metadata, close codes. Useful against WebSocket-based C2 channels and browser-extension traffic.

## Group D — HTTP / WinINet / PCA shims

### 8. Microsoft-Windows-WinHttp-Pca

**PCA = Program Compatibility Assistant.** Fires only when the WinHTTP shim layer is engaged for a legacy app under PCA. Use this to spot legacy callers using WinHTTP via compat shims (often older line-of-business or installer code).

- Note: this is **not** the full WinHTTP trace provider — the broader `Microsoft-Windows-WinHttp` provider exists separately and is intentionally not enabled here to keep the template focused on PCA-flagged use.

### 9. Microsoft-Windows-WinINet-Pca

Same idea as `WinHttp-Pca` but for WinINet (`wininet.dll`). Surfaces apps using the legacy WinINet API under PCA shims — common with classic IE-era components, Office add-ins, and older Windows components.

## Group E — Crypto / TLS

### 10. Microsoft-Windows-CAPI2

The classic CryptoAPI 2 provider. Captures certificate chain building, revocation checking (CRL/OCSP fetch), trust list (CTL) updates, and AuthRoot updates. Indispensable for TLS trust diagnostics, code-signing validation, and detecting unusual root insertions.

- High signal-to-noise for security investigations.

### 11. Microsoft-Windows-Crypto-CNG

**CNG = Cryptography API: Next Generation.** Algorithm provider events (BCrypt/NCrypt operations), key handle lifecycle, hash/encrypt/sign call traces. Used by SChannel (TLS 1.2/1.3), SMB encryption, EFS, BitLocker.

### 12. Microsoft-Windows-Crypto-NCrypt

Key-storage provider events (KSP). Tracks key creation/open/delete on TPM, Smart Card, software KSP. Critical for detecting unauthorized key material access, certificate enrollment, or DPAPI-NG use.

## Group F — Wireless / VPN

### 13. Microsoft-Windows-WLAN-AutoConfig

Wlansvc events: SSID scan results, connection state machine, profile selection, association/auth/4-way-handshake outcomes, roaming decisions.

### 14. Microsoft-Windows-WLAN-Driver

NDIS-WLAN driver layer. Lower-level radio/driver events that complement WLAN-AutoConfig (e.g., to diagnose disconnects when AutoConfig itself reports success).

### 15. Microsoft-Windows-VPN-Client

RAS/VPN client (rasman, rasapi32, EAP). Captures tunnel up/down, protocol negotiation (IKEv2/SSTP/L2TP/Always-On), authentication phase outcomes, and policy application.

## Group G — Lower stack & infra

### 16. Microsoft-Windows-NDIS

NDIS miniport / protocol driver events: per-packet metadata, OID requests, link state changes, filter driver attach/detach (LWF). Use sparingly — can be high volume on busy NICs but invaluable for low-level packet path issues and rogue LWF detection.

### 17. Microsoft-Windows-Network-Setup

Adapter add/remove, IP configuration changes, bind order changes, route table mutation. Useful to detect rogue adapter installation, malicious route injection, or unauthorized DHCP changes.

### 18. Microsoft-Windows-SMBServer

SMB server (`srv2.sys`) events: session setup, tree connect, file open, oplock, encryption negotiation. **On a typical Win11 client this provider is silent unless SMB server is running** (e.g., file/printer sharing enabled). Kept in the template so the same XML works equally well on workstation and server SKUs.

## Group H — Application runtime

### 19. Microsoft-Windows-DotNETRuntime

CLR ETW provider. Captures GC, JIT, loader, exception, security, and (with the right keywords) network-stack hits from managed apps. **At Verbose + all keywords this is extremely noisy** — easily hundreds of events/second per managed process. Kept maximal here per template intent; in production prefer narrow keywords (e.g., `0x4C14FCCBD` for GC + Loader + Exception + Security + Stack).

## Comparative notes

- **WinHttp vs WinHttp-Pca / WinINet vs WinINet-Pca.** The unsuffixed providers (`Microsoft-Windows-WinHttp` and `Microsoft-Windows-WinINet`) are the full instrumentation manifests for the respective client stacks and emit on every API call. The `-Pca` variants only fire when the Program Compatibility Assistant shim layer is active for a legacy app. This template enables only the `-Pca` variants because they are higher-signal and lower-noise; if you need full HTTP visibility, add the unsuffixed providers explicitly.
- **Winsock-Sockets vs Winsock-NameResolution vs Winsock-AFD.** Three different layers of the same stack. `Winsock-Sockets` is the user-mode `Ws2_32.dll` API surface (this template). `Winsock-NameResolution` is the resolver pipeline (also in this template). `Winsock-AFD` is the kernel-mode Ancillary Function Driver — not included here because at Verbose its volume is impractical for general capture; enable on demand for deep socket-state debugging.
- **Microsoft-Quic ↔ HTTP/3.** When a client negotiates HTTP/3 with a server, the wire-level events live under `Microsoft-Quic`, not under WinHTTP/WinINet. Always include `Microsoft-Quic` for any modern HTTP investigation.
- **Privacy-Auditing-CPSS scope.** CPSS is broader than network — it is the unified capability/permission audit channel. It is included here because exfiltration investigations frequently need correlation between capability requests (camera/mic/location) and outbound network activity around the same timestamps.

## Operational notes

- **Volume.** With all 19 providers at Verbose + `0xffffffffffffffff`, expect single-digit GB/hour on a moderately busy desktop. For long captures, narrow keywords or add `<EventIdFilter>` blocks per collector.
- **Privilege.** SilkETW must run elevated (Administrator) — required to enable user-mode ETW providers and to write to the configured output path.
- **Output.** `./Logs/network_telemetry.ndjson` (relative to `SilkETW.exe` working directory). Pair with `Import-NdjsonToElastic.ps1` from the repo root for downstream Elastic ingestion.
- **DotNETRuntime** in particular: consider narrowing keywords or filtering by process name in your downstream pipeline rather than at SilkETW level.
- **SMBServer**: silent on most clients — that is expected, not a bug.

---

## Russian version / Русская версия

## Назначение

Шаблон обеспечивает широкий, ориентированный на расследование сбор сетевых ETW-провайдеров на Windows 10/11. Он предназначен для реагирования на инциденты, threat hunting и офлайн-форензики, когда аналитику нужна полная картина: разрешение имён, транспорт (TCP/UDP/QUIC/HTTP/3), HTTP-клиентские стеки, TLS/крипто-операции, состояние беспроводных и VPN-соединений, события NDIS-уровня, экспозиция файлового шаринга и сетевая активность управляемого рантайма — всё в едином потоке NDJSON.

Все коллекторы настроены на `Verbose` со всеми ключами (`0xffffffffffffffff`) и **без `EventIdFilter`**, чтобы ничего не отбрасывалось у источника. Это намеренно максимальная конфигурация — рекомендации по сужению для прода см. в разделе _Операционные заметки_ ниже.

## Каталог провайдеров

| #   | Группа | Провайдер                                      | GUID                                   | Статус               |
| --- | ------ | ---------------------------------------------- | -------------------------------------- | -------------------- |
| 1   | A      | Microsoft-Windows-Network-ExecutionContext     | `0075E1AB-E1D1-5D1F-35F5-DA36FB4F41B1` | **NEW (2026-05-12)** |
| 2   | A      | Microsoft-Windows-Privacy-Auditing-CPSS        | `15F4CD44-CA53-5422-DB17-4E76821B5A69` | **NEW (2026-05-12)** |
| 3   | B      | Microsoft-Windows-DNS-Client                   | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | **NEW (2026-05-12)** |
| 4   | B      | Microsoft-Windows-Winsock-NameResolution       | `55404E71-4DB9-4DEB-A5F5-8F86E46DDE56` | **NEW (2026-05-12)** |
| 5   | C      | Microsoft-Quic                                 | `FF15E657-4F26-570E-88AB-0796B258D11C` | **NEW (2026-05-12)** |
| 6   | C      | Microsoft-Windows-Winsock-Sockets              | `BDE46AEA-2357-51FE-7367-D5296F530BD1` | **NEW (2026-05-12)** |
| 7   | C      | Microsoft-Windows-Websocket-Protocol-Component | `CBA5F63C-E2CF-4B36-8305-BDE1311924FC` | **NEW (2026-05-12)** |
| 8   | D      | Microsoft-Windows-WinHttp-Pca                  | `D071CE03-0D7B-5B27-E817-B9C12961934E` | **NEW (2026-05-12)** |
| 9   | D      | Microsoft-Windows-WinINet-Pca                  | `4860EA43-3F05-5FB8-20CE-7BA346A44747` | **NEW (2026-05-12)** |
| 10  | E      | Microsoft-Windows-CAPI2                        | `5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB` | **NEW (2026-05-12)** |
| 11  | E      | Microsoft-Windows-Crypto-CNG                   | `E3E0E2F0-C9C5-11E0-8AB9-9EBC4824019B` | **NEW (2026-05-12)** |
| 12  | E      | Microsoft-Windows-Crypto-NCrypt                | `E8ED09DC-100C-45E2-9FC8-B53399EC1F70` | **NEW (2026-05-12)** |
| 13  | F      | Microsoft-Windows-WLAN-AutoConfig              | `9580D7DD-0379-4658-9870-D5BE7D52D6DE` | **NEW (2026-05-12)** |
| 14  | F      | Microsoft-Windows-WLAN-Driver                  | `DAA6A96B-F3E7-4D4D-A0D6-31A350E6A445` | **NEW (2026-05-12)** |
| 15  | F      | Microsoft-Windows-VPN-Client                   | `3C088E51-65BE-40D1-9B90-62BFEC076737` | **NEW (2026-05-12)** |
| 16  | G      | Microsoft-Windows-NDIS                         | `CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9` | **NEW (2026-05-12)** |
| 17  | G      | Microsoft-Windows-Network-Setup                | `A111F1C2-5923-47C0-9A68-D0BAFB577901` | **NEW (2026-05-12)** |
| 18  | G      | Microsoft-Windows-SMBServer                    | `D48CE617-33A2-4BC3-A5C7-11AA4F29619E` | **NEW (2026-05-12)** |
| 19  | H      | Microsoft-Windows-DotNETRuntime                | `E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4` | **NEW (2026-05-12)** |

`NEW` означает, что провайдер ранее не использовался ни в одном `SilkETWConfig_*.xml`-шаблоне этого репозитория.

## Группа A — Контекст пользователя и приватность

### 1. Microsoft-Windows-Network-ExecutionContext

Эмитит контекст выполнения пользователя/приложения, привязанный к исходящим сетевым вызовам (токен, package family name, AppContainer SID, набор capabilities). Критично для атрибуции сетевой активности конкретному UWP-пакету, изолированному в AppContainer процессу или олицетворённой identity.

- Типичный сценарий: разделение трафика по приложениям на многопользовательских / kiosk / EDR-хостах.
- Шум: низкий — срабатывает только при установлении контекста.

### 2. Microsoft-Windows-Privacy-Auditing-CPSS

**CPSS = Capability Privacy-Sensitive State.** Логирует, какие приложения запрашивали или получали доступ к capability-защищённым ресурсам (микрофон, камера, геолокация, контакты, широкий доступ к ФС, история буфера обмена и т.д.). Не строго сетевой провайдер, но крайне релевантен для расследований эксфильтрации и обхода consent-промптов.

- Типичные события: проверка capability granted/denied + пакет + capability + вызывающий процесс.
- Шум: низкий–средний в зависимости от активности пользователя.

## Группа B — Разрешение имён

### 3. Microsoft-Windows-DNS-Client

Стандартный manifested-провайдер DNS-клиента. Подставлен вместо `Microsoft-Windows-DNS-Client-DiagTrack` (отсутствует на этой сборке Win11). Захватывает запросы `DnsQuery*`, ответы, попадания/промахи кэша, выбор протокола (Do53 / DoH / DoT, где применимо).

- Типичные события: 3006 (запрос отправлен), 3008/3010 (ответ), 3018 (обновление кэша), 3020 (согласование DoH), 1014/1015 (срабатывание NRPT).
- Шум: средний–высокий на нагруженных хостах.

### 4. Microsoft-Windows-Winsock-NameResolution

Низкоуровневый конвейер резолвера (`getaddrinfo` / `GetAddrInfoEx` / NSPI-провайдеры). Видит вызовы, обходящие кэш DNS-клиента или использующие альтернативные провайдеры имён (mDNS, hosts-файл, NRPT, NSPv2 plug-ins).

- Используется для обнаружения обхода резолвера или нестандартной NSP-активности.

## Группа C — Транспорт

### 5. Microsoft-Quic

Провайдер msquic.dll. Захватывает жизненный цикл QUIC-соединений, открытие/закрытие потоков, диапазоны packet numbers, события ACK и потерь, TLS-handshake внутри QUIC, connection IDs. Это основной сигнал для HTTP/3-трафика, поскольку события HTTP/3 появляются именно здесь (стеки WinHTTP/WinINet всё чаще являются тонкими обёртками над QUIC для HTTP/3).

- Типичные хантинги: обнаружение C2 поверх HTTP/3, идентификация выбранных сервером SNI/ALPN, аномалии согласования версии QUIC.

### 6. Microsoft-Windows-Winsock-Sockets

Инструментация user-mode Winsock 2 (`Ws2_32.dll`): `socket`, `connect`, `send/recv`, вызовы `WSA*`, выбор address family и протокола, коды ошибок.

- Совмещайте с группой A для атрибуции сокетов пакету/AppContainer.

### 7. Microsoft-Windows-Websocket-Protocol-Component

WebSocket-слой WinHTTP (`websocket.dll`). Логирует upgrade-handshake WebSocket, метаданные отправки/приёма фреймов, close-коды. Полезно против WebSocket-C2 каналов и трафика браузерных расширений.

## Группа D — HTTP / WinINet / PCA-шим

### 8. Microsoft-Windows-WinHttp-Pca

**PCA = Program Compatibility Assistant.** Срабатывает только когда задействован shim-слой WinHTTP для legacy-приложения под PCA. Используется для выявления legacy-вызывающих, использующих WinHTTP через compat-шимы (часто старый LOB-код или инсталляторы).

- Замечание: это **не** полный трейс-провайдер WinHTTP — более широкий `Microsoft-Windows-WinHttp` существует отдельно и намеренно не включён в этот шаблон, чтобы оставить фокус на PCA-флагнутых вызовах.

### 9. Microsoft-Windows-WinINet-Pca

Та же идея, что у `WinHttp-Pca`, но для WinINet (`wininet.dll`). Показывает приложения, использующие legacy WinINet API через PCA-шимы — типично для классических IE-эра компонентов, Office add-ins и старых компонентов Windows.

## Группа E — Crypto / TLS

### 10. Microsoft-Windows-CAPI2

Классический провайдер CryptoAPI 2. Захватывает построение цепочки сертификатов, проверку отзыва (CRL/OCSP fetch), обновления trust list (CTL), обновления AuthRoot. Незаменим для диагностики TLS-доверия, валидации подписи кода и обнаружения нестандартных корней.

- Высокое отношение сигнал/шум для security-расследований.

### 11. Microsoft-Windows-Crypto-CNG

**CNG = Cryptography API: Next Generation.** События алгоритмических провайдеров (операции BCrypt/NCrypt), жизненный цикл key handle, трейсы вызовов hash/encrypt/sign. Используется SChannel (TLS 1.2/1.3), SMB encryption, EFS, BitLocker.

### 12. Microsoft-Windows-Crypto-NCrypt

События key-storage providers (KSP). Отслеживает создание/открытие/удаление ключей в TPM, Smart Card, программном KSP. Критично для обнаружения несанкционированного доступа к ключевому материалу, enrollment сертификатов, использования DPAPI-NG.

## Группа F — Wireless / VPN

### 13. Microsoft-Windows-WLAN-AutoConfig

События Wlansvc: результаты сканирования SSID, машина состояний подключения, выбор профиля, итоги association/auth/4-way handshake, решения о роуминге.

### 14. Microsoft-Windows-WLAN-Driver

Уровень NDIS-WLAN драйвера. Низкоуровневые радио/драйвер события, дополняющие WLAN-AutoConfig (например, для диагностики разрывов, когда сам AutoConfig сообщает об успехе).

### 15. Microsoft-Windows-VPN-Client

RAS/VPN-клиент (rasman, rasapi32, EAP). Захватывает поднятие/опускание туннеля, согласование протокола (IKEv2/SSTP/L2TP/Always-On), исходы фазы аутентификации, применение политик.

## Группа G — Нижний стек и инфраструктура

### 16. Microsoft-Windows-NDIS

События NDIS miniport / protocol driver: метаданные пакетов, OID-запросы, изменения link state, attach/detach фильтр-драйверов (LWF). Использовать осторожно — большой объём на нагруженных NIC, но незаменим для low-level проблем и обнаружения rogue LWF.

### 17. Microsoft-Windows-Network-Setup

Добавление/удаление адаптеров, изменения IP-конфигурации, изменения порядка bind, мутации таблицы маршрутизации. Полезно для обнаружения установки rogue-адаптера, malicious route injection или несанкционированных DHCP-изменений.

### 18. Microsoft-Windows-SMBServer

События SMB-сервера (`srv2.sys`): session setup, tree connect, file open, oplock, согласование шифрования. **На типичном Win11-клиенте провайдер молчит, если SMB-сервер не запущен** (например, выключен общий доступ к файлам/принтерам). Оставлен в шаблоне, чтобы тот же XML одинаково работал на workstation и server SKUs.

## Группа H — Рантайм приложений

### 19. Microsoft-Windows-DotNETRuntime

ETW-провайдер CLR. Захватывает GC, JIT, loader, exceptions, security и (с правильными keywords) обращения к сетевому стеку из управляемых приложений. **На Verbose + всех keywords чрезвычайно шумный** — легко сотни событий/сек на managed-процесс. Оставлен максимальным согласно намерению шаблона; в проде предпочитайте узкие keywords (например, `0x4C14FCCBD` для GC + Loader + Exception + Security + Stack).

## Сравнительные заметки

- **WinHttp vs WinHttp-Pca / WinINet vs WinINet-Pca.** Провайдеры без суффикса (`Microsoft-Windows-WinHttp` и `Microsoft-Windows-WinINet`) — это полные инструментационные манифесты соответствующих клиентских стеков и эмитят на каждый API-вызов. Варианты `-Pca` срабатывают только когда активен shim-слой Program Compatibility Assistant для legacy-приложения. Шаблон включает только `-Pca`-варианты — у них выше сигнал и ниже шум; для полной видимости HTTP добавляйте провайдеры без суффикса явно.
- **Winsock-Sockets vs Winsock-NameResolution vs Winsock-AFD.** Три разных слоя одного стека. `Winsock-Sockets` — user-mode API `Ws2_32.dll` (есть в шаблоне). `Winsock-NameResolution` — конвейер резолвера (тоже в шаблоне). `Winsock-AFD` — kernel-mode Ancillary Function Driver — не включён, потому что на Verbose его объём непрактичен для общего захвата; включайте по требованию для глубокой отладки состояния сокетов.
- **Microsoft-Quic ↔ HTTP/3.** Когда клиент договаривается с сервером об HTTP/3, события wire-уровня живут под `Microsoft-Quic`, а не под WinHTTP/WinINet. Всегда включайте `Microsoft-Quic` для любого расследования современного HTTP.
- **Область Privacy-Auditing-CPSS.** CPSS шире, чем сеть — это унифицированный канал аудита capability/permissions. Включён сюда, потому что расследования эксфильтрации часто требуют корреляции запросов capability (камера/микрофон/геолокация) с исходящей сетевой активностью в близкие моменты времени.

## Операционные заметки

- **Объём.** При всех 19 провайдерах на Verbose + `0xffffffffffffffff` ожидайте единицы ГБ/час на средне нагруженном десктопе. Для долгих захватов сужайте keywords или добавляйте `<EventIdFilter>` поколлекторно.
- **Привилегии.** SilkETW должен запускаться с повышенными правами (Administrator) — требуется для включения user-mode ETW-провайдеров и записи в указанный output path.
- **Output.** `./Logs/network_telemetry.ndjson` (относительно рабочего каталога `SilkETW.exe`). Используйте парный `Import-NdjsonToElastic.ps1` из корня репозитория для последующего ingest в Elastic.
- **DotNETRuntime** особенно: рассмотрите сужение keywords или фильтрацию по имени процесса в downstream-конвейере, а не на уровне SilkETW.
- **SMBServer**: молчание на большинстве клиентов — это ожидаемо, не баг.
