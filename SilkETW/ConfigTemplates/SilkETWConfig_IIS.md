# SilkETWConfig_IIS — Provider Reference

## Purpose

Enables every major IIS ETW provider so a single capture covers the full request pipeline (W3SVC worker process, WWW Server / WWW Global, ISAPI, ASP), the management surface (APPHOSTSVC, Configuration, IISReset, MetabaseAudit, WMSVC), the perf counter feed, and FTP / Logging channels. Use for IIS misbehaviour debugging, web-shell hunting, attack-surface mapping on web hosts.

Output: `.\Logs\iis_etw_events.ndjson`. All collectors at `Verbose` with all keywords.

## Provider catalog

| #   | Provider                                 | GUID / Name                            |
| --- | ---------------------------------------- | -------------------------------------- |
| 1   | IIS: Active Server Pages (ASP)           | `06B94D9A-B15E-456E-A4EF-37C984A2CB4B` |
| 2   | IIS: WWW Global                          | `D55D3BC9-CBA9-44DF-827E-132D3A4596C2` |
| 3   | IIS: WWW Isapi Extension                 | `A1C2040E-8840-4C31-BA11-9871031A19EA` |
| 4   | IIS: WWW Server                          | `3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83` |
| 5   | Microsoft-Windows-IIS                    | (by name)                              |
| 6   | Microsoft-Windows-IIS-APPHOSTSVC         | (by name)                              |
| 7   | Microsoft-Windows-IIS-Configuration      | (by name)                              |
| 8   | Microsoft-Windows-IIS-FTP                | (by name)                              |
| 9   | Microsoft-Windows-IIS-IisMetabaseAudit   | (by name)                              |
| 10  | Microsoft-Windows-IIS-IISReset           | (by name)                              |
| 11  | Microsoft-Windows-IIS-Logging            | (by name)                              |
| 12  | Microsoft-Windows-IIS-W3SVC              | (by name)                              |
| 13  | Microsoft-Windows-IIS-W3SVC-PerfCounters | (by name)                              |
| 14  | Microsoft-Windows-IIS-W3SVC-WP           | (by name)                              |
| 15  | Microsoft-Windows-IIS-WMSVC              | (by name)                              |

## Notes

- The four legacy IIS providers (ASP, WWW Global/Isapi/Server) are GUID-only and are required for full request-pipeline observability. Their corresponding manifest dump (where available) is in `Microsoft-Windows-IIS-Configuration_manifest.xml`.
- `IIS-Configuration` events fire on `applicationHost.config` reads/writes — high signal for unauthorised config tampering.
- `IIS-IisMetabaseAudit` is the legacy metabase audit channel; on modern IIS it surfaces auth-relevant config-store activity.
- `W3SVC-PerfCounters` is metric-style; consider trimming in production.

## Operational notes

- Volume: high on busy web servers — narrow keywords or filter `IIS: WWW Server` event IDs (`Page Lifetime` / `URL Match` / `BeginRequest` etc.) for production captures.
- Privilege: SilkETW must run elevated.

---

## Russian version / Русская версия

## Назначение

Включает все основные IIS ETW-провайдеры, чтобы один захват покрыл полный конвейер запросов (W3SVC worker process, WWW Server / WWW Global, ISAPI, ASP), management-поверхность (APPHOSTSVC, Configuration, IISReset, MetabaseAudit, WMSVC), фид perf-счётчиков и каналы FTP / Logging. Применение: отладка IIS, охота на web-shell, картирование attack-surface веб-хостов.

Вывод: `.\Logs\iis_etw_events.ndjson`. Все коллекторы на `Verbose` со всеми keywords.

## Каталог провайдеров

| #   | Провайдер                                | GUID / Имя                             |
| --- | ---------------------------------------- | -------------------------------------- |
| 1   | IIS: Active Server Pages (ASP)           | `06B94D9A-B15E-456E-A4EF-37C984A2CB4B` |
| 2   | IIS: WWW Global                          | `D55D3BC9-CBA9-44DF-827E-132D3A4596C2` |
| 3   | IIS: WWW Isapi Extension                 | `A1C2040E-8840-4C31-BA11-9871031A19EA` |
| 4   | IIS: WWW Server                          | `3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83` |
| 5   | Microsoft-Windows-IIS                    | (по имени)                             |
| 6   | Microsoft-Windows-IIS-APPHOSTSVC         | (по имени)                             |
| 7   | Microsoft-Windows-IIS-Configuration      | (по имени)                             |
| 8   | Microsoft-Windows-IIS-FTP                | (по имени)                             |
| 9   | Microsoft-Windows-IIS-IisMetabaseAudit   | (по имени)                             |
| 10  | Microsoft-Windows-IIS-IISReset           | (по имени)                             |
| 11  | Microsoft-Windows-IIS-Logging            | (по имени)                             |
| 12  | Microsoft-Windows-IIS-W3SVC              | (по имени)                             |
| 13  | Microsoft-Windows-IIS-W3SVC-PerfCounters | (по имени)                             |
| 14  | Microsoft-Windows-IIS-W3SVC-WP           | (по имени)                             |
| 15  | Microsoft-Windows-IIS-WMSVC              | (по имени)                             |

## Заметки

- Четыре legacy IIS-провайдера (ASP, WWW Global/Isapi/Server) идентифицируются только GUID и нужны для полной видимости конвейера запросов. Соответствующий manifest dump (где доступен) — в `Microsoft-Windows-IIS-Configuration_manifest.xml`.
- События `IIS-Configuration` срабатывают при чтении/записи `applicationHost.config` — высокий сигнал на несанкционированное вмешательство в конфигурацию.
- `IIS-IisMetabaseAudit` — legacy-канал аудита метабазы; на современном IIS отражает auth-релевантную активность config-store.
- `W3SVC-PerfCounters` — метрический; в проде имеет смысл сужать.

## Операционные заметки

- Объём: высокий на нагруженных веб-серверах — сужайте keywords или фильтруйте event IDs `IIS: WWW Server` (`Page Lifetime` / `URL Match` / `BeginRequest` и т.п.) для прод-захватов.
- Привилегии: SilkETW должен запускаться с повышенными правами.
