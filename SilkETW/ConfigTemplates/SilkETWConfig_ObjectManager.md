# SilkETWConfig_ObjectManager — Provider Reference

## Purpose

Captures kernel handle lifecycle (create / close / duplicate) via the **System Object Provider**, with an automatic Win11+/Win8-10 dual-path: modern `EnableTraceEx2` on Windows 11+, legacy `TraceSetInformation` with `PERF_OB_HANDLE` on Windows 8/10/Server 2012+. Combined with a kernel File I/O collector to correlate file access with handle lifecycle.

Output: `./Logs/object_manager.ndjson`.

## Collector layout

| #   | CollectorType  | Provider / Flags                                                                                                                                                                                                                                               | Notes                                       |
| --- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100664832` (FileIO + FileIOInit + DiskFileIO + DiskIOInit), `EventIdFilter=64`                                                                                                                                                                 | Optional — file create only                 |
| 2   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1` (`SYSTEM_OBJECT_KW_HANDLE`), `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040` (`PERF_OB_HANDLE`), `InformationClass=4`, `EventIdFilter=32,33,34,36,37,38,39` | Auto-fallback to legacy ObTrace below Win11 |

## ObTrace event IDs

| ID  | Meaning               |
| --- | --------------------- |
| 32  | CreateHandle          |
| 33  | CloseHandle           |
| 34  | DuplicateHandle       |
| 36  | TypeDCStart (rundown) |
| 37  | TypeDCEnd (rundown)   |
| 38  | HandleDCStart         |
| 39  | HandleDCEnd           |

Below Windows 8 the SystemProvider collector fail-closes with an explicit error.

## Notes

- **Do NOT use `<ProviderName>` for SystemProvider collectors** — that element is for User (manifest-based) providers only. System provider GUIDs go inside `<SystemProviderGuids>`.
- On Win11+ each `<Provider>` entry is passed to `EnableTraceEx2` with its own keywords.
- On Win8/10 only the combined `<EnableFlags>` bitmask is meaningful (per-provider keywords ignored).
- References:
  - https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
  - https://learn.microsoft.com/en-us/windows/win32/etw/obtrace

## Operational notes

- Volume: high on heavily-multiprocess hosts (handle churn); use `<EventIdFilter>` to keep only the IDs you need.
- Privilege: must run elevated; system-logger session.

---

## Russian version / Русская версия

## Назначение

Захват жизненного цикла kernel-handle (create/close/duplicate) через **System Object Provider**, с автоматическим выбором Win11+/Win8-10: современный `EnableTraceEx2` на Windows 11+, legacy `TraceSetInformation` с `PERF_OB_HANDLE` на Windows 8/10/Server 2012+. Сочетается с kernel-коллектором File I/O для корреляции файлового доступа с lifecycle handle.

Вывод: `./Logs/object_manager.ndjson`.

## Раскладка коллекторов

| #   | CollectorType  | Провайдер / Флаги                                                                                                                                                                                                                                              | Примечание                                 |
| --- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| 1   | Kernel         | `KernelKeywords=100664832` (FileIO + FileIOInit + DiskFileIO + DiskIOInit), `EventIdFilter=64`                                                                                                                                                                 | Опциональный — только file create          |
| 2   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1` (`SYSTEM_OBJECT_KW_HANDLE`), `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040` (`PERF_OB_HANDLE`), `InformationClass=4`, `EventIdFilter=32,33,34,36,37,38,39` | Авто-fallback на legacy ObTrace ниже Win11 |

## ObTrace event IDs

| ID  | Значение              |
| --- | --------------------- |
| 32  | CreateHandle          |
| 33  | CloseHandle           |
| 34  | DuplicateHandle       |
| 36  | TypeDCStart (rundown) |
| 37  | TypeDCEnd (rundown)   |
| 38  | HandleDCStart         |
| 39  | HandleDCEnd           |

Ниже Windows 8 SystemProvider-коллектор fail-close с явной ошибкой.

## Заметки

- **Не используйте `<ProviderName>` для SystemProvider-коллекторов** — этот элемент только для User (manifest-based) провайдеров. GUIDы system-провайдеров — внутри `<SystemProviderGuids>`.
- На Win11+ каждый `<Provider>`-элемент передаётся в `EnableTraceEx2` со своими keywords.
- На Win8/10 значим только агрегированный bitmask `<EnableFlags>` (per-provider keywords игнорируются).
- Ссылки:
  - https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
  - https://learn.microsoft.com/en-us/windows/win32/etw/obtrace

## Операционные заметки

- Объём: высокий на хостах с большим числом процессов (churn handle); используйте `<EventIdFilter>` для оставления только нужных ID.
- Привилегии: запуск с повышенными правами; system-logger session.
