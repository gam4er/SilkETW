# SilkETWConfig_BlueHammer_Win11 — Provider Reference

## Purpose

Windows 11–oriented BlueHammer profile aimed at correlating object-manager handle lifecycle, kernel file I/O, and modern manifest-based file events for symlink/hardlink/FSCTL tracking. Compared to baseline `SilkETWConfig_BlueHammer`:

- Kernel collector now narrows to file/symlink-relevant event IDs (`64,69,71,75,79,80,81`).
- Adds a **manifest-based** Microsoft-Windows-Kernel-File collector with `KERNEL_FILE_KEYWORD_FILEIO` + `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH` (`0x0820`) and event-id filter `23,27,28,29` (FSCTL, RenamePath, SetLinkPath, Rename29).
- SystemProvider collector enables five system providers in one session: System Object, System Process, System Lock, System IO, System IO Filter.

Output: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Collector layout

| #   | CollectorType  | Provider / Flags                                                                                                                            |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088` (FileIO+FileIOInit+DiskFileIO+DiskIOInit+DiskIO), `EventIdFilter=64,69,71,75,79,80,81`                           |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x0820`, `EventIdFilter=23,27,28,29` |
| 3   | SystemProvider | five providers (see below), legacy `EnableFlags=0x86A10747`, `InformationClass=4`, `Verbose`, `UserKeywords=0xffffffffffffffff`             |

### SystemProvider sub-providers

| GUID                                   | Provider                  | UserKeywords                      | OpcodeFilter     |
| -------------------------------------- | ------------------------- | --------------------------------- | ---------------- |
| `febd7460-3d1d-47eb-af49-c9eeb1e146f2` | System Object Provider    | `0x1` (`SYSTEM_OBJECT_KW_HANDLE`) | `32,33,34,38,39` |
| `151f55dc-467d-471f-83b5-5f889d46ff66` | System Process Provider   | `0xffffffffffffffff`              | —                |
| `721ddfd3-dacc-4e1e-b26a-a2cb31d4705a` | System Lock Provider      | `0xffffffffffffffff`              | —                |
| `3d5c43e3-0f1c-4202-b817-174c0070dc79` | System IO Provider        | `0xffffffffffffffff`              | —                |
| `fbd09363-9e22-4661-b8bf-e7a34b535b8c` | System IO Filter Provider | `0xffffffffffffffff`              | —                |

### Kernel event IDs of interest (classic MSNT_SystemTrace)

| ID  | Event                                 |
| --- | ------------------------------------- |
| 64  | FileIo/Create                         |
| 69  | FileIo/SetInfo                        |
| 71  | FileIo/Rename                         |
| 75  | FileIo/FSControl                      |
| 79  | FileIo/DeletePath                     |
| 80  | FileIo/RenamePath                     |
| 81  | FileIo/SetLinkPath (symlink tracking) |

### Microsoft-Windows-Kernel-File keywords / IDs

- `KERNEL_FILE_KEYWORD_FILEIO` (`0x0020`) → events 23 (FSCTL), 29 (Rename29)
- `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH` (`0x0800`) → events 27 (RenamePath), 28 (SetLinkPath)
- Combined: `0x0820`.
- Events: `23` FSCTL (NTFS reparse / symlink / junction / mount-point via `FSCTL_SET_REPARSE_POINT`); `27` RenamePath (`FileRenameInformation` with full target path); `28` SetLinkPath (`FileLinkInformation` — NTFS hard-link with target path); `29` Rename29 (`FileRenameInformation` variant via `KERNEL_FILE_KEYWORD_FILEIO` path).

### Legacy `EnableFlags=0x86A10747` breakdown

`PERF_OB_HANDLE` (`0x80000040`) + `PROCESS` (`0x1`) + `THREAD` (`0x2`) + `IMAGE_LOAD` (`0x4`) + `DISK_IO` (`0x100`) + `DISK_FILE_IO` (`0x200`) + `DISK_IO_INIT` (`0x400`) + `NETWORK_TCPIP` (`0x10000`) + `SPLIT_IO` (`0x200000`) + `DRIVER` (`0x800000`) + `FILE_IO` (`0x2000000`) + `FILE_IO_INIT` (`0x4000000`).

System Lock Provider and System IO Filter Provider have no direct EVENT_TRACE_FLAG mapping — they are covered on Win11+ via the per-provider `EnableTraceEx2` path.

## Notes

- EventId values are shared across classes in MSNT_SystemTrace — correlate with EventName/OpcodeName, not EventId alone.
- `EnableStackTracing=true` (commented out) enables kernel call-stacks via `TraceSetInformation(TraceStackTracingInfo)` for Process/Start, Process/End, Thread/Start, Image/Load and FileIO/Create.
- Manifest reference: `ConfigTemplates\Microsoft-Windows-Kernel-File_manifest.xml`.
- Refs: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers · https://learn.microsoft.com/en-us/windows/win32/etw/obtrace · `TRACE_QUERY_INFO_CLASS` enum, `evntrace.h`.

## Operational notes

- Volume: high; designed for short targeted captures.
- Privilege: must run elevated; system-logger session.

---

## Russian version / Русская версия

## Назначение

Профиль BlueHammer для Windows 11, ориентированный на корреляцию handle lifecycle object-manager, kernel file I/O и современных manifest-based file-событий для отслеживания symlink/hardlink/FSCTL. По сравнению с базовым `SilkETWConfig_BlueHammer`:

- Kernel-коллектор теперь сужен до relevant event ID файлов/symlink (`64,69,71,75,79,80,81`).
- Добавлен **manifest-based** коллектор Microsoft-Windows-Kernel-File с `KERNEL_FILE_KEYWORD_FILEIO` + `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH` (`0x0820`) и event-id фильтром `23,27,28,29` (FSCTL, RenamePath, SetLinkPath, Rename29).
- SystemProvider-коллектор включает пять system-провайдеров в одной сессии: System Object, System Process, System Lock, System IO, System IO Filter.

Вывод: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Раскладка коллекторов

| #   | CollectorType  | Провайдер / Флаги                                                                                                                           |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088` (FileIO+FileIOInit+DiskFileIO+DiskIOInit+DiskIO), `EventIdFilter=64,69,71,75,79,80,81`                           |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x0820`, `EventIdFilter=23,27,28,29` |
| 3   | SystemProvider | пять провайдеров (см. ниже), legacy `EnableFlags=0x86A10747`, `InformationClass=4`, `Verbose`, `UserKeywords=0xffffffffffffffff`            |

### Под-провайдеры SystemProvider

| GUID                                   | Провайдер                 | UserKeywords                      | OpcodeFilter     |
| -------------------------------------- | ------------------------- | --------------------------------- | ---------------- |
| `febd7460-3d1d-47eb-af49-c9eeb1e146f2` | System Object Provider    | `0x1` (`SYSTEM_OBJECT_KW_HANDLE`) | `32,33,34,38,39` |
| `151f55dc-467d-471f-83b5-5f889d46ff66` | System Process Provider   | `0xffffffffffffffff`              | —                |
| `721ddfd3-dacc-4e1e-b26a-a2cb31d4705a` | System Lock Provider      | `0xffffffffffffffff`              | —                |
| `3d5c43e3-0f1c-4202-b817-174c0070dc79` | System IO Provider        | `0xffffffffffffffff`              | —                |
| `fbd09363-9e22-4661-b8bf-e7a34b535b8c` | System IO Filter Provider | `0xffffffffffffffff`              | —                |

### Kernel event IDs (classic MSNT_SystemTrace)

| ID  | Событие                                   |
| --- | ----------------------------------------- |
| 64  | FileIo/Create                             |
| 69  | FileIo/SetInfo                            |
| 71  | FileIo/Rename                             |
| 75  | FileIo/FSControl                          |
| 79  | FileIo/DeletePath                         |
| 80  | FileIo/RenamePath                         |
| 81  | FileIo/SetLinkPath (отслеживание symlink) |

### Microsoft-Windows-Kernel-File keywords / IDs

- `KERNEL_FILE_KEYWORD_FILEIO` (`0x0020`) → события 23 (FSCTL), 29 (Rename29)
- `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH` (`0x0800`) → события 27 (RenamePath), 28 (SetLinkPath)
- Комбинированно: `0x0820`.
- События: `23` FSCTL (NTFS reparse / symlink / junction / mount-point через `FSCTL_SET_REPARSE_POINT`); `27` RenamePath (`FileRenameInformation` с полным целевым путём); `28` SetLinkPath (`FileLinkInformation` — NTFS hard-link с целевым путём); `29` Rename29 (вариант `FileRenameInformation` через путь `KERNEL_FILE_KEYWORD_FILEIO`).

### Расшифровка legacy `EnableFlags=0x86A10747`

`PERF_OB_HANDLE` (`0x80000040`) + `PROCESS` (`0x1`) + `THREAD` (`0x2`) + `IMAGE_LOAD` (`0x4`) + `DISK_IO` (`0x100`) + `DISK_FILE_IO` (`0x200`) + `DISK_IO_INIT` (`0x400`) + `NETWORK_TCPIP` (`0x10000`) + `SPLIT_IO` (`0x200000`) + `DRIVER` (`0x800000`) + `FILE_IO` (`0x2000000`) + `FILE_IO_INIT` (`0x4000000`).

System Lock Provider и System IO Filter Provider не имеют прямого EVENT_TRACE_FLAG-маппинга — на Win11+ они покрываются через per-provider путь `EnableTraceEx2`.

## Заметки

- Значения EventId шарятся между классами в MSNT_SystemTrace — коррелируйте по EventName/OpcodeName, а не только по EventId.
- `EnableStackTracing=true` (закомментировано) включает kernel call-stacks через `TraceSetInformation(TraceStackTracingInfo)` для Process/Start, Process/End, Thread/Start, Image/Load и FileIO/Create.
- Manifest-reference: `ConfigTemplates\Microsoft-Windows-Kernel-File_manifest.xml`.
- Ссылки: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers · https://learn.microsoft.com/en-us/windows/win32/etw/obtrace · enum `TRACE_QUERY_INFO_CLASS`, `evntrace.h`.

## Операционные заметки

- Объём: высокий; рассчитан на короткие целевые захваты.
- Привилегии: запуск с повышенными правами; system-logger session.
