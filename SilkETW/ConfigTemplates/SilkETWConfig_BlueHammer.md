# SilkETWConfig_BlueHammer — Provider Reference

## Purpose

BlueHammer baseline profile for legacy / cross-version support. Pairs a kernel File I/O collector (broad bitmask, no event-id filter) with the System Object Provider (handle lifecycle, dual-path Win11+/Win8-10) and the VolSnap (VolumeSnapshot-Driver) user-mode provider. This is the original / baseline BlueHammer profile; the `Win11`, `Win11_noflt`, and `Win11_norm` variants are progressive refinements.

Output: `./Logs/object_BlueHammer.ndjson`.

## Collector layout

| #   | CollectorType  | Provider / Flags                                                                                                                                                                                                         |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Kernel         | `KernelKeywords=100665088` (FileIO + FileIOInit + DiskFileIO + DiskIOInit + DiskIO)                                                                                                                                      |
| 2   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1` (`SYSTEM_OBJECT_KW_HANDLE`), `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040` (`PERF_OB_HANDLE`), `InformationClass=4` |
| 3   | User           | `67fe2216-727a-40cb-94b2-c02211edb34a` (Microsoft-Windows-VolumeSnapshot-Driver)                                                                                                                                         |

## Kernel `EVENT_TRACE_FLAG_*` reference

`100665088` = `EVENT_TRACE_FLAG_FILE_IO` (`0x02000000`) + `EVENT_TRACE_FLAG_FILE_IO_INIT` (`0x04000000`) + `EVENT_TRACE_FLAG_DISK_FILE_IO` (`0x00000200`) + `EVENT_TRACE_FLAG_DISK_IO_INIT` (`0x00000400`) + `EVENT_TRACE_FLAG_DISK_IO` (`0x00000100`).

The full EVENT_TRACE_FLAG mapping (PROCESS, THREAD, IMAGE_LOAD, CSWITCH, DPC, INTERRUPT, SYSTEMCALL, REGISTRY, ALPC, NETWORK_TCPIP, etc.) is preserved as a reference — see `Setup-Environment.ps1` and the kernel logger documentation.

## Notes

- See companion variants:
  - `SilkETWConfig_BlueHammer_Win11.md` (multi-provider System collector + filtered Kernel-File user provider)
  - `SilkETWConfig_BlueHammer_Win11_noflt.md` (no event-id filter)
  - `SilkETWConfig_BlueHammer_Win11_norm.md` ("normalised" — extra symlink user provider, broader event-id list)
- Refs:
  - https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
  - https://learn.microsoft.com/en-us/windows/win32/etw/obtrace

## Operational notes

- Volume: medium–high under file activity.
- Privilege: must run elevated; system-logger session for the SystemProvider collector.

---

## Russian version / Русская версия

## Назначение

Базовый профиль BlueHammer для legacy / кросс-версий. Сочетает kernel-коллектор File I/O (широкий bitmask, без event-id фильтра), System Object Provider (handle lifecycle, dual-path Win11+/Win8-10) и user-mode провайдер VolSnap (VolumeSnapshot-Driver). Это оригинальный/базовый BlueHammer-профиль; варианты `Win11`, `Win11_noflt`, `Win11_norm` — последовательные доработки.

Вывод: `./Logs/object_BlueHammer.ndjson`.

## Раскладка коллекторов

| #   | CollectorType  | Провайдер / Флаги                                                                                                                                                                                                        |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Kernel         | `KernelKeywords=100665088` (FileIO + FileIOInit + DiskFileIO + DiskIOInit + DiskIO)                                                                                                                                      |
| 2   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1` (`SYSTEM_OBJECT_KW_HANDLE`), `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040` (`PERF_OB_HANDLE`), `InformationClass=4` |
| 3   | User           | `67fe2216-727a-40cb-94b2-c02211edb34a` (Microsoft-Windows-VolumeSnapshot-Driver)                                                                                                                                         |

## Справочник `EVENT_TRACE_FLAG_*`

`100665088` = `EVENT_TRACE_FLAG_FILE_IO` (`0x02000000`) + `EVENT_TRACE_FLAG_FILE_IO_INIT` (`0x04000000`) + `EVENT_TRACE_FLAG_DISK_FILE_IO` (`0x00000200`) + `EVENT_TRACE_FLAG_DISK_IO_INIT` (`0x00000400`) + `EVENT_TRACE_FLAG_DISK_IO` (`0x00000100`).

Полное соответствие EVENT_TRACE_FLAG (PROCESS, THREAD, IMAGE_LOAD, CSWITCH, DPC, INTERRUPT, SYSTEMCALL, REGISTRY, ALPC, NETWORK_TCPIP и т.д.) сохранено как справочник — см. `Setup-Environment.ps1` и документацию kernel logger.

## Заметки

- См. родственные варианты:
  - `SilkETWConfig_BlueHammer_Win11.md` (multi-provider System-коллектор + filtered Kernel-File user-провайдер)
  - `SilkETWConfig_BlueHammer_Win11_noflt.md` (без event-id фильтра)
  - `SilkETWConfig_BlueHammer_Win11_norm.md` («normalised» — дополнительный symlink user-провайдер, расширенный список event-id)
- Ссылки:
  - https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
  - https://learn.microsoft.com/en-us/windows/win32/etw/obtrace

## Операционные заметки

- Объём: средний–высокий при файловой активности.
- Привилегии: запуск с повышенными правами; system-logger session для SystemProvider-коллектора.
