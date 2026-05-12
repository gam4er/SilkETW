# SilkETWConfig_BlueHammer_Win11_noflt — Provider Reference

## Purpose

Variant of `SilkETWConfig_BlueHammer_Win11` with the kernel `EventIdFilter` removed (suffix `_noflt` = "no filter") and a wider Kernel-File user keyword mask. Use when you want every File I/O event from both the legacy kernel logger and the manifest-based Microsoft-Windows-Kernel-File provider, e.g. during initial provider discovery or to validate which events fire under a given workload.

Output: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Collector layout (differences vs `SilkETWConfig_BlueHammer_Win11`)

| #   | CollectorType  | Provider / Flags                                                                                                    | Δ vs Win11                                                                         |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088`                                                                                          | **No `EventIdFilter`** (removed)                                                   |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x18f0`      | Wider keyword mask, **no `EventIdFilter`**                                         |
| 3   | SystemProvider | five providers (System Object, Process, Lock, IO, IO Filter), legacy `EnableFlags=0x86A10747`, `InformationClass=4` | System Object Provider keywords widened to `0xffffffffffffffff`; no `OpcodeFilter` |

### `UserKeywords=0x18f0` breakdown

`0x18f0` = `0x0020` (`KERNEL_FILE_KEYWORD_FILEIO`) + `0x0800` (`KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH`) + additional bits in the `0x10D0` range. The exact set is intentionally broad to surface more file-operation classes (CreateNewFile, DirEnum, OpHandle, etc.) for inspection. Refer to `Microsoft-Windows-Kernel-File_manifest.xml` for the keyword/event mapping.

## Notes

- Same provider set, GUIDs, and legacy fallback strategy as `SilkETWConfig_BlueHammer_Win11`. Only **filtering** differs.
- Best used for one-off investigation captures; for production use prefer the filtered Win11 variant.

## Operational notes

- Volume: very high (no event-id filtering on Kernel + manifest-based File provider).
- Privilege: must run elevated; system-logger session.

---

## Russian version / Русская версия

## Назначение

Вариант `SilkETWConfig_BlueHammer_Win11` с удалённым kernel `EventIdFilter` (суффикс `_noflt` = "no filter") и более широкой маской keywords для Kernel-File. Применяется, когда нужны все события File I/O от обоих коллекторов (legacy kernel logger и manifest-based Microsoft-Windows-Kernel-File), например при первичном discovery провайдеров или для проверки, какие события срабатывают под определённой нагрузкой.

Вывод: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Раскладка коллекторов (отличия vs `SilkETWConfig_BlueHammer_Win11`)

| #   | CollectorType  | Провайдер / Флаги                                                                                                     | Δ vs Win11                                                                            |
| --- | -------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088`                                                                                            | **Нет `EventIdFilter`** (удалён)                                                      |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x18f0`        | Более широкая маска keywords, **нет `EventIdFilter`**                                 |
| 3   | SystemProvider | пять провайдеров (System Object, Process, Lock, IO, IO Filter), legacy `EnableFlags=0x86A10747`, `InformationClass=4` | Keywords System Object Provider расширены до `0xffffffffffffffff`; нет `OpcodeFilter` |

### Расшифровка `UserKeywords=0x18f0`

`0x18f0` = `0x0020` (`KERNEL_FILE_KEYWORD_FILEIO`) + `0x0800` (`KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH`) + дополнительные биты в диапазоне `0x10D0`. Точный набор намеренно широкий, чтобы выявить больше классов file-операций (CreateNewFile, DirEnum, OpHandle и т.д.) для инспекции. Соответствие keyword/event см. в `Microsoft-Windows-Kernel-File_manifest.xml`.

## Заметки

- Тот же набор провайдеров, GUIDы и стратегия legacy-fallback, что и в `SilkETWConfig_BlueHammer_Win11`. Отличается только **фильтрация**.
- Применяется для разовых investigation-захватов; для прода — отфильтрованный вариант Win11.

## Операционные заметки

- Объём: очень высокий (без event-id фильтрации на Kernel + manifest-based File провайдере).
- Привилегии: запуск с повышенными правами; system-logger session.
