# SilkETWConfig_BlueHammer_Win11_norm — Provider Reference

## Purpose

"Normalised" Windows 11 BlueHammer profile. Builds on `SilkETWConfig_BlueHammer_Win11` and adds a fourth user-mode collector — a custom WPP-style provider for symlink-tracking events from the kernel — plus a broader explicit Kernel `EventIdFilter` to surface a wider, normalised set of correlation-relevant events.

Output: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Collector layout

| #   | CollectorType  | Provider / Flags                                                                                                     |
| --- | -------------- | -------------------------------------------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088`, `EventIdFilter=0,1,2,3,4,32,33,35,36,37,38,39,40,48,49,50,51,64,69,70,71,74,75,79,80,81` |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x18F0`       |
| 3   | User           | `e02a841c-75a3-4fa7-afc8-ae09cf9b7f23` (custom kernel symlink-tracking provider), `Informational`                    |
| 4   | SystemProvider | five providers (System Object, Process, Lock, IO, IO Filter), legacy `EnableFlags=0x86A10747`, `InformationClass=4`  |

### Custom symlink provider `e02a841c-75a3-4fa7-afc8-ae09cf9b7f23`

Optional extra collector that complements the Kernel and Microsoft-Windows-Kernel-File providers. Triggered by a WPP tracepoint in the kernel firing on relevant symlink-related operations. Not strictly required when Microsoft-Windows-Kernel-File is enabled (its `RenamePath`/`SetLinkPath` templates already carry the target path) — but the custom provider can produce additional events with the **source** path in a `FilePath` field, useful for correlating with file-delete events from the Kernel provider that only carry the target path. Coverage and overhead characteristics differ from the standard manifest-based provider.

### Kernel event IDs in the broad filter

The set `0,1,2,3,4,32,33,35,36,37,38,39,40,48,49,50,51,64,69,70,71,74,75,79,80,81` deliberately spans:

- Process / thread / image rundown (`0`–`4`)
- ObTrace handle lifecycle (`32`–`40`)
- Disk I/O (`48`–`51`)
- File I/O (`64`–`81`, including `81` SetLinkPath for symlink tracking)

### SystemProvider sub-providers

Same five providers as `SilkETWConfig_BlueHammer_Win11`. Note: System Object Provider has **no `OpcodeFilter`** in this variant — full handle stream is captured.

## Notes

- Same legacy `EnableFlags=0x86A10747` composition as the other Win11 variants.
- The custom symlink provider must exist on the host; on stock Windows 11 it is typically registered by a third-party kernel component or a research driver. If absent, that collector will silently produce no events but will not fail the others.

## Operational notes

- Volume: very high.
- Privilege: must run elevated; system-logger session.

---

## Russian version / Русская версия

## Назначение

«Нормализованный» BlueHammer-профиль Windows 11. Расширяет `SilkETWConfig_BlueHammer_Win11` четвёртым user-mode коллектором — кастомным WPP-style провайдером для событий отслеживания symlink из ядра — и более широким явным Kernel `EventIdFilter`, чтобы получить более широкий, нормализованный набор correlation-relevant событий.

Вывод: `./Logs/object_file_symlink_BlueHammer_Win11.ndjson`.

## Раскладка коллекторов

| #   | CollectorType  | Провайдер / Флаги                                                                                                     |
| --- | -------------- | --------------------------------------------------------------------------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100665088`, `EventIdFilter=0,1,2,3,4,32,33,35,36,37,38,39,40,48,49,50,51,64,69,70,71,74,75,79,80,81`  |
| 2   | User           | `edd08927-9cc4-4e65-b970-c2560fb5c289` (Microsoft-Windows-Kernel-File), `Informational`, `UserKeywords=0x18F0`        |
| 3   | User           | `e02a841c-75a3-4fa7-afc8-ae09cf9b7f23` (кастомный kernel-провайдер отслеживания symlink), `Informational`             |
| 4   | SystemProvider | пять провайдеров (System Object, Process, Lock, IO, IO Filter), legacy `EnableFlags=0x86A10747`, `InformationClass=4` |

### Кастомный symlink-провайдер `e02a841c-75a3-4fa7-afc8-ae09cf9b7f23`

Опциональный дополнительный коллектор, дополняющий Kernel и Microsoft-Windows-Kernel-File. Триггерится WPP-tracepoint в ядре на relevant symlink-операциях. Строго не обязателен при включённом Microsoft-Windows-Kernel-File (его шаблоны `RenamePath`/`SetLinkPath` уже несут целевой путь) — но кастомный провайдер может давать дополнительные события с **исходным** путём в поле `FilePath`, что полезно для корреляции с file-delete событиями Kernel-провайдера, у которых есть только target. Покрытие и характеристики overhead отличаются от стандартного manifest-based провайдера.

### Kernel event IDs в широком фильтре

Набор `0,1,2,3,4,32,33,35,36,37,38,39,40,48,49,50,51,64,69,70,71,74,75,79,80,81` намеренно покрывает:

- Process / thread / image rundown (`0`–`4`)
- ObTrace handle lifecycle (`32`–`40`)
- Disk I/O (`48`–`51`)
- File I/O (`64`–`81`, включая `81` SetLinkPath для отслеживания symlink)

### Под-провайдеры SystemProvider

Те же пять провайдеров, что и в `SilkETWConfig_BlueHammer_Win11`. Отличие: у System Object Provider в этом варианте **нет `OpcodeFilter`** — захватывается полный поток handle.

## Заметки

- Та же композиция legacy `EnableFlags=0x86A10747`, что и в других Win11-вариантах.
- Кастомный symlink-провайдер должен существовать на хосте; на штатной Windows 11 он обычно регистрируется сторонним kernel-компонентом или research-драйвером. При отсутствии этот коллектор молча не выдаст событий, но не уронит остальные.

## Операционные заметки

- Объём: очень высокий.
- Привилегии: запуск с повышенными правами; system-logger session.
