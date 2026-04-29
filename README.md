# SilkETW — форк с поддержкой System Providers и экспортом в Elasticsearch

> English version below / [Jump to English](#silketw--fork-with-system-provider-support-and-elasticsearch-export)

---

Это переписанный форк оригинального [SilkETW](https://github.com/fireeye/SilkETW) (FuzzySecurity / Mandiant). Основное добавление — поддержка **System Providers** (ETW через `EnableTraceEx2`), единый NDJSON-вывод и готовый скрипт импорта в Elasticsearch / Kibana. Всё остальное — Kernel и ManifestBased (User) — работает как раньше.

---

## Провайдеры ETW: три типа

### Kernel Provider (`CollectorType: Kernel`)

Классический механизм ядра: сессия `NT Kernel Logger` (`MSNT_SystemTrace`). Управляется через числовые флаги (`KernelKeywords`). Покрывает файловые I/O (`FileIo/Create`, `FileIo/FSControl`, `FileIo/RenamePath`…), создание процессов, образов, потоков. Широкий охват, низкая стоимость.

**Важно:** `EventId` в этой сессии не уникален на класс события — один номер покрывает несколько типов. При анализе коррелируй по `EventName` + `OpcodeName`, не по `EventId` в одиночку.

### ManifestBased / User Provider (`CollectorType: User`)

Манифестный ETW: провайдер задаётся GUID или именем (например, `Microsoft-Windows-Kernel-File`). Каждый провайдер публикует xml-манифест с описанием всех событий. Структурированный payload, нет проблем с `EventId`, декодируется без символов. Удобен там, где важен точный путь (`FilePath`-поле), теги, версии событий.

### System Provider (`CollectorType: SystemProvider`)

Новый тип в этом форке. Использует `EnableTraceEx2` для добавления провайдеров к уже запущенной системной сессии (`NT Kernel Logger`). Открывает доступ к событиям, которых нет ни в классическом Kernel-пути, ни в манифестных провайдерах: **жизненный цикл объектов Object Manager** (открытие/закрытие дескрипторов, создание имён), процессы, блокировки, I/O-фильтры.

На Windows 11+ используется современный путь через `EnableTraceEx2`; на Windows 8/10 — legacy fallback через `TraceSetInformation`. Это описано в [`SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md`](SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md).

---

## Цель: NDJSON, готовый к импорту в Elastic

Все коллекторы пишут события в единый NDJSON-файл (одно событие — одна строка JSON). Формат подходит для прямого импорта в Elasticsearch: каждая строка содержит `@timestamp`, `ProcessName`, `ProviderName`, `EventName`, `ThreadID`, `XmlEventData.*` и прочие поля, которые Kibana сразу индексирует.

Несколько коллекторов (Kernel + ManifestBased + SystemProvider) можно запустить одновременно и указать один `<OutputPath>` — они пишут в один файл через потокобезопасный writer.

---

## Конфигурация

Коллекторы задаются XML-файлом. Пример — профиль для BlueHammer на Windows 11:

```xml
<SilkETWConfig>
  <OutputPath>./Logs/object_file_symlink_BlueHammer_Win11.ndjson</OutputPath>

  <!-- Kernel: File I/O -->
  <ETWCollector>
    <Guid>f9beff90-c9ad-4f39-b4fc-49be905f8d35</Guid>
    <CollectorType>Kernel</CollectorType>
    <KernelKeywords>100665088</KernelKeywords>
    <EventIdFilter>64,69,71,75,79,80,81</EventIdFilter>
  </ETWCollector>

  <!-- ManifestBased: Microsoft-Windows-Kernel-File -->
  <ETWCollector>
    <Guid>abe9f2f4-c9a2-4a03-a9d5-8f1f63e64ac5</Guid>
    <CollectorType>User</CollectorType>
    <ProviderName>Microsoft-Windows-Kernel-File</ProviderName>
    <UserKeywords>4503599644147711</UserKeywords>
  </ETWCollector>

  <!-- System Provider: Object Manager handle lifecycle -->
  <ETWCollector>
    <Guid>a9d2e96b-1c3c-4c2a-b8c7-0e5f3d1a7b22</Guid>
    <CollectorType>SystemProvider</CollectorType>
    <SystemProviderGuids>
      <ProviderGuid>{9B79EE91-B5FD-41C0-A243-4248B4B4CF09}</ProviderGuid>
    </SystemProviderGuids>
  </ETWCollector>
</SilkETWConfig>
```

Готовые профили лежат в [`SilkETW/ConfigTemplates/`](SilkETW/ConfigTemplates/):

| Файл | Назначение |
| --- | --- |
| `SilkETWConfig_BlueHammer_Win11.xml` | BlueHammer: File I/O + Object Manager, Windows 11 |
| `SilkETWConfig_BlueHammer_Win11_noflt.xml` | то же, без IO Filter Provider |
| `SilkETWConfig_BlueHammer.xml` | BlueHammer на старых Windows |
| `SilkETWConfig_ObjectManager.xml` | только Object Manager |
| `SilkETWConfig_Shadowcopy.xml` | VSS / shadow copy события |
| `SilkETWConfig_Certificates.xml` | события сертификатов |
| `SilkETWConfig_IIS.xml` | IIS |
| `SilkETWConfig_Office.xml` | Office |

---

## Запуск

```
SilkETW.exe -c SilkETW\ConfigTemplates\SilkETWConfig_BlueHammer_Win11.xml
```

Требует прав администратора. Запись идёт в файл, указанный в `<OutputPath>`.

---

## Импорт в Elasticsearch

После сбора данных готовый NDJSON можно отправить в локальный Elasticsearch одной командой:

```powershell
./Import-NdjsonToElastic/Import-NdjsonToElastic.ps1 `
    -NdjsonPath .\Logs\object_file_symlink_BlueHammer_Win11.ndjson `
    -IndexName bluehammer `
    -Recreate
```

Скрипт [`Import-NdjsonToElastic/Import-NdjsonToElastic.ps1`](Import-NdjsonToElastic/Import-NdjsonToElastic.ps1):
- нормализует кодировку к UTF-8;
- конвертирует NDJSON в Elasticsearch bulk-формат через `jq`;
- создаёт индекс с правильными маппингами (`@timestamp` как `date`, числа как `long`);
- заливает данные пачками (`--DocsPerBulk`, по умолчанию 5000);
- создаёт или обновляет Kibana Data View.

Требования: PowerShell 7+, `jq` в PATH, локальный Elasticsearch.

---

## BlueHammer: пример интересного кейса

[BlueHammer](BlueHammer/) — PoC локальной LPE-уязвимости в Windows Defender. Атака использует TOCTOU-гонку: через цепочку Object Manager symlink + oplock Defender при обновлении сигнатур (работая как SYSTEM) копирует SAM из теневой копии тома в директорию, доступную пользователю.

BlueHammer удобен как исследовательский кейс, потому что затрагивает сразу несколько ETW-слоёв: файловые операции, Object Manager, Cloud Files API, опционально — стек вызовов. Без правильно собранного ETW ни атака, ни её механизм не видны.

### Компиляция и запуск

```
BlueHammer/FunnyApp.sln  →  собрать в Release x64
```

Запускать на тестовой машине с не Administrator-правами. При наличии ожидающего обновления Defender PoC выполняет атаку автоматически.

### Мониторинг

Параллельно с PoC запустить:

```
SilkETW.exe -c SilkETW\ConfigTemplates\SilkETWConfig_BlueHammer_Win11.xml
```

Результат — NDJSON с полным трейсом: от загрузки `offreg.dll` и `cldapi.dll` до `FileIo/Create` со стороны `MsMpEng` на пути `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM`.

Подробный разбор артефактов: [`docs/bluehammer-funnyapp-talk-ru.md`](docs/bluehammer-funnyapp-talk-ru.md) / [`docs/bluehammer-funnyapp-talk-en.md`](docs/bluehammer-funnyapp-talk-en.md).

---

## Структура репозитория

```
SilkETW/               ← исходный код коллектора (C#)
  ConfigTemplates/     ← готовые XML-профили
BlueHammer/            ← PoC + исходники FunnyApp (C++)
Import-NdjsonToElastic/← скрипт импорта в Elasticsearch (PowerShell)
docs/                  ← технический разбор BlueHammer (RU + EN)
```

---

## Зависимости

| Пакет | Версия | Лицензия |
| --- | --- | --- |
| McMaster.Extensions.CommandLineUtils | 4.x | Apache-2.0 |
| Microsoft.Diagnostics.Tracing.TraceEvent | latest | MIT |
| Newtonsoft.Json | latest | MIT |

Подробнее: [LICENSE-3RD-PARTY.txt](LICENSE-3RD-PARTY.txt).

---
---

# SilkETW — Fork with System Provider Support and Elasticsearch Export

This is a rewritten fork of the original [SilkETW](https://github.com/fireeye/SilkETW) (FuzzySecurity / Mandiant). The main addition is support for **System Providers** (ETW via `EnableTraceEx2`), unified NDJSON output, and a ready-made import script for Elasticsearch / Kibana. Everything else — Kernel and ManifestBased (User) — works as before.

---

## ETW Provider Types

### Kernel Provider (`CollectorType: Kernel`)

The classic kernel mechanism: `NT Kernel Logger` session (`MSNT_SystemTrace`). Controlled by numeric flags (`KernelKeywords`). Covers file I/O (`FileIo/Create`, `FileIo/FSControl`, `FileIo/RenamePath`…), process, image, and thread creation. Broad coverage at low cost.

**Important:** `EventId` in this session is not unique per event class — one number can cover several types. When analyzing, correlate on `EventName` + `OpcodeName`, not on `EventId` alone.

### ManifestBased / User Provider (`CollectorType: User`)

Manifest-based ETW: the provider is identified by GUID or name (e.g., `Microsoft-Windows-Kernel-File`). Each provider publishes an XML manifest describing all its events. Structured payload, no `EventId` aliasing, decodes without PDB symbols. Convenient wherever the exact path (`FilePath` field), tags, or event versions matter.

### System Provider (`CollectorType: SystemProvider`)

New in this fork. Uses `EnableTraceEx2` to add providers to an already-running system session (`NT Kernel Logger`). Unlocks events not available through either the classic Kernel path or manifest providers: **Object Manager object lifecycle** (handle open/close, name creation), processes, locks, and I/O filters.

On Windows 11+, the modern path through `EnableTraceEx2` is used; on Windows 8/10 a legacy fallback via `TraceSetInformation` is available. See [`SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md`](SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md).

---

## Goal: NDJSON Ready for Elastic Import

All collectors write events to a single NDJSON file (one event = one JSON line). The format is suitable for direct Elasticsearch import: every line contains `@timestamp`, `ProcessName`, `ProviderName`, `EventName`, `ThreadID`, `XmlEventData.*`, and other fields that Kibana indexes immediately.

Multiple collectors (Kernel + ManifestBased + SystemProvider) can run simultaneously with a single `<OutputPath>` — they write to one file through a thread-safe writer.

---

## Configuration

Collectors are defined in an XML file. Example — BlueHammer profile for Windows 11:

```xml
<SilkETWConfig>
  <OutputPath>./Logs/object_file_symlink_BlueHammer_Win11.ndjson</OutputPath>

  <!-- Kernel: File I/O -->
  <ETWCollector>
    <Guid>f9beff90-c9ad-4f39-b4fc-49be905f8d35</Guid>
    <CollectorType>Kernel</CollectorType>
    <KernelKeywords>100665088</KernelKeywords>
    <EventIdFilter>64,69,71,75,79,80,81</EventIdFilter>
  </ETWCollector>

  <!-- ManifestBased: Microsoft-Windows-Kernel-File -->
  <ETWCollector>
    <Guid>abe9f2f4-c9a2-4a03-a9d5-8f1f63e64ac5</Guid>
    <CollectorType>User</CollectorType>
    <ProviderName>Microsoft-Windows-Kernel-File</ProviderName>
    <UserKeywords>4503599644147711</UserKeywords>
  </ETWCollector>

  <!-- System Provider: Object Manager handle lifecycle -->
  <ETWCollector>
    <Guid>a9d2e96b-1c3c-4c2a-b8c7-0e5f3d1a7b22</Guid>
    <CollectorType>SystemProvider</CollectorType>
    <SystemProviderGuids>
      <ProviderGuid>{9B79EE91-B5FD-41C0-A243-4248B4B4CF09}</ProviderGuid>
    </SystemProviderGuids>
  </ETWCollector>
</SilkETWConfig>
```

Ready-made profiles are in [`SilkETW/ConfigTemplates/`](SilkETW/ConfigTemplates/):

| File | Purpose |
| --- | --- |
| `SilkETWConfig_BlueHammer_Win11.xml` | BlueHammer: File I/O + Object Manager, Windows 11 |
| `SilkETWConfig_BlueHammer_Win11_noflt.xml` | Same, without IO Filter Provider |
| `SilkETWConfig_BlueHammer.xml` | BlueHammer on older Windows |
| `SilkETWConfig_ObjectManager.xml` | Object Manager only |
| `SilkETWConfig_Shadowcopy.xml` | VSS / shadow copy events |
| `SilkETWConfig_Certificates.xml` | Certificate events |
| `SilkETWConfig_IIS.xml` | IIS |
| `SilkETWConfig_Office.xml` | Office |

---

## Running

```
SilkETW.exe -c SilkETW\ConfigTemplates\SilkETWConfig_BlueHammer_Win11.xml
```

Requires Administrator privileges. Output is written to the file specified in `<OutputPath>`.

---

## Importing into Elasticsearch

After collection, the ready NDJSON can be sent to a local Elasticsearch with a single command:

```powershell
./Import-NdjsonToElastic/Import-NdjsonToElastic.ps1 `
    -NdjsonPath .\Logs\object_file_symlink_BlueHammer_Win11.ndjson `
    -IndexName bluehammer `
    -Recreate
```

The script [`Import-NdjsonToElastic/Import-NdjsonToElastic.ps1`](Import-NdjsonToElastic/Import-NdjsonToElastic.ps1):
- normalizes encoding to UTF-8;
- converts NDJSON to Elasticsearch bulk format via `jq`;
- creates an index with correct mappings (`@timestamp` as `date`, numbers as `long`);
- uploads data in batches (`-DocsPerBulk`, default 5000);
- creates or updates the Kibana Data View.

Requirements: PowerShell 7+, `jq` in PATH, local Elasticsearch.

---

## BlueHammer: An Interesting Example Case

[BlueHammer](BlueHammer/) is a PoC for a local LPE vulnerability in Windows Defender. The attack exploits a TOCTOU race: through an Object Manager symlink chain plus an oplock, Defender — while updating signatures as SYSTEM — copies the SAM hive out of a volume shadow copy into a user-accessible directory.

BlueHammer works well as a research case because it touches several ETW layers at once: file I/O, Object Manager, Cloud Files API, and optionally call stacks. Without properly collected ETW, neither the attack nor its mechanism is visible.

### Build

```
BlueHammer/FunnyApp.sln  →  build Release x64
```

Run on a test machine with Administrator rights. If a pending Defender update is available, the PoC executes the attack automatically.

### Monitoring

Run alongside the PoC:

```
SilkETW.exe -c SilkETW\ConfigTemplates\SilkETWConfig_BlueHammer_Win11.xml
```

Result: an NDJSON file with a full trace — from loading `offreg.dll` and `cldapi.dll` all the way to a `FileIo/Create` event from `MsMpEng` on the path `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM`.

Detailed artifact analysis: [`docs/bluehammer-funnyapp-talk-en.md`](docs/bluehammer-funnyapp-talk-en.md) / [`docs/bluehammer-funnyapp-talk-ru.md`](docs/bluehammer-funnyapp-talk-ru.md).

---

## Repository Layout

```
SilkETW/               ← collector source code (C#)
  ConfigTemplates/     ← ready-made XML profiles
BlueHammer/            ← PoC + FunnyApp source (C++)
Import-NdjsonToElastic/← Elasticsearch import script (PowerShell)
docs/                  ← BlueHammer technical write-up (RU + EN)
```

---

## Dependencies

| Package | Version | License |
| --- | --- | --- |
| McMaster.Extensions.CommandLineUtils | 4.x | Apache-2.0 |
| Microsoft.Diagnostics.Tracing.TraceEvent | latest | MIT |
| Newtonsoft.Json | latest | MIT |

See [LICENSE-3RD-PARTY.txt](LICENSE-3RD-PARTY.txt) for details.
