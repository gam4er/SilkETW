# SilkETW — форк с поддержкой System Providers и экспортом в Elasticsearch

> [English version](README.md)

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

## Окружение

Для установки зависимостей (jq, Docker Desktop) и запуска локального ELK-стека:

```powershell
./Setup-Environment.ps1
```

Параметры задокументированы в [Setup-Environment.ps1](Setup-Environment.ps1).

---

## Структура репозитория

```
SilkETW/               ← исходный код коллектора (C#)
  ConfigTemplates/     ← готовые XML-профили
BlueHammer/            ← PoC + исходники FunnyApp (C++)
Import-NdjsonToElastic/← скрипт импорта в Elasticsearch (PowerShell)
docs/                  ← технический разбор BlueHammer (RU + EN)
docker-elk/            ← ELK-стек (git submodule, deviantony/docker-elk)
```

---

## Зависимости

| Пакет | Версия | Лицензия |
| --- | --- | --- |
| McMaster.Extensions.CommandLineUtils | 4.x | Apache-2.0 |
| Microsoft.Diagnostics.Tracing.TraceEvent | latest | MIT |
| Newtonsoft.Json | latest | MIT |

Подробнее: [LICENSE-3RD-PARTY.txt](LICENSE-3RD-PARTY.txt).
