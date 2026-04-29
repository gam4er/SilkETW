# BlueHammer: от одного ETW-артефакта до понимания атаки

Технический черновик выступления на 20-30 минут.

## С чего начать

Сначала — конкретная строчка из Elasticsearch. Потом — откуда она взялась. Потом — почему её так трудно поймать без правильной телеметрии.

Главный тезис доклада такой: BlueHammer интересен не потому, что он связан с Defender, VSS или Cloud Files по отдельности. Он интересен потому, что это хороший пример TOCTOU-цепочки, где критичное поведение очень трудно увидеть по обычной пользовательской телеметрии, но его можно восстановить, если у нас есть правильно собранный ETW.

## Артефакт номер один: MsMpEng открывает SAM из shadow copy

Вот конкретный документ из индекса `hopes6` с `_id = d6F22J0Bg74gBbI902vy`:

| Поле | Значение |
| --- | --- |
| `@timestamp` | `2026-04-29T17:47:19.820133700Z` |
| `ProcessName` | `MsMpEng` |
| `EventName` | `FileIo/Create` |
| `ThreadID` | `4512` |
| `XmlEventData.OpenPath` | `\Device\HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM` |
| `XmlEventData.FileObject` | `0xffff820b39eb5200` |
| `XmlEventData.CreateOptions` | `18,874,436` |
| `XmlEventData.ShareAccess` | `7` |

Это и есть ключевой факт всего расследования. Windows Defender — `MsMpEng`, работающий как SYSTEM — открывает `SAM` не из живого реестра и не из штатного системного раздела. Он открывает его из `HarddiskVolumeShadowCopy2`: из теневой копии тома. В контексте ночного резервного копирования shadow copy access выглядел бы штатно. Но здесь это прямое следствие атаки.

Есть и второй похожий документ (`_id = M6F22J0Bg74gBbI902zy`, тот же путь, тот же `ThreadID`, через 4 мс). Безопасная интерпретация: два очень близких открытия одного пути на одном потоке — повторный `open` в рамках той же операции или overlap двух ETW-источников.

## Хронология одного эпизода: 60 миллисекунд на потоке 4512

Если взять узкое окно по `ProcessName = MsMpEng`, `ThreadID = 4512` и диапазон `17:47:19.780–17:47:19.840Z`, получается вот что:

| Время | Событие | Путь |
| --- | --- | --- |
| `17:47:19.805631` | `FileIo/Create` | `...\Definition Updates\{GUID}\mpengine.dll` |
| `17:47:19.805695` | `FileIo/Create` | `...\Temp\{GUID}\mpengine.dll` |
| `17:47:19.805831` | `FileIo/Create` | `...\Temp\{GUID}\mpasbase.vdm` |
| `17:47:19.805872` | `FileIo/Create` | `...\Temp\{GUID}\mpasbase.vdm` (повтор) |
| `17:47:19.805900` | `FileIo/Create` | то же, другие `CreateOptions` |
| `17:47:19.820133` | `FileIo/Create` | **`\Device\HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM`** |
| `17:47:19.822478+` | `FileIo/QueryInfo` | серия follow-up по тому же `FileObject` |
| `17:47:19.822822` | `FileIo/Create` | снова Defender Definition Updates — после SAM-open |

Это не набор разрозненных событий. Это короткий эпизод: переход от штатного Defender update workflow к прямому чтению SAM из shadow copy — в рамках одного потока, за 60 миллисекунд.

## FunnyApp в том же индексе: трейс атакующей стороны

В `hopes6` рядом с `MsMpEng` есть ещё один процесс — `FunnyApp`. Это и есть PoC. Он запустился в `17:45:06.741Z` и завершился в `17:47:25.963Z`. За эти два с небольшим минуты датасет зафиксировал **3628 событий** от `FunnyApp`.

### Структура событий FunnyApp

| Тип события | Кол-во |
| --- | --- |
| `OperationEnd` | 987 |
| `FileIo/Create` | 907 |
| `FileIo/QueryInfo` | 581 |
| `Create` | 256 |
| `QueryInformation` | 200 |
| `Cleanup` + `Close` | 369 |
| `FileIo/FSControl` | 125 |
| `QuerySecurity` | 81 |
| `FileIo/Delete` + `DletePath` | 20 |
| `NameCreate` | 1 |

125 событий `FileIo/FSControl` — это в первую очередь oplock-операции и Cloud Files API. 1 событие `NameCreate` — загрузка `offreg.dll` (Offline Registry).

### Ключевые события FunnyApp в хронологическом порядке

| Время | Событие | Значение |
| --- | --- | --- |
| `17:45:06.741` | первое событие FunnyApp | старт PoC |
| `17:45:06.749274` | `NameCreate` → `offreg.dll` | загружен Offline Registry API |
| `17:45:06.745–…` | 125× `FileIo/FSControl` | oplock (RstrtMgr.dll, Cloud Files) |
| `17:46:52.749206` | `FileIo/DletePath` → `mpam-fe[1].exe` в `INetCache\IE\...` | WD update binary скачан через WinINet и помещён в кэш IE |
| `17:47:18.068935` | `FileIo/DletePath` → `\Temp\9c83879e-5b1b-4138-9132-49b2c475ee2a` | temp GUID dir удалён (×2) |
| `17:47:19.820133` | **`MsMpEng` открывает SAM из shadow copy** | **критический артефакт** |
| `17:47:19.843552` | `FileIo/DletePath` → `d10afa6a-c9a5-43e5-adb2-6a0115b4a0d0.lock` | lock-файл Cloud Files FreezeVSS удалён (delete-on-close) |
| `17:47:19.844128` | `FileIo/DletePath` → `FunnyApp:${3D0CE612-FDEE-43f7-8ACA-957BEC0CCBA0}.SyncRootIdentity` | Cloud Files sync root metadata cleanup |
| `17:47:25.950–963` | `FileIo/DletePath` × 4 → `7d138e84-ffbf-4f4c-baeb-8f80d218774a\{mpengine.dll, mpasdlta.vdm, mpavbase.vdm, mpavdlta.vdm}` | удаление extracted WD update files |
| `17:47:25.963` | последнее событие FunnyApp | завершение PoC |

### Характерные DLL в FileName событиях FunnyApp

| DLL | Назначение в атаке |
| --- | --- |
| `wuapi.dll`, `wups.dll`, `uusbrain.dll` | Windows Update API (COM IUpdateSession) |
| `Cabinet.dll` | FDICreate/FDICopy для распаковки `mpam-fe.exe` |
| `WININET.dll` | загрузка с `go.microsoft.com/fwlink/?LinkID=121721` |
| `OFFREG.dll` | Offline Registry (OROpenHiveByHandle, без SYSTEM/SeBackupPrivilege) |
| `cldapi.dll` | Cloud Files API (CfRegisterSyncRoot, CfConnectSyncRoot) |
| `ktmw32.dll` | Kernel Transaction Manager (CreateFileTransacted для защиты от cleanup) |

Это не случайный набор. Каждая DLL соответствует одному функциональному блоку эксплойта.

## Как это работает: восемь шагов BlueHammer

> **TL;DR**: Windows Defender сам, с правами SYSTEM, отдаёт тебе базу паролей всех пользователей. Ты просто вежливо просишь.

Суть в трёх предложениях: Windows Defender при обновлении сигнатур работает как SYSTEM и открывает файлы из указанной директории. Атакующий через цепочку Object Manager symlink + oplock-гонку подменяет путь так, что WD сам копирует SAM из теневой копии тома в папку, доступную пользователю. Всё. Причём третье предложение — это слово из трёх букв.

### Шаг 1: Поиск обновлений — CheckForWDUpdates()

Через COM-интерфейс `IUpdateSession` — CLSID разрешается через `CLSIDFromProgID(L"Microsoft.Update.Session")` — ищется ожидающее обновление дефиниций Defender в категории «Microsoft Defender Antivirus». Цикл в `wmain` повторяет проверку каждые 30 секунд, пока обновление не появится. ETW-свидетельство: события к `wuapi.dll`, `wups.dll`, `uusbrain.dll` в FunnyApp FileIo trace.

### Шаг 2: Загрузка и распаковка — GetUpdateFiles()

Скачивается легитимный update-пакет с `go.microsoft.com/fwlink/?LinkID=121721&arch=x64` через WinINet. Файл кэшируется в IE cache как `mpam-fe[1].exe`. ETW-подтверждение: `FileIo/DletePath` для `mpam-fe[1].exe` в `INetCache\IE\IJ95A16Z\` в `17:46:52.749206`.

Функция `GetCabFileFromBuff()` парсит PE-заголовки скачанного EXE, находит секцию `.rsrc` и извлекает встроенный `.cab`. Распаковка через Cabinet API — `FDICreate/FDICopy` с кастомными callback-ами для работы целиком в памяти. ETW: загрузка `Cabinet.dll`, temp GUID-директории с файлами обновлений.

### Шаг 3: Создание VSS через EICAR + oplock — TriggerWDForVS()

Создаётся EICAR-файл (строка хранится задом наперёд, `rev()`). Открывается `RstrtMgr.dll` с exclusive batch oplock — это «замораживает» WD на время создания VSS-снимка. Параллельно `ShadowCopyFinderThread` мониторит `\Device` через `NtQueryDirectoryObject`, ожидая появления нового `HarddiskVolumeShadowCopy`. ETW: 125 `FileIo/FSControl` событий — это в том числе именно эти oplock-запросы.

### Шаг 4: Заморозка WD через Cloud Files API — FreezeVSS()

Регистрируется sync root с провайдером `"IHATEMICROSOFT"` через `CfRegisterSyncRoot`. Callback `CfCallbackFetchPlaceHolders` определяет PID процесса WD, создаёт placeholder-файл и удерживает WD на ещё одном oplock. Результат — WD замер, VSS доступен. ETW-след: UUID-именованный lock-файл `d10afa6a-c9a5-43e5-adb2-6a0115b4a0d0.lock`, последовательно загружается `cldapi.dll`.

### Шаг 5: RPC-вызов обновления + oplock на mpasbase.vdm — wmain

Путь к обновлениям проходит через Object Manager symlink `WDUpdateDirectory`. Вызов `Proc42_ServerMpUpdateEngineSignature` в отдельном потоке заставляет WD обрабатывать обновления из указанной директории. Через `ReadDirectoryChangesW` ловится момент, когда WD создаёт новую папку дефиниций. На `mpasbase.vdm` ставится batch oplock — когда он срабатывает, известно, что WD начал читать файл.

### Шаг 6: Подмена symlink → SAM

В момент срабатывания oplock symlink `WDUpdateDirectory` пересоздаётся — теперь он указывает на Object Manager directory. Внутри создаётся symlink `mpasbase.vdm` → `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM` (строки 3666–3680 в [BlueHammer/FunnyApp.cpp](../BlueHammer/FunnyApp.cpp)). WD продолжает работу и копирует содержимое SAM в `Definition Updates\{GUID}\mpasbase.vdm`. Файл открывается через `CreateFileTransacted` — транзакция нужна, чтобы WD не успел удалить файл при cleanup. ETW-подтверждение: `FileIo/Create` на `HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM` со стороны `MsMpEng`, `ThreadID 4512`, `17:47:19.820133`.

### Шаг 7: Credential theft через Offline Registry — DoSpawnShellAsAllUsers()

Шелл от других пользователей в PoC — это просто demo. Настоящая атака — кража учётных данных.

- `OROpenHiveByHandle(samfile, &hSAMhive)` — Offline Registry API парсит SAM как обычный файл, **без прав SYSTEM, без SeBackupPrivilege**, без загрузки куста в живой реестр. ETW-след: NameCreate для `offreg.dll` в `17:45:06.749274`.
- `GetLSASecretKey()` — извлекает boot key из `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}` с перестановкой по таблице индексов.
- `UnprotectPasswordEncryptionKey()` — достаёт зашифрованный ключ SAM из значения `F`, расшифровывает через AES-128-CBC.
- Для каждого пользователя: `ORGetValue(hkey2, NULL, L"V", ...)` — читает запись `V`, из которой по фиксированным смещениям извлекаются username, LM-хеш, NT-хеш.
- `UnprotectNTHash()` снимает AES-обёртку, затем `UnproctectPasswordHashDES()` — DES-ECB с двумя ключами, производными от RID.

### Шаг 8: NTLM-хеш в открытом виде

После этого pass-the-hash, offline-брут, relay — дело техники. `SamiChangePasswordUser` и запуск сервисов через `CreateService` — это только proof-of-concept. Хеши уже утекли.

## Теперь — общее: почему это TOCTOU и почему это трудно мониторить

Time Of Check / Time Of Use-уязвимости возникают тогда, когда между моментом проверки и моментом использования объекта его состояние успевает измениться. На бумаге определение простое. На практике проблема намного неприятнее.

**Первая сложность**: по отдельности почти все действия выглядят нормально. Defender обновляет сигнатуры, VSS создаёт shadow copy, Cloud Files работает с placeholder-файлами, файловая подсистема обслуживает oplock, объектный менеджер открывает и закрывает дескрипторы. Каждый слой в отдельности — обычная системная жизнь.

**Вторая сложность**: атакующий не оставляет один очевидный IOC. Он создаёт короткое окно, в котором привилегированный компонент уже открыл нужную точку зрения на файловую систему, а непривилегированный код ещё успевает этим воспользоваться. У детектора должна быть не одна сигнатура, а способность собрать последовательность по нескольким источникам.

**Третья сложность**: даже когда есть файловая телеметрия, она показывает только «нормальные» промежуточные пути — `mpengine.dll`, `mpasbase.vdm`, временные файлы. Критический путь может быть виден очень коротко.

## Почему в этом кейсе нужен именно ETW

Если задача — понять по исходникам, что должен делать PoC — исходников достаточно. Но если задача — на реальной машине доказать или опровергнуть эксплуатацию — нужна наблюдаемость.

В этом проекте наблюдаемость строится через ETW в единый NDJSON-поток. BlueHammer пересекает несколько слоёв: файловые операции, manifest-based kernel file telemetry, object-manager, корреляция процесс/поток/путь/IRP/FileObject.

Конфиг [SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml](../SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml) включает одновременно:

- `Kernel` collector для `MSNT_SystemTrace` file I/O;
- manifest-based `Microsoft-Windows-Kernel-File`;
- `SystemProvider` с Object Provider, Process Provider, Lock Provider, IO Provider, IO Filter Provider.

Критическая оговорка: в `MSNT_SystemTrace` значения `EventId` разделяются между классами событий. Коррелировать нужно по `EventName` + `OpcodeName` + контекст провайдера, а не по `EventId` в одиночку.

## Какие ETW-слои задействованы

**Classic kernel collector** — `FileIo/Create`, `FileIo/FSControl`, `FileIo/RenamePath` и т.д. Даёт широкий охват. Именно здесь виден главный артефакт — SAM из shadow copy.

**Manifest-based Microsoft-Windows-Kernel-File** — богаче payload, нет двусмысленности с `EventId`. Удобен для событий, где критичен целевой путь (`RenamePath`, `SetLinkPath`).

**System Object Provider и соседние providers** — жизненный цикл объектов и дескрипторов, пересечение с process/thread/image. Для Windows 11+ через modern path с System Providers, для старых — legacy fallback. Подробнее: [SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md](../SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md).

## Отдельно про ETW, недоступный обычным процессам

Некоторые ETW-сессии защищены так, что обычный процесс — даже с высокими правами — не может их consume. `SecurityTrace` AutoLogger, `Microsoft-Windows-Threat-Intelligence` — доступны только на уровне Antimalware-PPL. Хороший разбор у Connor McGarr в статье про SecurityTrace.

ETW — не один механизм, а семейство с разным уровнем привилегий. Обещать слушателю «просто включим вообще весь ETW» нельзя. Часть источников защищена архитектурно. В датасете `hopes6` narrative строится на file/object telemetry — это архитектурный контекст, а не утверждение о присутствии Threat Intelligence provider в индексе.

## Сильные и слабые признаки в hopes6

### Сильные признаки

1. `ProcessName = MsMpEng`
2. `EventName = FileIo/Create` (не просто `EventId = 64`)
3. `OpenPath` содержит `HarddiskVolumeShadowCopy*\Windows\System32\Config\SAM`
4. Корреляция по одному `ThreadID` в коротком окне
5. Соседние открытия `mpengine.dll` и `mpasbase.vdm` на том же потоке

### Слабые и шумные признаки

`FileObject` — плохой глобальный pivot. Быстро даёт несвязанный шум из разных процессов. Полезен только внутри узкого эпизода.

`IrpPtr` — аналогично. Внутри короткого эпизода полезен, при широком поиске смешивает несвязанные операции.

`EventId` в одиночку — опасен. В `MSNT_SystemTrace` один `EventId` покрывает несколько классов событий.

## Практические Elasticsearch-запросы

### 1. Два ключевых SAM-документа

```json
GET hopes6/_search
{
  "query": { "ids": { "values": ["d6F22J0Bg74gBbI902vy", "M6F22J0Bg74gBbI902zy"] } },
  "_source": ["@timestamp","ProcessName","ProviderName","EventName","ThreadID",
    "XmlEventData.OpenPath","XmlEventData.FileObject","XmlEventData.CreateOptions","XmlEventData.ShareAccess"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 2. Shadow-copy hive access со стороны MsMpEng

```json
GET hopes6/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "ProcessName": "MsMpEng" } },
        { "term": { "EventName": "FileIo/Create" } }
      ],
      "should": [
        { "wildcard": { "XmlEventData.OpenPath.keyword": "*HarddiskVolumeShadowCopy*\\Windows\\System32\\Config\\*" } },
        { "wildcard": { "XmlEventData.FileName.keyword": "*HarddiskVolumeShadowCopy*\\Windows\\System32\\Config\\*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "_source": ["@timestamp","ThreadID","XmlEventData.OpenPath","XmlEventData.FileName",
    "XmlEventData.FileObject","XmlEventData.CreateOptions"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 3. Thread-scoped таймлайн эпизода

```json
GET hopes6/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "ProcessName": "MsMpEng" } },
        { "term": { "ThreadID": 4512 } },
        { "range": { "@timestamp": { "gte": "2026-04-29T17:47:19.780Z", "lte": "2026-04-29T17:47:19.840Z" } } }
      ]
    }
  },
  "_source": ["@timestamp","ProviderName","EventName","ThreadID",
    "XmlEventData.OpenPath","XmlEventData.FileName","XmlEventData.FileObject","XmlEventData.CreateOptions"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 4. Антипример: FileObject уходит в шум

```json
GET hopes6/_search
{
  "size": 50,
  "query": { "term": { "XmlEventData.FileObject.keyword": "0xffff820b39eb5200" } },
  "_source": ["@timestamp","ProcessName","ProviderName","EventName","ThreadID",
    "XmlEventData.OpenPath","XmlEventData.FileObject"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 5. FunnyApp: полная активность PoC в датасете

```json
GET hopes6/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "ProcessName": "FunnyApp" } },
        { "range": { "@timestamp": { "gte": "2026-04-29T17:45:00Z", "lte": "2026-04-29T17:48:00Z" } } }
      ]
    }
  },
  "_source": ["@timestamp","XmlEventData.EventName","XmlEventData.FileName","ThreadID"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 6. FunnyApp: ключевые DLL и cleanup артефакты

```json
GET hopes6/_search
{
  "size": 20,
  "query": {
    "bool": {
      "must": [{"term": {"ProcessName": "FunnyApp"}}],
      "should": [
        { "term": { "XmlEventData.EventName.keyword": "NameCreate" } },
        { "term": { "XmlEventData.EventName.keyword": "FileIo/DletePath" } }
      ],
      "minimum_should_match": 1
    }
  },
  "_source": ["@timestamp","XmlEventData.EventName","XmlEventData.FileName"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

Этот запрос выдаёт полную цепочку от загрузки `offreg.dll` до удаления lock-файла и очистки extracted update files.

## Детектирующая идея

Не «универсальная сигнатура BlueHammer». Это было бы технически слабо. Правильнее говорить про корреляцию последовательности:

1. Необычный непривилегированный процесс загружает `cldapi.dll`, `Cabinet.dll`, `OFFREG.dll`, `ktmw32.dll`, `WININET.dll` в одном запуске
2. Поведение вокруг Defender update workflow (Windows Update API + RPC к `c503f532-443a-4c69-8300-ccd1fbdb3839`)
3. Файловые события по `mpasbase.vdm` в темпе, нетипичном для обычного WD-обновления
4. Доступ к `HarddiskVolumeShadowCopy*\Windows\System32\Config\*` со стороны `MsMpEng`

Это sequence detection, а не single-event detection.

## Что важно проговорить про ограничения

Два близких документа по одному SAM-пути не доказывают источник дублирования. Корректная формулировка: два близких открытия на одном потоке `MsMpEng`.

ETW-телеметрия показывает наблюдаемое поведение, но не доказывает полный внутренний алгоритм Defender. Артефакт и последовательность вокруг него — это уже очень много, но не замена исходному коду Windows.

Раздел про PPL-only ETW — архитектурный фон, а не утверждение о присутствии конкретного провайдера в датасете.

## Итоговая мысль

BlueHammer полезен для blue team не только как «ещё один локальный LPE». Он полезен как напоминание о том, что современная эксплуатация строится на нормальных подсистемах Windows, которые по отдельности выглядят легитимно. Defender, VSS, Cloud Files и Object Manager не обязаны быть «сломаны» по отдельности, чтобы их композиция стала опасной.

Без ETW-видимости защитная команда увидит слишком мало. С ETW, но с неверными ключами корреляции — утонет в `EventId`, `FileObject` и `IrpPtr`. С правильной видимостью — сложная TOCTOU-цепочка раскладывается в осмысленный эпизод: сначала `FunnyApp` загружает `Cabinet.dll` и `OFFREG.dll`, скачивает `mpam-fe[1].exe`, создаёт и удаляет lock-файл; затем `MsMpEng` на потоке 4512 за 60 миллисекунд переходит от `mpasbase.vdm` к прямому открытию SAM из shadow copy.

Именно поэтому ETW — не «nice to have», а реальный инструмент доказательства.

## Репозиторные источники

- [BlueHammer/README.md](../BlueHammer/README.md)
- [BlueHammer/FunnyApp.cpp](../BlueHammer/FunnyApp.cpp)
- [SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml](../SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml)
- [SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md](../SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md)

## Внешние источники

- Connor McGarr, Windows Internals: Check Your Privilege - The Curious Case of ETW's SecurityTrace Flag: https://connormcgarr.github.io/securitytrace-etw-ppl/
- Penligent, BlueHammer and the Windows Defender Race to SYSTEM: https://www.penligent.ai/hackinglabs/bluehammer-and-the-windows-defender-race-to-system/
- BlueHammer PoC repository: https://github.com/Nightmare-Eclipse/BlueHammer
- Microsoft Learn, Microsoft Defender Antivirus updates: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates
- Microsoft Learn, Volume Shadow Copy Service: https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
- Microsoft Learn, CfRegisterSyncRoot: https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfregistersyncroot
- Microsoft Learn, Opportunistic Locks: https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks