# Task: добавить в SilkETW fork поддержку object-manager ETW с modern path на Windows 11+ и legacy fallback на более старых ОС

## Цель

Добавить в форк поддержку сбора object-manager ETW-событий с такой логикой:

- **Windows 11+**: использовать **System Object Provider** (`SystemObjectProviderGuid`) через `EnableTraceEx2` в **system logger mode session**.
- **Windows 10 / Windows 8 / Server 2012+**: использовать **legacy fallback** через `TraceSetInformation(..., TraceSystemTraceEnableFlagsInfo, ...)` с флагом `PERF_OB_HANDLE (0x80000040)` после `StartTrace`.

Нужный результат:
- collector умеет включать object-manager telemetry на современных ОС через **System Providers**;
- collector умеет автоматически откатываться на **legacy ObTrace path** на более старых, но поддерживаемых ОС;
- события попадают в существующий NDJSON pipeline без отдельного формата;
- конфигурация делается из XML;
- существующие `Kernel` и `User` collector'ы не ломаются.

---

## Почему это нужно

Нужно поддержать **оба официальных механизма** Microsoft:

### Modern path
Для Windows 11+ Microsoft документирует, что system trace provider events можно включать через `EnableTraceEx2`, а System Providers являются modern-обёрткой над legacy system flags/groups.

Для Object Manager это:
- **System Object Provider**
- GUID: `{febd7460-3d1d-47eb-af49-c9eeb1e146f2}`
- keyword `SYSTEM_OBJECT_KW_HANDLE` соответствует legacy `PERF_OB_HANDLE`

### Legacy path
Для `ObTrace` Microsoft документирует, что object-manager event tracing включается вызовом:
- `TraceSetInformation`
- `InformationClass = TraceSystemTraceEnableFlagsInfo`
- `EnableFlags = PERF_OB_HANDLE (0x80000040)`

И это должно делаться **после `StartTrace`**.

---

## Итоговая логика выбора пути

Нужно реализовать следующую стратегию:

1. Если ОС **Windows 11 или новее**:
   - стартовать **system logger mode session**;
   - попытаться включить **System Object Provider** через `EnableTraceEx2`;
   - если modern enablement не удался, логировать ошибку и **по желанию** можно сделать fallback в legacy path в рамках той же задачи только если это технически безопасно и не ломает архитектуру.  
   Для первой версии fallback по ошибке modern-enable можно **не делать**, если уже есть fallback по версии ОС.

2. Если ОС **ниже Windows 11**, но поддерживает ObTrace:
   - стартовать совместимую kernel/system session;
   - после `StartTrace` вызвать `TraceSetInformation(...TraceSystemTraceEnableFlagsInfo...)` с `PERF_OB_HANDLE = 0x80000040`.

3. Если ОС **ниже Windows 8 / Server 2012**:
   - fail-closed с понятным сообщением, что object-manager tracing этим способом не поддерживается.

---

## Важные ограничения

1. **Нельзя включать System Object Provider в обычной отдельной user session.**
   Для modern system providers нужен именно **system logger mode session**.

2. **Нельзя заменять весь существующий kernel path только modern-путём.**
   Нужен fallback на legacy.

3. **Нельзя ломать существующий NDJSON pipeline.**
   Изменения только в старте/enablement session и provider.

4. **Legacy path — это не отдельный provider GUID.**
   Это именно вызов `TraceSetInformation` с `TraceSystemTraceEnableFlagsInfo` и нужным bitmask.

5. **Не угадывать numeric value `SYSTEM_OBJECT_KW_HANDLE` из головы.**
   Для modern path в первой версии допустимо использовать `MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF`, чтобы включить все keywords provider'а.

---

## Требуемые изменения по файлам

### 1) `h_SilkETW.cs`

#### Добавить новый режим collector'а

Рекомендуется добавить:
- `CollectorType.SystemProvider`

Почему:
- так проще явно отделить обычный user provider, обычный kernel collector и special-case system provider logic.

#### Добавить новые поля в `CollectorParameters`

Добавить как минимум:

- `Guid? SystemProviderGuid`
- `ulong SystemProviderKeywords`
- `UserTraceEventLevel SystemProviderLevel`
- `bool RequireWindows11OrLater`
- `bool EnableLegacyObTraceFallback`

Рекомендуемые значения по умолчанию:
- `SystemProviderKeywords = 0xFFFFFFFFFFFFFFFF`
- `SystemProviderLevel = Verbose`
- `RequireWindows11OrLater = false`  
  Потому что теперь есть fallback.
- `EnableLegacyObTraceFallback = true`

#### Добавить константы

Добавить:

- `SystemObjectProviderGuid = "febd7460-3d1d-47eb-af49-c9eeb1e146f2"`
- `PerfObHandle = 0x80000040`

И, если удобно, константу/enum для:
- `TraceSystemTraceEnableFlagsInfo = 4`

---

### 2) `SilkParameters.cs`

#### Расширить XML-схему

Добавить поддержку нового режима конфигурации, например:

```xml
<ETWCollector>
  <Guid>...</Guid>
  <CollectorType>SystemProvider</CollectorType>
  <ProviderName>febd7460-3d1d-47eb-af49-c9eeb1e146f2</ProviderName>
  <UserTraceEventLevel>Verbose</UserTraceEventLevel>
  <UserKeywords>0xffffffffffffffff</UserKeywords>
  <EventIdFilter>32,33,34,36,37,38,39</EventIdFilter>
</ETWCollector>
```

#### Валидация

Для `CollectorType == SystemProvider`:

- `ProviderName` обязателен;
- GUID должен корректно парситься;
- `UserKeywords` можно default'ить в `0xffffffffffffffff`;
- не запрещать запуск только потому, что ОС ниже Windows 11, потому что теперь есть **legacy fallback**;
- но нужно предупредить в логах/валидации, что:
  - Windows 11+ -> modern provider path
  - older supported OS -> legacy ObTrace path

#### Coexistence

Разрешить:
- один `SystemProvider` collector
- и при этом один обычный `Kernel` collector

Это полезно, потому что object-manager ETW и file I/O ETW часто нужно собирать вместе.

---

### 3) `ETWCollector.cs`

Это основной файл, где нужен redesign старта session и enablement logic.

## Новый execution path для `CollectorType.SystemProvider`

Нужно реализовать один унифицированный path:

- стартовать session корректного типа;
- затем выбрать способ enablement в зависимости от версии ОС.

---

### 3A. Windows 11+ modern path

#### Создание session

Нужно стартовать **system logger mode session**, а не обычную user session.

Требования:
- `EVENT_TRACE_PROPERTIES.LogFileMode` включает `EVENT_TRACE_SYSTEM_LOGGER_MODE`
- `LoggerName` должен быть **private logger name**
- `Wnode.Guid` не должен быть `SystemTraceControlGuid`; нужен новый GUID

#### Включение provider

После `StartTrace` вызвать `EnableTraceEx2` для:
- `ProviderId = SystemObjectProviderGuid`
- `ControlCode = EVENT_CONTROL_CODE_ENABLE_PROVIDER`
- `Level = configured level` (например `Verbose`)
- `MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF`
- `MatchAllKeyword = 0`

#### Потребление событий

Для чтения событий оставить существующий подход:
- `ETWTraceEventSource(sessionName, TraceEventSourceType.Session)`
- `DynamicTraceEventParser.All`

То есть парсер и NDJSON-структуру не менять.

---

### 3B. Legacy fallback path для Windows ниже 11

#### Когда использовать

Использовать, если:
- ОС ниже Windows 11
- но не ниже Windows 8 / Server 2012

#### Как включать

После `StartTrace` вызвать:

- `TraceSetInformation`
- `InformationClass = TraceSystemTraceEnableFlagsInfo`
- передать буфер с `PERF_OB_HANDLE (0x80000040)`

Важные детали:
- вызывать **после** `StartTrace`
- это и есть официальный способ включить `ObTrace`
- minimum supported client для `ObTrace` — Windows 8

#### Session model

Для fallback path можно использовать kernel/system trace session, совместимую с legacy object manager tracing.

Важно:
- не пытаться делать legacy fallback как `EnableProvider` по GUID — это не provider-based path;
- это именно отдельный вызов `TraceSetInformation`.

---

### 3C. Helper-функции

Добавить отдельные helper'ы, например:

- `StartModernSystemProviderSession(...)`
- `EnableModernSystemObjectProvider(...)`
- `EnableLegacyObTraceFallback(...)`
- `IsWindows11OrLater()`
- `IsWindows8OrLater()`

---

### 3D. P/Invoke

Добавить interop для modern path:

- `StartTraceW`
- `EnableTraceEx2`
- `ControlTraceW`

И для legacy path:

- `TraceSetInformation`

Также нужны структуры:
- `EVENT_TRACE_PROPERTIES`
- `WNODE_HEADER`
- `ENABLE_TRACE_PARAMETERS`

Использовать:
- `advapi32.dll`
- `sechost.dll`, если это нужно по текущему таргету/SDK/рантайму

---

### 3E. Обработка ошибок

#### Modern path
Если:
- `StartTraceW` упал
- `EnableTraceEx2` вернул ошибку

то:
- логировать причину;
- collector не должен silently succeed.

#### Legacy fallback
Если:
- `TraceSetInformation` вернул ошибку

то:
- логировать код ошибки;
- не запускать collector как будто всё прошло успешно.

#### Unsupported OS
Если ОС ниже Windows 8:
- fail-closed;
- логировать, что legacy ObTrace minimum — Windows 8 / Server 2012.

---

### 4) `SilkETW.cs`

#### Старт collector'ов

Нужно:
- красиво логировать, какой путь выбран:
  - `SystemProvider (modern Windows 11+ path)`
  - `SystemProvider (legacy ObTrace fallback path)`

#### Stop path

Так как для modern path session будет native-started, cleanup должен поддерживать:
- `ControlTrace(... EVENT_TRACE_CONTROL_STOP ...)`
- освобождение managed/native ресурсов

Если legacy fallback использует ту же session-инфраструктуру, cleanup должен быть единообразным.

---

### 5) `SilkETWConfig_Shadowcopy.xml`

Добавить обновлённый пример.

```xml
<SilkETWConfig>
  <OutputPath>./Logs/object_manager.ndjson</OutputPath>

  <!-- Existing kernel file I/O collector -->
  <ETWCollector>
    <Guid>...</Guid>
    <CollectorType>Kernel</CollectorType>
    <KernelKeywords>100664832</KernelKeywords>
  </ETWCollector>

  <!-- Object Manager collector:
       Windows 11+ => System Object Provider via EnableTraceEx2
       Older supported OS => legacy ObTrace via TraceSetInformation -->
  <ETWCollector>
    <Guid>...</Guid>
    <CollectorType>SystemProvider</CollectorType>
    <ProviderName>febd7460-3d1d-47eb-af49-c9eeb1e146f2</ProviderName>
    <UserTraceEventLevel>Verbose</UserTraceEventLevel>
    <UserKeywords>0xffffffffffffffff</UserKeywords>
    <EventIdFilter>32,33,34,36,37,38,39</EventIdFilter>
  </ETWCollector>
</SilkETWConfig>
```

#### Почему такие EventIdFilter

Полезны:
- `32`, `33` — `CreateHandle`, `CloseHandle`
- `34` — `DuplicateHandle`
- `36`, `37` — `TypeDCStart`, `TypeDCEnd`
- `38`, `39` — `HandleDCStart`, `HandleDCEnd`

---

## Реализационные требования

### ОС-совместимость

Новая логика должна работать так:

- **Windows 11+**
  - modern path через `EnableTraceEx2`

- **Windows 8 / 10 / Server 2012+**
  - legacy fallback через `TraceSetInformation(...TraceSystemTraceEnableFlagsInfo...)`

- **ниже Windows 8**
  - unsupported

### Backward compatibility

- Старые `Kernel` и `User` collector'ы должны продолжать работать как раньше.
- NDJSON-формат не менять.
- `EventIdFilter` оставить совместимым.

### Logging

Добавить понятные сообщения:
- какой путь выбран: modern или legacy fallback;
- какой provider GUID включается;
- для legacy path — что включается `PERF_OB_HANDLE = 0x80000040`;
- какие keywords/level используются;
- stop/cleanup статусы.

### Safety

- Не включать `SystemObjectProviderGuid` в обычной отдельной user session.
- Не подменять существующий `Kernel` collector новым поведением.
- Не убирать legacy path.
- Не использовать “магические числа” без комментирования их источника.

---

## Acceptance criteria

Считать задачу выполненной, если:

1. В проекте есть новый режим `SystemProvider` или эквивалентный отдельный path.
2. На Windows 11+ этот path создаёт **system logger mode session** и включает `SystemObjectProviderGuid` через `EnableTraceEx2`.
3. На Windows 10 / Windows 8 / Server 2012+ этот path использует legacy fallback через `TraceSetInformation(...TraceSystemTraceEnableFlagsInfo...)` и `PERF_OB_HANDLE (0x80000040)`.
4. На Windows ниже 8 collector fail-closed.
5. Старые collector'ы не ломаются.
6. События пишутся в NDJSON без изменения формата.
7. В конфиге есть рабочий пример.
8. `EventIdFilter` можно применять к `32,33,34,36,37,38,39`.
9. В комментариях/README явно описано:
   - modern path для Windows 11+
   - legacy fallback для older supported OS

---

## Документация, на которую надо опираться

### Modern path
1. **System Providers**
   - список system providers
   - `SystemObjectProviderGuid`
   - соответствие `SYSTEM_OBJECT_KW_HANDLE -> PERF_OB_HANDLE`

2. **Configuring and Starting a SystemTraceProvider Session**
   - private logger
   - `EVENT_TRACE_SYSTEM_LOGGER_MODE`
   - `Wnode.Guid != SystemTraceControlGuid`

3. **EnableTraceEx2**
   - modern enablement
   - Windows 11 support для system trace provider events
   - `0xFFFFFFFFFFFFFFFF` для включения всех keywords

### Legacy path
4. **ObTrace**
   - object manager tracing включается через `TraceSetInformation`
   - `TraceSystemTraceEnableFlagsInfo`
   - `PERF_OB_HANDLE (0x80000040)`
   - minimum supported client: Windows 8

5. **TraceSetInformation**
   - вызывать после `StartTrace`
   - общая семантика и коды ошибок

---

## Ссылки на документацию

- System Providers  
  https://learn.microsoft.com/en-us/windows/win32/etw/system-providers

- Configuring and Starting a SystemTraceProvider Session  
  https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session

- EnableTraceEx2  
  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2

- ObTrace  
  https://learn.microsoft.com/en-us/windows/win32/etw/obtrace

- TraceSetInformation  
  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation

---

## Что не делать

- Не оставлять только modern path без fallback.
- Не пытаться включать legacy ObTrace как provider GUID.
- Не включать System Object Provider в обычной отдельной user session.
- Не менять формат NDJSON.
- Не делать silent fallback без логирования выбранного пути.

---

## Желательный результат в коде

После изменений я хочу видеть:

- новый конфиг-режим для object-manager ETW;
- явный modern path для Windows 11+;
- явный legacy fallback для older supported Windows;
- понятные логи выбора режима;
- минимально-инвазивные изменения существующей архитектуры;
- комментарии в коде с отсылкой к Microsoft Learn.
