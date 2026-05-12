# SilkETWConfig_Office — Provider Reference

## Purpose

Captures Microsoft Office client telemetry via the manifest-based Office providers and a couple of internal Office subcomponent providers (rendering surface, logging liblet). Targeted at incident response on endpoints where Office is the suspected entry point (macros, add-ins, Protected View bypass, ActiveX abuse).

Output: `C:\Logs\office_etw_events.ndjson`. All collectors at `Verbose` with all keywords.

## Provider catalog

| #   | Provider                | GUID                                   | Notes                                |
| --- | ----------------------- | -------------------------------------- | ------------------------------------ |
| 1   | Microsoft-Office-Events | (resolved by name)                     | Top-level Office telemetry channel   |
| 2   | Microsoft-Office-Word   | (resolved by name)                     | Word UI/document events              |
| 3   | Microsoft-Office-Word2  | (resolved by name)                     | Secondary Word channel               |
| 4   | Microsoft-Office-Word3  | (resolved by name)                     | Tertiary Word channel                |
| 5   | OfficeAirSpace          | `F562BB8E-422D-4B5C-B20E-90D710F7D11C` | Office composition/rendering surface |
| 6   | OfficeLoggingLiblet     | `F50D9315-E17E-43C1-8370-3EDF6CC057BE` | Common Office logging library        |

## Notes

- Office providers are resolved by **name** (not GUID) — they must be registered on the host. Registration happens automatically on Office install.
- `Microsoft-Office-Word{2,3}` are additional Word channels Microsoft enables for finer-grained activity; behaviour may vary by Office build.
- AirSpace and LoggingLiblet are _internal_ Office plumbing — useful when correlating crashes/abuse with Office-specific window/composition activity.

## Operational notes

- Volume: medium when Office is in active use; near-zero otherwise.
- Privilege: SilkETW must run elevated.
- Pair with `SilkETWConfig_Network_Telemetry` to follow data movement out of Office.

---

## Russian version / Русская версия

## Назначение

Сбор клиентской телеметрии Microsoft Office через manifest-провайдеры Office и несколько внутренних подкомпонентных провайдеров (поверхность рендеринга, логирующий liblet). Целевой сценарий — реагирование на инциденты на хостах, где Office — предполагаемая точка входа (макросы, add-ins, обход Protected View, ActiveX).

Вывод: `C:\Logs\office_etw_events.ndjson`. Все коллекторы на `Verbose` со всеми keywords.

## Каталог провайдеров

| #   | Провайдер               | GUID                                   | Примечание                               |
| --- | ----------------------- | -------------------------------------- | ---------------------------------------- |
| 1   | Microsoft-Office-Events | (по имени)                             | Верхнеуровневый канал телеметрии Office  |
| 2   | Microsoft-Office-Word   | (по имени)                             | События UI/документов Word               |
| 3   | Microsoft-Office-Word2  | (по имени)                             | Вторичный канал Word                     |
| 4   | Microsoft-Office-Word3  | (по имени)                             | Третичный канал Word                     |
| 5   | OfficeAirSpace          | `F562BB8E-422D-4B5C-B20E-90D710F7D11C` | Поверхность композиции/рендеринга Office |
| 6   | OfficeLoggingLiblet     | `F50D9315-E17E-43C1-8370-3EDF6CC057BE` | Общая библиотека логирования Office      |

## Заметки

- Провайдеры Office указываются **по имени** (не по GUID) — они должны быть зарегистрированы на хосте. Регистрация происходит автоматически при установке Office.
- `Microsoft-Office-Word{2,3}` — дополнительные каналы Word, которые Microsoft использует для более гранулярной активности; поведение может варьироваться по сборке Office.
- AirSpace и LoggingLiblet — _внутренние_ компоненты Office, полезны для корреляции крэшей/злоупотреблений с активностью композиции/окон Office.

## Операционные заметки

- Объём: средний при активной работе с Office; около нуля в покое.
- Привилегии: SilkETW должен запускаться с повышенными правами.
- Сочетайте с `SilkETWConfig_Network_Telemetry` для отслеживания исходящих данных из Office.
