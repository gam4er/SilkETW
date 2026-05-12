# SilkETWConfig_Certificates — Provider Reference

## Purpose

Captures the full Windows certificate-services client surface: enrollment, autoenrollment, credential roaming, lifecycle, certificate-policy engine, and the lower-level credential-roaming + cert-services trace channels. Targeted at investigations involving certificate provisioning, enterprise CA enrollment fraud, smartcard/TPM key activity and DPAPI/credential roaming.

Output: `C:\Logs\cert_etw_events.ndjson`. All collectors at `Verbose` with all keywords.

## Provider catalog

| #   | Provider                                                      | GUID / Name                            | Notes                                                 |
| --- | ------------------------------------------------------------- | -------------------------------------- | ----------------------------------------------------- |
| 1   | Certificate Services Client CredentialRoaming Trace           | `EF4109DC-68FC-45AF-B329-CA2825437209` | Lower-level credroam trace                            |
| 2   | Certificate Services Client Trace                             | `F01B7774-7ED7-401E-8088-B576793D7841` | Lower-level certsvc trace                             |
| 3   | Microsoft-Windows-CertificateServicesClient                   | (by name)                              | Core manifested provider                              |
| 4   | Microsoft-Windows-CertificateServicesClient-AutoEnrollment    | (by name)                              | AutoEnrollment service events                         |
| 5   | Microsoft-Windows-CertificateServicesClient-CertEnroll        | (by name)                              | Enrollment via CertEnroll API                         |
| 6   | Microsoft-Windows-CertificateServicesClient-CredentialRoaming | (by name)                              | Roaming user certificates / private keys              |
| 7   | Microsoft-Windows-CertificateServicesClient-Lifecycle-System  | (by name)                              | Machine cert lifecycle                                |
| 8   | Microsoft-Windows-CertificateServicesClient-Lifecycle-User    | (by name)                              | User cert lifecycle                                   |
| 9   | Microsoft-Windows-CertificationAuthorityClient-CertCli        | (by name)                              | CertCli (certreq, ICertRequest) interactions with CA  |
| 10  | Microsoft-Windows-CertPolEng                                  | (by name)                              | Certificate policy engine (chain validation policies) |

## Notes

- Use together with CAPI2 (`5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB`, in `SilkETWConfig_Network_Telemetry`) for full chain-building visibility.
- Lifecycle-System vs Lifecycle-User: same events, different stores (LocalMachine vs CurrentUser). Both included.
- CertEnroll surfaces template selection, request submission, and CA response — high-value for detecting templated abuse (e.g., ESC1/ESC2/ESC3-style misconfig exploitation).

## Operational notes

- Volume: low–medium except during AutoEnrollment cycles.
- Privilege: SilkETW must run elevated.

---

## Russian version / Русская версия

## Назначение

Полный охват клиентской поверхности служб сертификатов Windows: enrollment, autoenrollment, credential roaming, lifecycle, движок политик сертификатов и низкоуровневые трейсы credroam/certsvc. Целевые расследования: provisioning сертификатов, мошеннический enrollment в корпоративном CA, активность ключей smartcard/TPM, DPAPI/credential roaming.

Вывод: `C:\Logs\cert_etw_events.ndjson`. Все коллекторы на `Verbose` со всеми keywords.

## Каталог провайдеров

| #   | Провайдер                                                     | GUID / Имя                             | Примечание                                               |
| --- | ------------------------------------------------------------- | -------------------------------------- | -------------------------------------------------------- |
| 1   | Certificate Services Client CredentialRoaming Trace           | `EF4109DC-68FC-45AF-B329-CA2825437209` | Низкоуровневый credroam-трейс                            |
| 2   | Certificate Services Client Trace                             | `F01B7774-7ED7-401E-8088-B576793D7841` | Низкоуровневый certsvc-трейс                             |
| 3   | Microsoft-Windows-CertificateServicesClient                   | (по имени)                             | Основной manifested-провайдер                            |
| 4   | Microsoft-Windows-CertificateServicesClient-AutoEnrollment    | (по имени)                             | События службы AutoEnrollment                            |
| 5   | Microsoft-Windows-CertificateServicesClient-CertEnroll        | (по имени)                             | Enrollment через CertEnroll API                          |
| 6   | Microsoft-Windows-CertificateServicesClient-CredentialRoaming | (по имени)                             | Роуминг пользовательских сертификатов / приватных ключей |
| 7   | Microsoft-Windows-CertificateServicesClient-Lifecycle-System  | (по имени)                             | Lifecycle сертификатов machine-store                     |
| 8   | Microsoft-Windows-CertificateServicesClient-Lifecycle-User    | (по имени)                             | Lifecycle сертификатов user-store                        |
| 9   | Microsoft-Windows-CertificationAuthorityClient-CertCli        | (по имени)                             | Взаимодействия CertCli (certreq, ICertRequest) с CA      |
| 10  | Microsoft-Windows-CertPolEng                                  | (по имени)                             | Движок политик сертификатов (политики валидации цепочек) |

## Заметки

- Используйте совместно с CAPI2 (`5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB`, в `SilkETWConfig_Network_Telemetry`) для полной видимости построения цепочек.
- Lifecycle-System vs Lifecycle-User: те же события, разные хранилища (LocalMachine vs CurrentUser). Включены оба.
- CertEnroll показывает выбор template, отправку запроса и ответ CA — высокая ценность для обнаружения злоупотреблений template (например, эксплуатации misconfig типа ESC1/ESC2/ESC3).

## Операционные заметки

- Объём: низкий–средний, кроме циклов AutoEnrollment.
- Привилегии: SilkETW должен запускаться с повышенными правами.
