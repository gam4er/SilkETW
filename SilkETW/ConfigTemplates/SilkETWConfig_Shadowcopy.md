# SilkETWConfig_Shadowcopy — Provider Reference

## Purpose

Shadow-copy (VSS / VolSnap) monitoring profile. Combines a kernel File I/O collector (so reads through `\Device\HarddiskVolumeShadowCopy*` paths surface), four user-mode VSS-related providers (control plane), and the System Object Provider (handle lifecycle) for Win11+/Win8-10 dual-path. Targeted at detecting offline credential theft (e.g. `vssadmin`/`wbadmin`/raw VSS API access to `SAM`/`SYSTEM`/`NTDS.dit`).

Output: `./Logs/shadowcopy_monitor.ndjson`.

## Collector layout

| #   | CollectorType  | Provider / Flags                                                                                                                                                          | Notes                                              |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100664832` (FileIO + FileIOInit + DiskFileIO + DiskIOInit)                                                                                                | Surfaces actual reads via shadow-copy device paths |
| 2   | User           | `67fe2216-727a-40cb-94b2-c02211edb34a` (Microsoft-Windows-VolumeSnapshot-Driver)                                                                                          | VolSnap kernel driver events                       |
| 3   | User           | `6529026f-23d7-4a9e-a4ba-a5265e198365`                                                                                                                                    | VSS-related provider (see comment in source XML)   |
| 4   | User           | `9138500E-3648-4EDB-AA4C-859E9F7B7C38`                                                                                                                                    | VSS-related provider                               |
| 5   | User           | `77D8F687-8130-4A14-B8A6-3B922E05B99C`                                                                                                                                    | VSS-related provider                               |
| 6   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1`, `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040`, `InformationClass=4` | Handle lifecycle, dual-path Win11+/Win8-10         |

## Notes

- The four manifest-named VSS-area providers were curated from the user's environment; verify with `logman query providers` before deploying to a new SKU.
- Reference manifest: `Microsoft-Windows-VolumeSnapshot-Driver_manifest.xml` in this directory.
- For full backup-toolchain coverage you may also want to enable `Microsoft-Windows-Backup` and `Microsoft-Windows-VSS` separately.

## Operational notes

- Volume: low–medium except during active backup/snapshot operations.
- Privilege: must run elevated; system-logger session for the SystemProvider collector.

---

## Russian version / Русская версия

## Назначение

Профиль мониторинга теневых копий (VSS / VolSnap). Сочетает kernel-коллектор File I/O (чтобы видеть чтения через пути `\Device\HarddiskVolumeShadowCopy*`), четыре user-mode провайдера, связанных с VSS (control plane), и System Object Provider (handle lifecycle) с dual-path Win11+/Win8-10. Целевой сценарий: обнаружение оффлайн-кражи credential (например, `vssadmin`/`wbadmin`/raw VSS API доступ к `SAM`/`SYSTEM`/`NTDS.dit`).

Вывод: `./Logs/shadowcopy_monitor.ndjson`.

## Раскладка коллекторов

| #   | CollectorType  | Провайдер / Флаги                                                                                                                                                         | Примечание                                          |
| --- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| 1   | Kernel         | `KernelKeywords=100664832` (FileIO + FileIOInit + DiskFileIO + DiskIOInit)                                                                                                | Видит реальные чтения через пути shadow-copy device |
| 2   | User           | `67fe2216-727a-40cb-94b2-c02211edb34a` (Microsoft-Windows-VolumeSnapshot-Driver)                                                                                          | События ядра VolSnap                                |
| 3   | User           | `6529026f-23d7-4a9e-a4ba-a5265e198365`                                                                                                                                    | VSS-related провайдер                               |
| 4   | User           | `9138500E-3648-4EDB-AA4C-859E9F7B7C38`                                                                                                                                    | VSS-related провайдер                               |
| 5   | User           | `77D8F687-8130-4A14-B8A6-3B922E05B99C`                                                                                                                                    | VSS-related провайдер                               |
| 6   | SystemProvider | `febd7460-3d1d-47eb-af49-c9eeb1e146f2` (System Object Provider), `UserKeywords=0x1`, `OpcodeFilter=32,33,34,38,39`, legacy `EnableFlags=0x80000040`, `InformationClass=4` | Handle lifecycle, dual-path Win11+/Win8-10          |

## Заметки

- Четыре manifest-named провайдера VSS-области подобраны из пользовательского окружения; перед развёртыванием на новой SKU проверяйте `logman query providers`.
- Reference manifest: `Microsoft-Windows-VolumeSnapshot-Driver_manifest.xml` в этом каталоге.
- Для полного покрытия backup-toolchain также можно включить `Microsoft-Windows-Backup` и `Microsoft-Windows-VSS` отдельно.

## Операционные заметки

- Объём: низкий–средний, кроме активных операций backup/snapshot.
- Привилегии: запуск с повышенными правами; system-logger session для SystemProvider-коллектора.
