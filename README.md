# SilkETW — Fork with System Provider Support and Elasticsearch Export

> [Русская версия](README-ru.md)

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

## Setup

To install dependencies (jq, Docker Desktop) and start the local ELK stack:

```powershell
./Setup-Environment.ps1
```

See [Setup-Environment.ps1](Setup-Environment.ps1) for full parameter documentation.

---

## Repository Layout

```
SilkETW/               ← collector source code (C#)
  ConfigTemplates/     ← ready-made XML profiles
BlueHammer/            ← PoC + FunnyApp source (C++)
Import-NdjsonToElastic/← Elasticsearch import script (PowerShell)
docs/                  ← BlueHammer technical write-up (RU + EN)
docker-elk/            ← ELK stack (git submodule, deviantony/docker-elk)
```

---

## Dependencies

| Package | Version | License |
| --- | --- | --- |
| McMaster.Extensions.CommandLineUtils | 4.x | Apache-2.0 |
| Microsoft.Diagnostics.Tracing.TraceEvent | latest | MIT |
| Newtonsoft.Json | latest | MIT |

See [LICENSE-3RD-PARTY.txt](LICENSE-3RD-PARTY.txt) for details.
