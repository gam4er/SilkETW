# BlueHammer: From a Single ETW Artifact to Understanding the Attack

Technical draft for a 20-30 minute talk.

## Where to Start

First, a concrete line from Elasticsearch. Then where it came from. Then why it is so hard to catch without the right telemetry.

The main thesis of this talk is simple: BlueHammer is interesting not because it touches Defender, VSS, or Cloud Files in isolation. It is interesting because it is a good example of a TOCTOU chain where the critical behavior is very hard to see through ordinary user-level telemetry, but can be reconstructed if ETW is collected correctly.

## Artifact One: MsMpEng Opens SAM from a Shadow Copy

Here is a concrete document from the `hopes6` index with `_id = d6F22J0Bg74gBbI902vy`:

| Field | Value |
| --- | --- |
| `@timestamp` | `2026-04-29T17:47:19.820133700Z` |
| `ProcessName` | `MsMpEng` |
| `EventName` | `FileIo/Create` |
| `ThreadID` | `4512` |
| `XmlEventData.OpenPath` | `\Device\HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM` |
| `XmlEventData.FileObject` | `0xffff820b39eb5200` |
| `XmlEventData.CreateOptions` | `18,874,436` |
| `XmlEventData.ShareAccess` | `7` |

This is the key fact of the entire investigation. Windows Defender - `MsMpEng`, running as SYSTEM - opens `SAM` not from the live registry and not from the normal system volume. It opens it from `HarddiskVolumeShadowCopy2`: from a volume shadow copy. In the context of nighttime backup activity, access to a shadow copy would look routine. Here, however, it is a direct consequence of the attack.

There is also a second similar document (`_id = M6F22J0Bg74gBbI902zy`, same path, same `ThreadID`, 4 ms later). The safe interpretation is: two very close opens of the same path on the same thread - either a repeated `open` within the same operation or overlap between two ETW sources.

## Timeline of One Episode: 60 Milliseconds on Thread 4512

If we take a narrow window for `ProcessName = MsMpEng`, `ThreadID = 4512`, and the range `17:47:19.780-17:47:19.840Z`, we get this:

| Time | Event | Path |
| --- | --- | --- |
| `17:47:19.805631` | `FileIo/Create` | `...\Definition Updates\{GUID}\mpengine.dll` |
| `17:47:19.805695` | `FileIo/Create` | `...\Temp\{GUID}\mpengine.dll` |
| `17:47:19.805831` | `FileIo/Create` | `...\Temp\{GUID}\mpasbase.vdm` |
| `17:47:19.805872` | `FileIo/Create` | `...\Temp\{GUID}\mpasbase.vdm` (repeat) |
| `17:47:19.805900` | `FileIo/Create` | same path, different `CreateOptions` |
| `17:47:19.820133` | `FileIo/Create` | **`\Device\HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM`** |
| `17:47:19.822478+` | `FileIo/QueryInfo` | a series of follow-up queries against the same `FileObject` |
| `17:47:19.822822` | `FileIo/Create` | Defender Definition Updates again - after the SAM open |

This is not just a pile of unrelated events. It is a short episode: a transition from the normal Defender update workflow to a direct read of SAM from a shadow copy, on a single thread, within 60 milliseconds.

## FunnyApp in the Same Index: The Attacker's Trace

In `hopes6`, alongside `MsMpEng`, there is another process: `FunnyApp`. That is the PoC. It started at `17:45:06.741Z` and ended at `17:47:25.963Z`. During those two-plus minutes, the dataset recorded **3628 events** from `FunnyApp`.

### FunnyApp Event Structure

| Event Type | Count |
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

The 125 `FileIo/FSControl` events are primarily oplock operations and Cloud Files API activity. The single `NameCreate` event is the loading of `offreg.dll` (Offline Registry).

### Key FunnyApp Events in Chronological Order

| Time | Event | Meaning |
| --- | --- | --- |
| `17:45:06.741` | first FunnyApp event | PoC start |
| `17:45:06.749274` | `NameCreate` -> `offreg.dll` | Offline Registry API loaded |
| `17:45:06.745-...` | 125x `FileIo/FSControl` | oplocks (`RstrtMgr.dll`, Cloud Files) |
| `17:46:52.749206` | `FileIo/DletePath` -> `mpam-fe[1].exe` in `INetCache\IE\...` | WD update binary downloaded through WinINet and placed into IE cache |
| `17:47:18.068935` | `FileIo/DletePath` -> `\Temp\9c83879e-5b1b-4138-9132-49b2c475ee2a` | temp GUID directory deleted (x2) |
| `17:47:19.820133` | **`MsMpEng` opens SAM from a shadow copy** | **critical artifact** |
| `17:47:19.843552` | `FileIo/DletePath` -> `d10afa6a-c9a5-43e5-adb2-6a0115b4a0d0.lock` | Cloud Files FreezeVSS lock file deleted (delete-on-close) |
| `17:47:19.844128` | `FileIo/DletePath` -> `FunnyApp:${3D0CE612-FDEE-43f7-8ACA-957BEC0CCBA0}.SyncRootIdentity` | Cloud Files sync root metadata cleanup |
| `17:47:25.950-963` | `FileIo/DletePath` x4 -> `7d138e84-ffbf-4f4c-baeb-8f80d218774a\{mpengine.dll, mpasdlta.vdm, mpavbase.vdm, mpavdlta.vdm}` | deletion of extracted WD update files |
| `17:47:25.963` | last FunnyApp event | PoC end |

### Characteristic DLLs in FunnyApp FileName Events

| DLL | Role in the attack |
| --- | --- |
| `wuapi.dll`, `wups.dll`, `uusbrain.dll` | Windows Update API (`IUpdateSession` COM flow) |
| `Cabinet.dll` | `FDICreate/FDICopy` for unpacking `mpam-fe.exe` |
| `WININET.dll` | download from `go.microsoft.com/fwlink/?LinkID=121721` |
| `OFFREG.dll` | Offline Registry (`OROpenHiveByHandle`, without SYSTEM or `SeBackupPrivilege`) |
| `cldapi.dll` | Cloud Files API (`CfRegisterSyncRoot`, `CfConnectSyncRoot`) |
| `ktmw32.dll` | Kernel Transaction Manager (`CreateFileTransacted` to protect against cleanup) |

This is not a random set. Each DLL maps to one functional block of the exploit.

## How It Works: Eight Steps of BlueHammer

> **TL;DR**: Windows Defender itself, with SYSTEM privileges, hands you every user's password database. You just ask politely.

The whole thing boils down to three sentences. During signature updates, Windows Defender runs as SYSTEM and opens files from a designated directory. Through an Object Manager symlink chain plus an oplock race, the attacker swaps that path so that WD itself copies SAM out of a volume shadow copy into a user-accessible folder. That is the whole trick.

### Step 1: Finding Updates - CheckForWDUpdates()

Through the `IUpdateSession` COM interface - the CLSID is resolved via `CLSIDFromProgID(L"Microsoft.Update.Session")` - the code looks for a pending Defender definition update in the "Microsoft Defender Antivirus" category. The loop in `wmain` repeats the check every 30 seconds until an update appears. ETW evidence: activity involving `wuapi.dll`, `wups.dll`, and `uusbrain.dll` in the FunnyApp FileIo trace.

### Step 2: Downloading and Unpacking - GetUpdateFiles()

A legitimate update package is downloaded from `go.microsoft.com/fwlink/?LinkID=121721&arch=x64` through WinINet. The file is cached in IE cache as `mpam-fe[1].exe`. ETW confirmation: `FileIo/DletePath` for `mpam-fe[1].exe` in `INetCache\IE\IJ95A16Z\` at `17:46:52.749206`.

`GetCabFileFromBuff()` parses the downloaded EXE's PE headers, finds the `.rsrc` section, and extracts the embedded `.cab`. Unpacking is done through the Cabinet API - `FDICreate/FDICopy` with custom callbacks so the entire flow can operate in memory. ETW: `Cabinet.dll` gets loaded, and temp GUID directories with update files appear.

### Step 3: Creating VSS via EICAR + oplock - TriggerWDForVS()

An EICAR file is created (the string is stored reversed, then restored with `rev()`). `RstrtMgr.dll` is opened with an exclusive batch oplock - that stalls WD long enough for a VSS snapshot to be created. In parallel, `ShadowCopyFinderThread` monitors `\Device` via `NtQueryDirectoryObject`, waiting for a new `HarddiskVolumeShadowCopy` to appear. ETW: the 125 `FileIo/FSControl` events include precisely these oplock requests.

### Step 4: Freezing WD via the Cloud Files API - FreezeVSS()

A sync root is registered with provider name `"IHATEMICROSOFT"` via `CfRegisterSyncRoot`. The `CfCallbackFetchPlaceHolders` callback identifies the WD process PID, creates a placeholder file, and holds WD on another oplock. The result is that WD is frozen while VSS becomes accessible. ETW trace: the UUID-named lock file `d10afa6a-c9a5-43e5-adb2-6a0115b4a0d0.lock`, followed by the loading of `cldapi.dll`.

### Step 5: RPC Update Call + oplock on mpasbase.vdm - wmain

The update path goes through the `WDUpdateDirectory` Object Manager symlink. Calling `Proc42_ServerMpUpdateEngineSignature` on a separate thread forces WD to process updates from the specified directory. `ReadDirectoryChangesW` is then used to catch the moment when WD creates a new definitions folder. A batch oplock is placed on `mpasbase.vdm`; once it fires, we know WD has started reading the file.

### Step 6: Symlink Swap -> SAM

At the moment the oplock fires, the `WDUpdateDirectory` symlink is recreated so that it points to an Object Manager directory. Inside it, a `mpasbase.vdm` symlink is created -> `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM` (lines 3666-3680 in [BlueHammer/FunnyApp.cpp](../BlueHammer/FunnyApp.cpp)). WD keeps going and copies the contents of SAM into `Definition Updates\{GUID}\mpasbase.vdm`. The file is opened through `CreateFileTransacted` - the transaction is there to keep WD from deleting the file during cleanup. ETW confirmation: `FileIo/Create` against `HarddiskVolumeShadowCopy2\Windows\System32\Config\SAM` by `MsMpEng`, `ThreadID 4512`, `17:47:19.820133`.

### Step 7: Credential Theft via Offline Registry - DoSpawnShellAsAllUsers()

The shell-spawning part of the PoC is just a demo. The real attack is credential theft.

- `OROpenHiveByHandle(samfile, &hSAMhive)` - the Offline Registry API parses SAM as an ordinary file, **without SYSTEM, without `SeBackupPrivilege`, and without loading the hive into the live registry**. ETW trace: `NameCreate` for `offreg.dll` at `17:45:06.749274`.
- `GetLSASecretKey()` - extracts the boot key from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}` using the documented permutation of indices.
- `UnprotectPasswordEncryptionKey()` - pulls the encrypted SAM key out of value `F` and decrypts it via AES-128-CBC.
- For each user: `ORGetValue(hkey2, NULL, L"V", ...)` - reads the `V` record, from which fixed offsets are used to extract the username, LM hash, and NT hash.
- `UnprotectNTHash()` removes the AES wrapper, and then `UnproctectPasswordHashDES()` applies DES-ECB with two keys derived from the RID.

### Step 8: NTLM Hashes in the Clear

After that, pass-the-hash, offline cracking, and relay are just technique. `SamiChangePasswordUser` and service creation through `CreateService` are only proof-of-concept. The hashes have already been stolen.

## Now the General Case: Why This Is TOCTOU and Why It Is Hard to Monitor

Time Of Check / Time Of Use vulnerabilities arise when the state of an object can change between the moment it is checked and the moment it is used. On paper, the definition is simple. In practice, the problem is much nastier.

**First difficulty**: in isolation, almost every action looks normal. Defender updates signatures, VSS creates a shadow copy, Cloud Files works with placeholder files, the file subsystem serves oplocks, and the Object Manager opens and closes handles. Each layer, taken separately, looks like ordinary system behavior.

**Second difficulty**: the attacker does not leave behind one obvious IOC. Instead, they create a short window where a privileged component has already opened the right view of the filesystem, while unprivileged code still has time to benefit from it. The detector therefore needs more than one signature; it needs to reconstruct a sequence across multiple telemetry sources.

**Third difficulty**: even when file telemetry exists, it often shows only the "normal" intermediate paths - `mpengine.dll`, `mpasbase.vdm`, temporary files. The critical path may be visible for only a very short time.

## Why ETW Is Necessary in This Case

If the goal is to understand from the source code what the PoC is supposed to do, the source is enough. But if the goal is to prove or disprove exploitation on a real machine, you need observability.

In this project, observability is built by funneling ETW into a single NDJSON stream. BlueHammer crosses several layers: file operations, manifest-based kernel file telemetry, object-manager activity, and correlation across process, thread, path, IRP, and `FileObject`.

The config [SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml](../SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml) enables all of these at once:

- `Kernel` collector for `MSNT_SystemTrace` file I/O
- manifest-based `Microsoft-Windows-Kernel-File`
- `SystemProvider` with Object Provider, Process Provider, Lock Provider, IO Provider, and IO Filter Provider

One critical caveat: in `MSNT_SystemTrace`, `EventId` values are shared between multiple event classes. Correlation therefore has to use `EventName` + `OpcodeName` + provider context, not `EventId` by itself.

## Which ETW Layers Are Involved

**Classic kernel collector** - `FileIo/Create`, `FileIo/FSControl`, `FileIo/RenamePath`, and so on. It gives broad coverage. This is where the main artifact - SAM from a shadow copy - becomes visible.

**Manifest-based Microsoft-Windows-Kernel-File** - richer payload and no ambiguity around `EventId`. Useful for events where the target path matters most, such as `RenamePath` and `SetLinkPath`.

**System Object Provider and neighboring providers** - object and handle lifecycle, plus intersections with process, thread, and image context. On Windows 11+, this goes through the modern System Providers path; for older versions, there is a legacy fallback. Details: [SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md](../SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md).

## A Note on ETW That Ordinary Processes Cannot Access

Some ETW sessions are protected in such a way that an ordinary process - even one with high privileges - still cannot consume them. `SecurityTrace` AutoLogger and `Microsoft-Windows-Threat-Intelligence` are only available at the Antimalware-PPL level. Connor McGarr's article on SecurityTrace is a good reference here.

ETW is not one mechanism but a family of mechanisms with different privilege levels. You cannot honestly tell the audience, "we will just turn on all ETW." No, you will not. Part of it is architecturally protected. In the `hopes6` dataset, the narrative is built around file/object telemetry - that is architectural context, not a claim that the Threat Intelligence provider is present in the index.

## Strong and Weak Signals in hopes6

### Strong Signals

1. `ProcessName = MsMpEng`
2. `EventName = FileIo/Create` (not just `EventId = 64`)
3. `OpenPath` contains `HarddiskVolumeShadowCopy*\Windows\System32\Config\SAM`
4. Correlation on a single `ThreadID` within a short window
5. Neighboring opens of `mpengine.dll` and `mpasbase.vdm` on the same thread

### Weak and Noisy Signals

`FileObject` is a poor global pivot. It quickly produces unrelated noise from other processes. It is useful only inside a narrow episode.

`IrpPtr` is similar. Inside a short episode it helps; across a wider search it mixes unrelated operations together.

`EventId` alone is dangerous. In `MSNT_SystemTrace`, one `EventId` can cover several event classes.

## Practical Elasticsearch Queries

### 1. Two Key SAM Documents

```json
GET hopes6/_search
{
  "query": { "ids": { "values": ["d6F22J0Bg74gBbI902vy", "M6F22J0Bg74gBbI902zy"] } },
  "_source": ["@timestamp","ProcessName","ProviderName","EventName","ThreadID",
    "XmlEventData.OpenPath","XmlEventData.FileObject","XmlEventData.CreateOptions","XmlEventData.ShareAccess"],
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```

### 2. Shadow-Copy Hive Access by MsMpEng

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

### 3. Thread-Scoped Timeline of the Episode

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

### 4. Counterexample: FileObject Turns into Noise

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

### 5. FunnyApp: Full PoC Activity in the Dataset

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

### 6. FunnyApp: Key DLLs and Cleanup Artifacts

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

This query yields the full chain from loading `offreg.dll` to deleting the lock file and cleaning up the extracted update files.

## Detection Idea

Not a "universal BlueHammer signature." That would be technically weak. It is better framed as sequence correlation:

1. An unusual unprivileged process loads `cldapi.dll`, `Cabinet.dll`, `OFFREG.dll`, `ktmw32.dll`, and `WININET.dll` in one run
2. Behavior around the Defender update workflow (Windows Update API + RPC to `c503f532-443a-4c69-8300-ccd1fbdb3839`)
3. File events around `mpasbase.vdm` at a pace that does not look like an ordinary WD update
4. Access to `HarddiskVolumeShadowCopy*\Windows\System32\Config\*` by `MsMpEng`

This is sequence detection, not single-event detection.

## What Must Be Said About the Limitations

Two nearby documents for the same SAM path do not prove the source of duplication. The correct wording is: two very close opens on one `MsMpEng` thread.

ETW telemetry shows observable behavior, but it does not prove the full internal Defender algorithm. The artifact and the sequence around it already tell us a lot, but they are not a substitute for Windows source code.

The PPL-only ETW section is architectural background, not a claim that a specific provider is present in the dataset.

## Final Point

BlueHammer matters to blue teams not only as "one more local LPE." It matters as a reminder that modern exploitation is often built out of normal Windows subsystems that each look legitimate in isolation. Defender, VSS, Cloud Files, and Object Manager do not have to be "broken" individually for their composition to become dangerous.

Without ETW visibility, the defensive team will see too little. With ETW but the wrong correlation keys, the analyst will drown in `EventId`, `FileObject`, and `IrpPtr`. With the right visibility, even a complex TOCTOU chain starts to decompose into a coherent episode: first `FunnyApp` loads `Cabinet.dll` and `OFFREG.dll`, downloads `mpam-fe[1].exe`, creates and deletes the lock file; then `MsMpEng` on thread 4512, within 60 milliseconds, moves from `mpasbase.vdm` to a direct open of SAM from a shadow copy.

That is why ETW is not a "nice to have" here. It is an actual proof mechanism.

## Repository Sources

- [BlueHammer/README.md](../BlueHammer/README.md)
- [BlueHammer/FunnyApp.cpp](../BlueHammer/FunnyApp.cpp)
- [SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml](../SilkETW/ConfigTemplates/SilkETWConfig_BlueHammer_Win11.xml)
- [SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md](../SilkETW/task_for_agent_windows11_system_object_provider_with_legacy_fallback.md)

## External Sources

- Connor McGarr, Windows Internals: Check Your Privilege - The Curious Case of ETW's SecurityTrace Flag: https://connormcgarr.github.io/securitytrace-etw-ppl/
- Penligent, BlueHammer and the Windows Defender Race to SYSTEM: https://www.penligent.ai/hackinglabs/bluehammer-and-the-windows-defender-race-to-system/
- BlueHammer PoC repository: https://github.com/Nightmare-Eclipse/BlueHammer
- Microsoft Learn, Microsoft Defender Antivirus updates: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates
- Microsoft Learn, Volume Shadow Copy Service: https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
- Microsoft Learn, CfRegisterSyncRoot: https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfregistersyncroot
- Microsoft Learn, Opportunistic Locks: https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks