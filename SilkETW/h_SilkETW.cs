using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Spectre.Console;

namespace SilkETW
{
    // Enums
    public enum CollectorType
    {
        None = 0,
        Kernel,
        User,
        // Object Manager events via a system-logger-mode session.
        // Windows 11+  => modern path: EnableTraceEx2 for System Object Provider.
        // Windows 8-10 => legacy fallback: TraceSetInformation with PERF_OB_HANDLE.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
        SystemProvider
    }

    // KernelKeywords must be long to match KernelTraceEventParser.Keywords
    // without truncating values like PMCProfile (0x80000000).
    public enum KernelKeywords : long
    {
        PMCProfile = unchecked((int)0x80000000),
        NonContainer = -16777248,
        None = 0,
        Process = 1,
        Thread = 2,
        ImageLoad = 4,
        ProcessCounters = 8,
        ContextSwitch = 16,
        DeferedProcedureCalls = 32,
        Interrupt = 64,
        SystemCall = 128,
        DiskIO = 256,
        DiskFileIO = 512,
        DiskIOInit = 1024,
        Dispatcher = 2048,
        Memory = 4096,
        MemoryHardFaults = 8192,
        VirtualAlloc = 16384,
        VAMap = 32768,
        NetworkTCPIP = 65536,
        Registry = 131072,
        AdvancedLocalProcedureCalls = 1048576,
        SplitIO = 2097152,
        Handle = 4194304,
        Driver = 8388608,
        OS = 11534432,
        Profile = 16777216,
        Default = 16852751,
        ThreadTime = 16854815,
        FileIO = 33554432,
        FileIOInit = 67108864,
        Verbose = 117702431,
        All = 129236991,
        IOQueue = 268435456,
        ThreadPriority = 536870912,
        ReferenceSet = 1073741824
    }

    public enum UserTraceEventLevel
    {
        Always = 0,
        Critical = 1,
        Error = 2,
        Warning = 3,
        Informational = 4,
        Verbose = 5
    }

    // Event record for JSON serialization
    public struct EventRecordStruct
    {
        public Guid ProviderGuid;
        public string ProviderName;
        public int EventId;
        public string EventName;
        public TraceEventOpcode Opcode;
        public string OpcodeName;
        public DateTime TimeStamp;
        public int ThreadID;
        public int ProcessID;
        public string ProcessName;
        public int PointerSize;
        public int EventDataLength;
        public Dictionary<string, string> XmlEventData;
    }

    // Per-collector configuration parsed from XML
    public struct CollectorParameters
    {
        public Guid CollectorGUID;
        public CollectorType CollectorType;
        public KernelKeywords KernelKeywords;
        public string ProviderName;
        public UserTraceEventLevel UserTraceEventLevel;
        public ulong UserKeywords;
        public HashSet<int> EventIdFilter; // null = no filter

        // SystemProvider-specific fields.
        // SystemProviderGuids: one or more System Provider GUIDs enabled via
        //   EnableTraceEx2 (Win11+) or TraceSetInformation (Win8/10 legacy path).
        // EnableFlags: bitmask passed to TraceSetInformation on the legacy path
        //   (TRACE_INFO_CLASS = TraceSystemTraceEnableFlagsInfo).
        //   Use EVENT_TRACE_FLAG_* / PERF_* values from evntrace.h.
        //   Example: 0x80000040 = PERF_OB_HANDLE for Object Manager tracing.
        // InformationClass: TRACE_INFO_CLASS value for TraceSetInformation.
        //   Default = TraceSystemTraceEnableFlagsInfo (4).
        //   Only used on the legacy Win8/10 path.
        public List<Guid> SystemProviderGuids; // null = not a SystemProvider collector
        public uint EnableFlags;
        public int  InformationClass;
    }

    // Runtime bookkeeping for a running collector
    public class CollectorInstance
    {
        public Guid CollectorGUID;
        public ETWTraceEventSource EventSource;
        public TraceEventSession TraceSession;
        /// <summary>Non-zero for SystemProvider collectors started via native StartTraceW.</summary>
        public ulong NativeTraceHandle;
        public string EventParseSessionName;
    }

    static class SilkUtility
    {
        // Thread-safe lists for running collectors
        public static readonly List<CollectorParameters> CollectorParameterSets = new List<CollectorParameters>();
        public static readonly List<Thread> CollectorThreadList = new List<Thread>();
        public static readonly List<CollectorInstance> CollectorTaskList = new List<CollectorInstance>();
        public static readonly ManualResetEvent SignalThreadStarted = new ManualResetEvent(false);

        // Global event counters (updated from multiple collector threads)
        public static long RunningEventCount;   // all events received from ETW
        public static long FilteredEventCount;  // events that passed the filter and were written

        // Print logo
        public static void PrintLogo()
        {
            AnsiConsole.MarkupLine("[bold red]███████╗██╗██╗   ██╗  ██╗███████╗████████╗██╗    ██╗[/]");
            AnsiConsole.MarkupLine("[bold red]██╔════╝██║██║   ██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║[/]");
            AnsiConsole.MarkupLine("[bold red]███████╗██║██║   █████╔╝ █████╗     ██║   ██║ █╗ ██║[/]");
            AnsiConsole.MarkupLine("[bold red]╚════██║██║██║   ██╔═██╗ ██╔══╝     ██║   ██║███╗██║[/]");
            AnsiConsole.MarkupLine("[bold red]███████║██║█████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝[/]");
            AnsiConsole.MarkupLine("[bold red]╚══════╝╚═╝╚════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝[/]");
            AnsiConsole.MarkupLine("                  [dim]v1.0 — based on SilkETW by @FuzzySec[/]\n");
        }

        // Status message helpers
        public static void WriteInfo(string message)
        {
            AnsiConsole.MarkupLine($"[green][[+]] {Markup.Escape(message)}[/]");
        }

        public static void WriteWarning(string message)
        {
            AnsiConsole.MarkupLine($"[yellow][[*]] {Markup.Escape(message)}[/]");
        }

        public static void WriteError(string message)
        {
            AnsiConsole.MarkupLine($"[red][[!]] {Markup.Escape(message)}[/]");
        }

        // Check if user has specific access to a directory
        public static bool DirectoryHasPermission(string directoryPath, FileSystemRights accessRight)
        {
            bool isInRoleWithAccess = false;

            try
            {
                var di = new DirectoryInfo(directoryPath);
                var acl = di.GetAccessControl();
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));
                var currentUser = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(currentUser);

                foreach (AuthorizationRule rule in rules)
                {
                    var fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & accessRight) > 0)
                    {
                        var ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                            continue;

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            if (fsAccessRule.AccessControlType == AccessControlType.Deny)
                                return false;
                            isInRoleWithAccess = true;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }

            return isInRoleWithAccess;
        }
    }

    /// <summary>
    /// ETW constants used across the project.
    /// </summary>
    static class SilkConstants
    {
        // =====================================================================
        // System Provider GUIDs
        // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
        // =====================================================================

        public static readonly Guid SystemAlpcProviderGuid        = new Guid("fcb9baaf-e529-4980-92e9-ced1a6aadfdf");
        public static readonly Guid SystemConfigProviderGuid      = new Guid("fef3a8b6-318d-4b67-a96a-3b0f6b8f18fe");
        public static readonly Guid SystemCpuProviderGuid         = new Guid("c6c5265f-eae8-4650-aae4-9d48603d8510");
        public static readonly Guid SystemHypervisorProviderGuid  = new Guid("bafa072a-918a-4bed-b622-bc152097098f");
        public static readonly Guid SystemInterruptProviderGuid   = new Guid("d4bbee17-b545-4888-858b-744169015b25");
        public static readonly Guid SystemIoProviderGuid          = new Guid("3d5c43e3-0f1c-4202-b817-174c0070dc79");
        public static readonly Guid SystemIoFilterProviderGuid    = new Guid("fbd09363-9e22-4661-b8bf-e7a34b535b8c");
        public static readonly Guid SystemLockProviderGuid        = new Guid("721ddfd3-dacc-4e1e-b26a-a2cb31d4705a");
        public static readonly Guid SystemMemoryProviderGuid      = new Guid("82958ca9-b6cd-47f8-a3a8-03ae85a4bc24");
        public static readonly Guid SystemObjectProviderGuid      = new Guid("febd7460-3d1d-47eb-af49-c9eeb1e146f2");
        public static readonly Guid SystemPowerProviderGuid       = new Guid("c134884a-32d5-4488-80e5-14ed7abb8269");
        public static readonly Guid SystemProcessProviderGuid     = new Guid("151f55dc-467d-471f-83b5-5f889d46ff66");
        public static readonly Guid SystemProfileProviderGuid     = new Guid("bfeb0324-1cee-496f-a409-2ac2b48a6322");
        public static readonly Guid SystemRegistryProviderGuid    = new Guid("16156bd9-fab4-4cfa-a232-89d1099058e3");
        public static readonly Guid SystemSchedulerProviderGuid   = new Guid("599a2a76-4d91-4910-9ac7-7d33f2e97a6c");
        public static readonly Guid SystemSyscallProviderGuid     = new Guid("434286f7-6f1b-45bb-b37e-95f623046c7c");
        public static readonly Guid SystemTimerProviderGuid       = new Guid("4f061568-e215-499f-ab2e-eda0ae890a5b");

        // =====================================================================
        // EVENT_TRACE_FLAG_* — EnableFlags bitmask values for EVENT_TRACE_PROPERTIES
        // and TraceSetInformation(TraceSystemTraceEnableFlagsInfo).
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        // =====================================================================

        public const uint EventTraceFlagProcess          = 0x00000001;
        public const uint EventTraceFlagThread           = 0x00000002;
        public const uint EventTraceFlagImageLoad        = 0x00000004;
        public const uint EventTraceFlagProcessCounters  = 0x00000008;
        public const uint EventTraceFlagCSwitch          = 0x00000010;
        public const uint EventTraceFlagDpc              = 0x00000020;
        public const uint EventTraceFlagInterrupt        = 0x00000040;
        public const uint EventTraceFlagSystemCall       = 0x00000080;
        public const uint EventTraceFlagDiskIo           = 0x00000100;
        public const uint EventTraceFlagDiskFileIo       = 0x00000200;
        public const uint EventTraceFlagDiskIoInit       = 0x00000400;
        public const uint EventTraceFlagDispatcher       = 0x00000800;
        public const uint EventTraceFlagMemoryPageFaults = 0x00001000;
        public const uint EventTraceFlagMemoryHardFaults = 0x00002000;
        public const uint EventTraceFlagVirtualAlloc     = 0x00004000;
        public const uint EventTraceFlagVaMap            = 0x00008000;
        public const uint EventTraceFlagNetworkTcpIp     = 0x00010000;
        public const uint EventTraceFlagRegistry         = 0x00020000;
        public const uint EventTraceFlagJob              = 0x00080000;
        public const uint EventTraceFlagAlpc             = 0x00100000;
        public const uint EventTraceFlagSplitIo          = 0x00200000;
        public const uint EventTraceFlagDriver           = 0x00800000;
        public const uint EventTraceFlagProfile          = 0x01000000;
        public const uint EventTraceFlagFileIo           = 0x02000000;
        public const uint EventTraceFlagFileIoInit       = 0x04000000;
        public const uint EventTraceFlagNoSysconfig      = 0x10000000;

        // =====================================================================
        // TRACE_QUERY_INFO_CLASS values for TraceSetInformation / TraceQueryInformation.
        // Default for system trace enable-flags is TraceSystemTraceEnableFlagsInfo = 4.
        // Ref: TRACE_QUERY_INFO_CLASS enum, evntrace.h
        // =====================================================================

        public const int TraceSystemTraceEnableFlagsInfo = 4;
    }
}
