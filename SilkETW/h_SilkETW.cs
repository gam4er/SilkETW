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
        User
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
    }

    // Runtime bookkeeping for a running collector
    public class CollectorInstance
    {
        public Guid CollectorGUID;
        public ETWTraceEventSource EventSource;
        public TraceEventSession TraceSession;
        public string EventParseSessionName;
    }

    static class SilkUtility
    {
        // Thread-safe lists for running collectors
        public static readonly List<CollectorParameters> CollectorParameterSets = new List<CollectorParameters>();
        public static readonly List<Thread> CollectorThreadList = new List<Thread>();
        public static readonly List<CollectorInstance> CollectorTaskList = new List<CollectorInstance>();
        public static readonly ManualResetEvent SignalThreadStarted = new ManualResetEvent(false);

        // Global event counter (updated from multiple collector threads)
        public static long RunningEventCount;

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
}
