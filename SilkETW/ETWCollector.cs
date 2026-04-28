using System;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Xml;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace SilkETW
{
    static class ETWCollector
    {
        // =====================================================================
        // Public entry point
        // =====================================================================

        /// <summary>
        /// Starts an ETW trace session for the given collector parameters.
        /// Events are serialized to JSON and written to the shared <paramref name="writer"/>.
        /// This method blocks until the trace is stopped (via Ctrl+C or error).
        /// </summary>
        public static void StartTrace(CollectorParameters collector, NdjsonFileWriter writer)
        {
            if (TraceEventSession.IsElevated() != true)
            {
                SilkUtility.WriteError($"Collector {collector.CollectorGUID}: must be run as Administrator");
                return;
            }

            SilkUtility.WriteInfo($"Collector {collector.CollectorGUID}: starting trace");

            if (collector.CollectorType == CollectorType.SystemProvider)
            {
                StartSystemProviderTrace(collector, writer);
                return;
            }

            // ---- Kernel / User path ----
            string sessionName = collector.CollectorType == CollectorType.Kernel
                ? KernelTraceEventParser.KernelSessionName
                : "SilkETWUserCollector_" + Guid.NewGuid().ToString("N");

            var traceSession = new TraceEventSession(sessionName);
            traceSession.StopOnDispose = true;

            using (var eventSource = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session))
            {
                void TerminateCollector()
                {
                    eventSource.StopProcessing();
                    try { traceSession?.Stop(); } catch { }
                    try { traceSession?.Dispose(); } catch { }
                }

                var eventParser = new DynamicTraceEventParser(eventSource);
                eventParser.All += delegate (TraceEvent data)
                {
                    ProcessEventData(data, collector, writer, TerminateCollector);
                };

                try
                {
                    if (collector.CollectorType == CollectorType.Kernel)
                    {
                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: enabling Kernel provider " +
                            $"keywords=0x{(long)collector.KernelKeywords:X}");

                        traceSession.EnableKernelProvider(
                            (KernelTraceEventParser.Keywords)collector.KernelKeywords);

                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: Kernel provider enable succeeded");

                        // Optional: kernel call-stack tracing for classic kernel events.
                        // Enabled via <EnableStackTracing>true</EnableStackTracing> in config.
                        if (collector.EnableStackTracing)
                        {
                            ulong handle = GetManagedSessionHandle(traceSession);
                            EnableStackTracingForSession(handle, collector.CollectorGUID);
                        }
                    }
                    else
                    {
                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: enabling User provider " +
                            $"name={collector.ProviderName} " +
                            $"level={(byte)collector.UserTraceEventLevel} " +
                            $"keywords=0x{collector.UserKeywords:X16}");

                        traceSession.EnableProvider(
                            collector.ProviderName,
                            (TraceEventLevel)collector.UserTraceEventLevel,
                            collector.UserKeywords);

                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: User provider enable succeeded");

                        // Optional: binary-path tracking for User (manifest-based) providers.
                        // Emits EventTraceGuid/opcode=0x43 events mapping provider GUIDs to
                        // the DLL/EXE path of the ETW callback — useful for threat hunting.
                        // Enabled via <EnableProviderBinaryTracking>true</EnableProviderBinaryTracking>.
                        if (collector.EnableProviderBinaryTracking)
                        {
                            ulong handle = GetManagedSessionHandle(traceSession);
                            EnableProviderBinaryTrackingForSession(handle, collector.CollectorGUID);
                        }
                    }
                }
                catch (Exception ex)
                {
                    SilkUtility.WriteError(
                        $"Collector {collector.CollectorGUID}: provider enable failed: {ex.Message}");
                    return;
                }

                var instance = new CollectorInstance
                {
                    CollectorGUID         = collector.CollectorGUID,
                    EventSource           = eventSource,
                    TraceSession          = traceSession,
                    NativeTraceHandle     = 0,
                    EventParseSessionName = sessionName
                };
                lock (SilkUtility.CollectorTaskList)
                    SilkUtility.CollectorTaskList.Add(instance);

                SilkUtility.SignalThreadStarted.Set();
                eventSource.Process();
            }
        }

        // =====================================================================
        // SystemProvider path
        // =====================================================================

        /// <summary>
        /// Starts a system-logger-mode ETW session for Object Manager tracing.
        ///
        /// OS routing:
        ///   Windows 11+ (build >= 22000) — modern path:
        ///     StartTraceW with EVENT_TRACE_SYSTEM_LOGGER_MODE, then EnableTraceEx2
        ///     for the configured provider GUID (e.g. System Object Provider).
        ///     Ref: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
        ///     Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
        ///
        ///   Windows 8 / 10 / Server 2012+ — legacy fallback:
        ///     StartTraceW with EVENT_TRACE_SYSTEM_LOGGER_MODE, then
        ///     TraceSetInformation(TraceSystemTraceEnableFlagsInfo, PERF_OB_HANDLE).
        ///     Ref: https://learn.microsoft.com/en-us/windows/win32/etw/obtrace
        ///
        ///   Below Windows 8 — unsupported, fail-closed.
        /// </summary>
        private static void StartSystemProviderTrace(CollectorParameters collector, NdjsonFileWriter writer)
        {
            // --- OS check ---
            // Legacy path minimum: Windows 8 / Server 2012.
            // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/obtrace
            if (!IsWindows8OrLater())
            {
                SilkUtility.WriteError(
                    $"Collector {collector.CollectorGUID}: SystemProvider requires " +
                    "Windows 8 / Windows Server 2012 or later.");
                return;
            }

            // Validated by SilkParameters — guard defensively.
            List<SystemProviderSettings> systemProviders = GetEffectiveSystemProviders(collector);
            if (systemProviders == null || systemProviders.Count == 0)
            {
                SilkUtility.WriteError(
                    $"Collector {collector.CollectorGUID}: SystemProvider has no provider GUIDs");
                return;
            }

            bool   isWin11   = IsWindows11OrLater();
            var    osVersion = GetWindowsVersion();
            string pathLabel = isWin11
                ? "modern Windows 11+ path (EnableTraceEx2)"
                : $"legacy fallback path (TraceSetInformation InformationClass={collector.InformationClass} EnableFlags=0x{collector.EnableFlags:X8})";

            SilkUtility.WriteInfo(
                $"Collector {collector.CollectorGUID}: SystemProvider OS build " +
                $"{osVersion.Major}.{osVersion.Minor}.{osVersion.Build} — {pathLabel}");

            string sessionName  = SilkConstants.SystemProviderSessionName;
            ulong  nativeHandle = 0;

            // --- Start system-logger-mode session via native P/Invoke ---
            // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
            if (!StartNativeSystemLoggerSession(sessionName, collector.CollectorGUID, out nativeHandle))
                return;   // error already logged

            try
            {
                // --- Enable provider(s) or set legacy flags ---
                bool enabled;
                if (isWin11)
                {
                    // Modern path: EnableTraceEx2 for every configured provider GUID.
                    // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
                    enabled = true;
                    var enabledProviders = new List<Guid>();
                    var failedProviders = new List<Guid>();

                    foreach (SystemProviderSettings provider in systemProviders)
                    {
                        ulong keywords = provider.UserKeywords.HasValue
                            ? provider.UserKeywords.Value
                            : collector.UserKeywords;

                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: " +
                            $"EnableTraceEx2 guid={provider.ProviderGuid} " +
                            $"level={(byte)collector.UserTraceEventLevel} " +
                            $"keywords=0x{keywords:X16}");

                        bool guidEnabled = EnableModernSystemObjectProvider(
                            nativeHandle,
                            provider.ProviderGuid,
                            (byte)collector.UserTraceEventLevel,
                            keywords,
                            collector.CollectorGUID);

                        if (!guidEnabled)
                        {
                            failedProviders.Add(provider.ProviderGuid);
                            enabled = false;   // log and continue; partial failure is reported
                        }
                        else
                        {
                            enabledProviders.Add(provider.ProviderGuid);
                        }
                    }

                    if (enabledProviders.Count > 0)
                    {
                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: enabled provider GUID(s): " +
                            string.Join(", ", enabledProviders));
                    }

                    if (failedProviders.Count > 0)
                    {
                        SilkUtility.WriteError(
                            $"Collector {collector.CollectorGUID}: failed provider GUID(s): " +
                            string.Join(", ", failedProviders));
                    }
                }
                else
                {
                    // Legacy path: TraceSetInformation with the configured EnableFlags bitmask.
                    // Must be called after StartTrace.
                    // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
                    SilkUtility.WriteInfo(
                        $"Collector {collector.CollectorGUID}: " +
                        $"TraceSetInformation InformationClass={collector.InformationClass} " +
                        $"EnableFlags=0x{collector.EnableFlags:X8}");

                    bool hasPerProviderKeywordOverride = false;
                    bool hasPerProviderEventFilters = false;
                    foreach (SystemProviderSettings provider in systemProviders)
                    {
                        if (provider.UserKeywords.HasValue)
                            hasPerProviderKeywordOverride = true;

                        if ((provider.EventIdFilter != null && provider.EventIdFilter.Count > 0) ||
                            (provider.OpcodeFilter != null && provider.OpcodeFilter.Count > 0) ||
                            (provider.EventNameFilter != null && provider.EventNameFilter.Count > 0) ||
                            (provider.EventNamePrefixFilter != null && provider.EventNamePrefixFilter.Count > 0))
                        {
                            hasPerProviderEventFilters = true;
                        }
                    }

                    if (hasPerProviderKeywordOverride)
                    {
                        SilkUtility.WriteWarning(
                            $"Collector {collector.CollectorGUID}: per-provider UserKeywords are ignored on legacy Win8/10 path; collector UserKeywords/EnableFlags are used instead");
                    }

                    if (hasPerProviderEventFilters)
                    {
                        SilkUtility.WriteWarning(
                            $"Collector {collector.CollectorGUID}: per-provider EventName/Opcode/EventId filters are evaluated after event capture and do not change legacy provider enablement");
                    }

                    enabled = EnableLegacySystemProviderFallback(
                        nativeHandle,
                        collector.EnableFlags,
                        collector.InformationClass,
                        collector.CollectorGUID);

                    if (enabled)
                    {
                        SilkUtility.WriteInfo(
                            $"Collector {collector.CollectorGUID}: legacy enable succeeded for configured provider GUID(s): " +
                            string.Join(", ", collector.SystemProviderGuids));
                    }
                    else
                    {
                        SilkUtility.WriteError(
                            $"Collector {collector.CollectorGUID}: legacy enable failed for configured provider GUID(s): " +
                            string.Join(", ", collector.SystemProviderGuids));
                    }
                }

                if (!enabled)
                {
                    SilkUtility.WriteError(
                        $"Collector {collector.CollectorGUID}: " +
                        "one or more providers failed to enable — check previous errors");
                    return;
                }

                // --- Consume events via standard ETWTraceEventSource pipeline ---
                using (var eventSource = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session))
                {
                    void TerminateCollector()
                    {
                        eventSource.StopProcessing();
                        if (nativeHandle != 0)
                        {
                            StopNativeSession(nativeHandle, sessionName, collector.CollectorGUID);
                            nativeHandle = 0;
                        }
                    }

                    var eventParser = new DynamicTraceEventParser(eventSource);
                    eventParser.All += delegate (TraceEvent data)
                    {
                        ProcessEventData(data, collector, writer, TerminateCollector);
                    };

                    var instance = new CollectorInstance
                    {
                        CollectorGUID         = collector.CollectorGUID,
                        EventSource           = eventSource,
                        TraceSession          = null,           // native session, no managed wrapper
                        NativeTraceHandle     = nativeHandle,
                        EventParseSessionName = sessionName
                    };
                    lock (SilkUtility.CollectorTaskList)
                        SilkUtility.CollectorTaskList.Add(instance);

                    SilkUtility.SignalThreadStarted.Set();
                    eventSource.Process();
                }
            }
            finally
            {
                // Ensure native session is stopped even if an exception escapes.
                if (nativeHandle != 0)
                    StopNativeSession(nativeHandle, sessionName, collector.CollectorGUID);
            }
        }

        // =====================================================================
        // Shared event-processing helper
        // =====================================================================

        /// <summary>
        /// Builds an <see cref="EventRecordStruct"/>, applies the EventIdFilter,
        /// serialises to NDJSON and enqueues it. Called from every collector path.
        /// </summary>
        private static void ProcessEventData(
            TraceEvent data,
            CollectorParameters collector,
            NdjsonFileWriter writer,
            Action onWriteFailed)
        {
            // For classic/WMI providers data.ID is 0xFFFF (TraceEventID.Illegal);
            // the real event type for those providers is encoded in Opcode.
            int resolvedEventId = (ushort)data.ID == 0xFFFF
                ? (int)data.Opcode
                : (int)data.ID;

            var eRecord = new EventRecordStruct
            {
                ProviderGuid    = data.ProviderGuid,
                ProviderName    = data.ProviderName,
                EventId         = resolvedEventId,
                EventName       = data.EventName,
                Opcode          = data.Opcode,
                OpcodeName      = data.OpcodeName,
                TimeStamp       = data.TimeStamp,
                ThreadID        = data.ThreadID,
                ProcessID       = data.ProcessID,
                ProcessName     = data.ProcessName,
                PointerSize     = data.PointerSize,
                EventDataLength = data.EventDataLength
            };

            if (string.IsNullOrEmpty(eRecord.ProcessName))
            {
                try   { eRecord.ProcessName = Process.GetProcessById(eRecord.ProcessID).ProcessName; }
                catch { eRecord.ProcessName = "N/A"; }
            }

            var eventProperties = new Dictionary<string, string>();
            try
            {
                using (var stringReader = new StringReader(data.ToString()))
                {
                    var settings = new XmlReaderSettings
                    {
                        ConformanceLevel = ConformanceLevel.Fragment,
                        DtdProcessing    = DtdProcessing.Prohibit
                    };
                    using (var xmlReader = XmlReader.Create(stringReader, settings))
                    {
                        while (xmlReader.Read())
                        {
                            for (int i = 0; i < xmlReader.AttributeCount; i++)
                            {
                                xmlReader.MoveToAttribute(i);
                                string attrName  = xmlReader.Name;
                                string attrValue = xmlReader.Value;

                                if (attrValue.Length > 10000)
                                    attrValue = attrValue.Substring(0, 10000);

                                if (!eventProperties.ContainsKey(attrName))
                                    eventProperties[attrName] = attrValue;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                eventProperties["XmlEventParsing"]      = "false";
                eventProperties["XmlEventParsingError"] = ex.Message;
            }
            eRecord.XmlEventData = eventProperties;

            // Count every event received from ETW, regardless of filtering.
            Interlocked.Increment(ref SilkUtility.RunningEventCount);
            SilkUtility.IncrementCollectorAccepted(collector.CollectorGUID);

            if (collector.EventIdFilter != null &&
                collector.CollectorType != CollectorType.SystemProvider &&
                !collector.EventIdFilter.Contains(resolvedEventId))
            {
                SilkUtility.IncrementCollectorFilteredOut(collector.CollectorGUID);
                return;
            }

            if (collector.CollectorType == CollectorType.SystemProvider &&
                !ShouldIncludeSystemProviderEvent(data, resolvedEventId, collector))
            {
                SilkUtility.IncrementCollectorFilteredOut(collector.CollectorGUID);
                return;
            }

            string jsonLine = Newtonsoft.Json.JsonConvert.SerializeObject(
                eRecord, Newtonsoft.Json.Formatting.None);

            if (!writer.Enqueue(jsonLine))
            {
                SilkUtility.WriteError(
                    $"Collector {collector.CollectorGUID}: failed to enqueue event (writer stopped)");
                SilkUtility.IncrementCollectorLost(collector.CollectorGUID);
                onWriteFailed();
                return;
            }

            // Count events that actually passed the filter and were written.
            Interlocked.Increment(ref SilkUtility.FilteredEventCount);
            SilkUtility.IncrementCollectorWritten(collector.CollectorGUID);
        }

        private static List<SystemProviderSettings> GetEffectiveSystemProviders(CollectorParameters collector)
        {
            if (collector.SystemProviders != null && collector.SystemProviders.Count > 0)
                return collector.SystemProviders;

            if (collector.SystemProviderGuids == null || collector.SystemProviderGuids.Count == 0)
                return null;

            var providers = new List<SystemProviderSettings>();
            foreach (Guid guid in collector.SystemProviderGuids)
            {
                providers.Add(new SystemProviderSettings
                {
                    ProviderGuid = guid
                });
            }

            return providers;
        }

        private static bool ShouldIncludeSystemProviderEvent(
            TraceEvent data,
            int resolvedEventId,
            CollectorParameters collector)
        {
            List<SystemProviderSettings> providers = GetEffectiveSystemProviders(collector);
            if (providers == null || providers.Count == 0)
                return true;

            bool hasProviderLevelFilters = false;
            foreach (SystemProviderSettings provider in providers)
            {
                if (HasProviderLevelFilters(provider))
                {
                    hasProviderLevelFilters = true;
                    break;
                }
            }

            if (hasProviderLevelFilters)
            {
                foreach (SystemProviderSettings provider in providers)
                {
                    if (!HasProviderLevelFilters(provider))
                        continue;

                    if (MatchesProviderLevelFilters(provider, data, resolvedEventId))
                        return true;
                }

                return false;
            }

            if (collector.EventIdFilter != null)
                return collector.EventIdFilter.Contains(resolvedEventId);

            return true;
        }

        private static bool HasProviderLevelFilters(SystemProviderSettings provider)
        {
            return (provider.EventIdFilter != null && provider.EventIdFilter.Count > 0) ||
                   (provider.OpcodeFilter != null && provider.OpcodeFilter.Count > 0) ||
                   (provider.EventNameFilter != null && provider.EventNameFilter.Count > 0) ||
                   (provider.EventNamePrefixFilter != null && provider.EventNamePrefixFilter.Count > 0);
        }

        private static bool MatchesProviderLevelFilters(
            SystemProviderSettings provider,
            TraceEvent data,
            int resolvedEventId)
        {
            if (provider.EventIdFilter != null &&
                provider.EventIdFilter.Count > 0 &&
                !provider.EventIdFilter.Contains(resolvedEventId))
            {
                return false;
            }

            int opcode = (int)data.Opcode;
            if (provider.OpcodeFilter != null &&
                provider.OpcodeFilter.Count > 0 &&
                !provider.OpcodeFilter.Contains(opcode))
            {
                return false;
            }

            if (provider.EventNameFilter != null &&
                provider.EventNameFilter.Count > 0)
            {
                string eventName = data.EventName ?? string.Empty;
                if (!provider.EventNameFilter.Contains(eventName))
                    return false;
            }

            if (provider.EventNamePrefixFilter != null &&
                provider.EventNamePrefixFilter.Count > 0)
            {
                string eventName = data.EventName ?? string.Empty;
                bool prefixMatched = false;
                foreach (string prefix in provider.EventNamePrefixFilter)
                {
                    if (eventName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        prefixMatched = true;
                        break;
                    }
                }

                if (!prefixMatched)
                    return false;
            }

            return true;
        }

        // =====================================================================
        // OS version helpers
        // =====================================================================

        /// <summary>Returns true for Windows 11+ (build >= 22000).</summary>
        private static bool IsWindows11OrLater()
        {
            var v = GetWindowsVersion();
            return v.Major == 10 && v.Build >= 22000;
        }

        /// <summary>
        /// Returns true for Windows 8 / Server 2012 and later.
        /// ObTrace minimum supported client is Windows 8 (NT 6.2).
        /// Ref: https://learn.microsoft.com/en-us/windows/win32/etw/obtrace
        /// </summary>
        private static bool IsWindows8OrLater()
        {
            var v = GetWindowsVersion();
            return (v.Major == 6 && v.Minor >= 2) || v.Major >= 10;
        }

        private static (uint Major, uint Minor, uint Build) GetWindowsVersion()
        {
            var info = new OSVERSIONINFOEX
            {
                OSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEX))
            };
            RtlGetVersion(ref info);
            return (info.MajorVersion, info.MinorVersion, info.BuildNumber);
        }

        // =====================================================================
        // Native session helpers
        // =====================================================================

        /// <summary>
        /// Starts a real-time ETW session with EVENT_TRACE_SYSTEM_LOGGER_MODE.
        /// Required for both modern (EnableTraceEx2) and legacy (TraceSetInformation) paths.
        /// Ref: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
        /// </summary>
        private static bool StartNativeSystemLoggerSession(
            string  sessionName,
            Guid    collectorGuid,
            out     ulong traceHandle)
        {
            traceHandle = 0;

            int    propSize  = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
            int    nameBytes = (sessionName.Length + 1) * sizeof(char);  // Unicode + null
            int    totalSize = propSize + nameBytes;
            IntPtr buffer    = Marshal.AllocHGlobal(totalSize);
            try
            {
                ZeroBuffer(buffer, totalSize);

                var props = new EVENT_TRACE_PROPERTIES();
                props.Wnode.BufferSize = (uint)totalSize;
                // New unique GUID — must NOT be SystemTraceControlGuid.
                // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
                props.Wnode.Guid       = Guid.NewGuid();
                props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
                // Real-time delivery + system logger mode (required for system providers).
                // EVENT_TRACE_SYSTEM_LOGGER_MODE minimum: Windows 8 / Server 2012.
                props.LogFileMode      = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
                props.MinimumBuffers   = 4;
                props.MaximumBuffers   = 64;
                props.BufferSize       = 64;     // 64 KB per buffer
                props.LoggerNameOffset = (uint)propSize;

                Marshal.StructureToPtr(props, buffer, false);

                // Write session name after the struct (Unicode, no log file name needed).
                IntPtr namePtr = new IntPtr(buffer.ToInt64() + propSize);
                for (int i = 0; i < sessionName.Length; i++)
                    Marshal.WriteInt16(namePtr, i * 2, sessionName[i]);
                // Null terminator is already zero from ZeroBuffer.

                uint status = StartTraceW(out traceHandle, sessionName, buffer);
                if (status == 0)
                {
                    SilkUtility.WriteInfo(
                        $"Collector {collectorGuid}: " +
                        $"native system-logger session started (handle=0x{traceHandle:X})");
                    return true;
                }

                SilkUtility.WriteError(
                    $"Collector {collectorGuid}: StartTraceW failed — " +
                    $"error 0x{status:X8} ({status})");
                traceHandle = 0;
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Enables a provider on the session via EnableTraceEx2 (Windows 11+ modern path).
        /// Ref: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
        /// Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
        /// </summary>
        private static bool EnableModernSystemObjectProvider(
            ulong traceHandle,
            Guid  providerGuid,
            byte  level,
            ulong matchAnyKeyword,
            Guid  collectorGuid)
        {
            uint status = EnableTraceEx2(
                traceHandle,
                ref providerGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                level,
                matchAnyKeyword,
                0,           // MatchAllKeyword = 0 (no additional restriction)
                0,           // Timeout = 0 (async, non-blocking)
                IntPtr.Zero  // No filter parameters
            );

            if (status == 0)
            {
                SilkUtility.WriteInfo(
                    $"Collector {collectorGuid}: provider enabled via EnableTraceEx2");
                return true;
            }

            SilkUtility.WriteError(
                $"Collector {collectorGuid}: EnableTraceEx2 failed — " +
                $"error 0x{status:X8} ({status})");
            return false;
        }

        /// <summary>
        /// Enables system trace events via TraceSetInformation (legacy Win8/10 path).
        /// The <paramref name="enableFlags"/> bitmask is the ULONG payload written to the
        /// TraceInformation buffer; its meaning depends on <paramref name="informationClass"/>.
        /// For TraceSystemTraceEnableFlagsInfo (class=4) it is an EVENT_TRACE_FLAG_* / PERF_*
        /// bitmask (e.g. 0x80000040 = PERF_OB_HANDLE for Object Manager tracing).
        /// Must be called AFTER StartTraceW.
        /// Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
        /// </summary>
        private static bool EnableLegacySystemProviderFallback(
            ulong traceHandle,
            uint  enableFlags,
            int   informationClass,
            Guid  collectorGuid)
        {
            // The buffer for TraceSystemTraceEnableFlagsInfo is a single ULONG bitmask.
            IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
            try
            {
                Marshal.WriteInt32(buffer, unchecked((int)enableFlags));

                uint status = TraceSetInformation(
                    traceHandle,
                    informationClass,
                    buffer,
                    sizeof(uint));

                if (status == 0)
                {
                    SilkUtility.WriteInfo(
                        $"Collector {collectorGuid}: " +
                        $"TraceSetInformation (class={informationClass} " +
                        $"flags=0x{enableFlags:X8}) succeeded");
                    return true;
                }

                SilkUtility.WriteError(
                    $"Collector {collectorGuid}: " +
                    $"TraceSetInformation (class={informationClass} " +
                    $"flags=0x{enableFlags:X8}) failed — " +
                    $"error 0x{status:X8} ({status})");
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Retrieves the native trace handle from a managed <see cref="TraceEventSession"/>
        /// via reflection. The field/property name varies across TraceEvent library versions;
        /// the method tries several known names and falls back to 0 on failure.
        /// </summary>
        private static ulong GetManagedSessionHandle(TraceEventSession session)
        {
            const BindingFlags flags =
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public;
            Type t = session.GetType();

            // TraceEvent 3.x stores the handle in m_SessionHandle (ulong or TraceHandle struct).
            foreach (string name in new[] { "m_SessionHandle", "m_Handle", "sessionHandle" })
            {
                FieldInfo f = t.GetField(name, flags);
                if (f == null) continue;
                object val = f.GetValue(session);
                if (val is ulong u && u != 0) return u;
                if (val is long  l && l  > 0) return (ulong)l;
                // If it is a struct (TraceHandle) try its Value property.
                if (val != null)
                {
                    PropertyInfo vp = val.GetType().GetProperty("Value", flags);
                    if (vp != null)
                    {
                        object v = vp.GetValue(val);
                        if (v is ulong u2 && u2 != 0) return u2;
                    }
                }
            }

            // Some versions expose a public property.
            foreach (string name in new[] { "SessionHandle", "Handle" })
            {
                PropertyInfo p = t.GetProperty(name, flags);
                if (p == null) continue;
                object val = p.GetValue(session);
                if (val is ulong u && u != 0) return u;
                if (val is long  l && l  > 0) return (ulong)l;
                if (val != null)
                {
                    PropertyInfo vp = val.GetType().GetProperty("Value", flags);
                    if (vp != null)
                    {
                        object v = vp.GetValue(val);
                        if (v is ulong u2 && u2 != 0) return u2;
                    }
                }
            }

            return 0;
        }

        /// <summary>
        /// Enables binary-path provider tracking for the session.
        /// ETW will emit events (EventTraceGuid, opcode 0x43) that map each enabled
        /// provider GUID to the full path of the DLL/EXE containing its callback.
        /// Useful for detecting rogue or hijacked ETW providers in threat hunting.
        ///
        /// Only meaningful for User-mode (manifest-based) collectors.
        /// Requires Windows 10 version 1709 (build 16299) or later.
        /// Ref: TRACE_QUERY_INFO_CLASS.TraceProviderBinaryTracking (18)
        /// </summary>
        private static void EnableProviderBinaryTrackingForSession(
            ulong traceHandle,
            Guid  collectorGuid)
        {
            if (traceHandle == 0)
            {
                SilkUtility.WriteWarning(
                    $"Collector {collectorGuid}: binary tracking skipped — could not obtain native session handle");
                return;
            }

            // TraceProviderBinaryTracking requires Win10 1709+ (build 16299).
            var os = GetWindowsVersion();
            if (!(os.Major >= 10 && os.Build >= 16299))
            {
                SilkUtility.WriteWarning(
                    $"Collector {collectorGuid}: binary tracking requires Windows 10 1709+ (build 16299); " +
                    $"current build {os.Build} — skipped");
                return;
            }

            IntPtr buf = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(buf, 0, 1); // BOOLEAN TRUE
                uint status = TraceSetInformation(
                    traceHandle,
                    SilkConstants.TraceProviderBinaryTracking,
                    buf,
                    1);

                if (status == 0)
                    SilkUtility.WriteInfo(
                        $"Collector {collectorGuid}: provider binary tracking enabled " +
                        "(EventTraceGuid/opcode=0x43 events will appear in NDJSON)");
                else
                    SilkUtility.WriteWarning(
                        $"Collector {collectorGuid}: TraceSetInformation(BinaryTracking) " +
                        $"returned 0x{status:X8} ({status})");
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        /// <summary>
        /// Enables kernel call-stack capture for a predefined set of classic kernel events.
        /// Stack-walk events (provider StackWalk, opcode 32) arrive as separate records in
        /// the event stream and are automatically written to NDJSON with Stack1…StackN fields
        /// containing raw frame addresses (offline symbolication with PDB/symbols required).
        ///
        /// Only meaningful for Kernel collectors (classic/WMI kernel events).
        /// Ref: TRACE_QUERY_INFO_CLASS.TraceStackTracingInfo (3)
        /// </summary>
        private static void EnableStackTracingForSession(
            ulong traceHandle,
            Guid  collectorGuid)
        {
            if (traceHandle == 0)
            {
                SilkUtility.WriteWarning(
                    $"Collector {collectorGuid}: stack tracing skipped — could not obtain native session handle");
                return;
            }

            CLASSIC_EVENT_ID[] events  = DefaultStackTraceEvents;
            int                count   = events.Length;
            int                itemSz  = Marshal.SizeOf(typeof(CLASSIC_EVENT_ID));
            int                bufSize = count * itemSz;
            IntPtr             buf     = Marshal.AllocHGlobal(bufSize);
            try
            {
                for (int i = 0; i < count; i++)
                    Marshal.StructureToPtr(events[i], new IntPtr(buf.ToInt64() + i * itemSz), false);

                uint status = TraceSetInformation(
                    traceHandle,
                    SilkConstants.TraceStackTracingInfo,
                    buf,
                    (uint)bufSize);

                if (status == 0)
                    SilkUtility.WriteInfo(
                        $"Collector {collectorGuid}: kernel stack tracing enabled for " +
                        $"{count} classic event(s) — StackWalk records will appear in NDJSON");
                else
                    SilkUtility.WriteWarning(
                        $"Collector {collectorGuid}: TraceSetInformation(StackTracing) " +
                        $"returned 0x{status:X8} ({status})");
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        /// <summary>
        /// Stops a native ETW session via ControlTraceW with EVENT_TRACE_CONTROL_STOP.
        /// Called from both the inline TerminateCollector closure and StopAllCollectors.
        /// </summary>
        internal static void StopNativeSession(
            ulong  traceHandle,
            string sessionName,
            Guid   collectorGuid)
        {
            if (traceHandle == 0) return;
            try
            {
                int    propSize  = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
                int    nameBytes = (sessionName.Length + 1) * sizeof(char);
                int    totalSize = propSize + nameBytes;
                IntPtr buffer    = Marshal.AllocHGlobal(totalSize);
                try
                {
                    ZeroBuffer(buffer, totalSize);

                    var props = new EVENT_TRACE_PROPERTIES();
                    props.Wnode.BufferSize = (uint)totalSize;
                    props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
                    props.LoggerNameOffset = (uint)propSize;
                    Marshal.StructureToPtr(props, buffer, false);

                    uint status = ControlTraceW(
                        traceHandle, null, buffer, EVENT_TRACE_CONTROL_STOP);

                    if (status == 0)
                        SilkUtility.WriteInfo(
                            $"Collector {collectorGuid}: native session stopped");
                    else
                        SilkUtility.WriteWarning(
                            $"Collector {collectorGuid}: " +
                            $"ControlTraceW stop returned 0x{status:X8}");
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                SilkUtility.WriteWarning(
                    $"Collector {collectorGuid}: " +
                    $"exception stopping native session: {ex.Message}");
            }
        }

        /// <summary>
        /// Stops a native ETW session by <paramref name="sessionName"/> alone (handle = 0).
        /// Used by the startup purge to clean up sessions from previous forcibly-killed runs.
        /// ControlTraceW accepts handle=0 and a non-null session name to locate the session.
        /// </summary>
        internal static void StopSessionByName(string sessionName)
        {
            if (string.IsNullOrEmpty(sessionName))
                return;

            try
            {
                int    propSize  = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
                int    nameBytes = (sessionName.Length + 1) * sizeof(char);
                int    totalSize = propSize + nameBytes;
                IntPtr buffer    = Marshal.AllocHGlobal(totalSize);
                try
                {
                    ZeroBuffer(buffer, totalSize);

                    var props = new EVENT_TRACE_PROPERTIES();
                    props.Wnode.BufferSize = (uint)totalSize;
                    props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
                    props.LoggerNameOffset = (uint)propSize;
                    Marshal.StructureToPtr(props, buffer, false);

                    // Pass handle=0 and non-null session name: ControlTraceW locates by name.
                    uint status = ControlTraceW(0, sessionName, buffer, EVENT_TRACE_CONTROL_STOP);

                    if (status == 0 || status == 4201 /* ERROR_WMI_INSTANCE_NOT_FOUND: already gone */)
                        SilkUtility.WriteInfo($"Startup purge: session \"{sessionName}\" stopped");
                    else
                        SilkUtility.WriteWarning(
                            $"Startup purge: ControlTraceW(\"{sessionName}\") returned 0x{status:X8}");
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                SilkUtility.WriteWarning(
                    $"Startup purge: exception stopping \"{sessionName}\": {ex.Message}");
            }
        }

        // =====================================================================
        // P/Invoke — structures
        // =====================================================================

        // CLASSIC_EVENT_ID — identifies a classic (WMI/MOF) kernel event by GUID + opcode Type.
        // Used with TraceSetInformation(TraceStackTracingInfo) to specify which kernel events
        // should have their call stack captured.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-classic_event_id
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct CLASSIC_EVENT_ID
        {
            public Guid  EventGuid;
            public byte  Type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
            public byte[] Reserved;

            public CLASSIC_EVENT_ID(Guid guid, byte type)
            {
                EventGuid = guid;
                Type      = type;
                Reserved  = new byte[7];
            }
        }

        // Default kernel events for which stack tracing is enabled when
        // <EnableStackTracing>true</EnableStackTracing> is set on a Kernel collector.
        // These are the classic WMI/MOF GUIDs for well-known kernel event sources.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
        private static readonly CLASSIC_EVENT_ID[] DefaultStackTraceEvents =
        {
            // Process/Start   (Type 1)
            new CLASSIC_EVENT_ID(new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"), 1),
            // Process/End     (Type 2)
            new CLASSIC_EVENT_ID(new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"), 2),
            // Thread/Start    (Type 1)
            new CLASSIC_EVENT_ID(new Guid("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"), 1),
            // Image/Load      (Type 10)
            new CLASSIC_EVENT_ID(new Guid("2cb15d1d-5fc1-11d2-abe1-00a0c911f518"), 10),
            // FileIO/Create   (Type 64)
            new CLASSIC_EVENT_ID(new Guid("90cbdc39-4a3e-11d1-84f4-0000f80464e3"), 64),
        };

        // WNODE_HEADER — embedded in EVENT_TRACE_PROPERTIES.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        [StructLayout(LayoutKind.Sequential)]
        private struct WNODE_HEADER
        {
            public uint  BufferSize;
            public uint  ProviderId;
            public ulong HistoricalContext;   // union: Version (ULONG) + Linkage (ULONG)
            public long  TimeStamp;           // union: KernelHandle (HANDLE) / LARGE_INTEGER
            public Guid  Guid;
            public uint  ClientContext;
            public uint  Flags;
        }

        // EVENT_TRACE_PROPERTIES — session configuration.
        // The logger-name string is written immediately after the struct in the same allocation.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint   BufferSize;
            public uint   MinimumBuffers;
            public uint   MaximumBuffers;
            public uint   MaximumFileSize;
            public uint   LogFileMode;
            public uint   FlushTimer;
            public uint   EnableFlags;
            public int    AgeLimit;          // union with FlushThreshold
            public uint   NumberOfBuffers;
            public uint   FreeBuffers;
            public uint   EventsLost;
            public uint   BuffersWritten;
            public uint   LogBuffersLost;
            public uint   RealTimeBuffersLost;
            public IntPtr LoggerThreadId;    // HANDLE — pointer-sized
            public uint   LogFileNameOffset;
            public uint   LoggerNameOffset;
            // Followed in the same buffer by: LogFileName (WCHAR[]), LoggerName (WCHAR[])
        }

        // OSVERSIONINFOEX — used by RtlGetVersion to obtain the true OS version,
        // bypassing the application compatibility manifest shim.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOEX
        {
            public uint   OSVersionInfoSize;
            public uint   MajorVersion;
            public uint   MinorVersion;
            public uint   BuildNumber;
            public uint   PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CSDVersion;
            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte   ProductType;
            public byte   Reserved;
        }

        // =====================================================================
        // P/Invoke — constants
        // =====================================================================

        // Real-time delivery to consumers — no log file.
        private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;  // evntrace.h

        // Required for system-provider / system-trace sessions.
        // Minimum: Windows 8 / Server 2012.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
        private const uint EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000;

        private const uint WNODE_FLAG_TRACED_GUID             = 0x00020000;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
        private const uint EVENT_TRACE_CONTROL_STOP           = 1;

        // =====================================================================
        // P/Invoke — functions
        // =====================================================================

        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern uint StartTraceW(
            out   ulong  TraceHandle,
            [In]  string InstanceName,
            [In]  IntPtr Properties);      // PEVENT_TRACE_PROPERTIES

        // Starting with Windows 11, system trace provider events can be enabled via this API.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern uint EnableTraceEx2(
                  ulong    TraceHandle,
            [In]  ref Guid ProviderId,
                  uint     ControlCode,
                  byte     Level,
                  ulong    MatchAnyKeyword,
                  ulong    MatchAllKeyword,
                  uint     Timeout,
            [In]  IntPtr   EnableParameters);  // PENABLE_TRACE_PARAMETERS (IntPtr.Zero = no filter)

        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern uint ControlTraceW(
                  ulong  TraceHandle,
            [In]  string InstanceName,
            [In]  IntPtr Properties,      // PEVENT_TRACE_PROPERTIES
                  uint   ControlCode);

        // Used for legacy ObTrace: TraceSystemTraceEnableFlagsInfo + PERF_OB_HANDLE buffer.
        // Must be called AFTER StartTrace.
        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern uint TraceSetInformation(
                  ulong  TraceHandle,
                  int    InformationClass,   // TRACE_INFO_CLASS
            [In]  IntPtr TraceInformation,
                  uint   InformationLength);

        // Returns the true OS version regardless of app-compat shims.
        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref OSVERSIONINFOEX versionInfo);

        // =====================================================================
        // Misc helpers
        // =====================================================================

        private static void ZeroBuffer(IntPtr buffer, int size)
        {
            byte[] zeros = new byte[size];
            Marshal.Copy(zeros, 0, buffer, size);
        }
    }
}