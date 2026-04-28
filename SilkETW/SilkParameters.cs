using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Text;
using System.Xml.Linq;

namespace SilkETW
{
    /// <summary>
    /// Parses and validates the SilkETWConfig.xml configuration file.
    /// </summary>
    static class SilkParameters
    {
        /// <summary>
        /// Parsed output file path from the top-level &lt;OutputPath&gt; element.
        /// </summary>
        public static string OutputPath { get; private set; } = string.Empty;

        /// <summary>
        /// Read and parse the XML configuration file.
        /// Returns a list of collector parameter sets, or an empty list on failure.
        /// </summary>
        public static List<CollectorParameters> ReadXmlConfig()
        {
            var result = new List<CollectorParameters>();

            string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SilkETWConfig.xml");
            XElement xmlRoot;
            try
            {
                xmlRoot = XElement.Load(configPath);
            }
            catch (Exception ex)
            {
                SilkUtility.WriteError($"Configuration file invalid or not found: {ex.Message}");
                return result;
            }

            // Read top-level OutputPath
            try
            {
                var outputPathElement = xmlRoot.Element(XName.Get("OutputPath"));
                OutputPath = outputPathElement?.Value?.Trim() ?? string.Empty;
            }
            catch
            {
                OutputPath = string.Empty;
            }

            // Element names
            XName xCollector = XName.Get("ETWCollector");
            XName xGuid = XName.Get("Guid");
            XName xType = XName.Get("CollectorType");
            XName xKernelKw = XName.Get("KernelKeywords");
            XName xProvider         = XName.Get("ProviderName");
            XName xLevel            = XName.Get("UserTraceEventLevel");
            XName xUserKw           = XName.Get("UserKeywords");
            XName xEventIdFilter    = XName.Get("EventIdFilter");
            XName xSysProvGuids     = XName.Get("SystemProviderGuids");
            XName xSysProvGuid      = XName.Get("ProviderGuid");
            XName xSysProvEntry     = XName.Get("Provider");
            XName xEnableFlags      = XName.Get("EnableFlags");
            XName xInformationClass = XName.Get("InformationClass");
            XName xEnableBinaryTracking = XName.Get("EnableProviderBinaryTracking");
            XName xEnableStackTracing   = XName.Get("EnableStackTracing");

            try
            {
                foreach (XElement collectorEl in xmlRoot.Elements(xCollector))
                {
                    var cp = new CollectorParameters();

                    // Guid
                    cp.CollectorGUID = ParseElement(collectorEl, xGuid, out string guidVal) && Guid.TryParse(guidVal, out Guid parsedGuid)
                        ? parsedGuid
                        : Guid.Empty;

                    // CollectorType
                    cp.CollectorType = ParseElement(collectorEl, xType, out string typeVal) && Enum.TryParse(typeVal, true, out CollectorType ct)
                        ? ct
                        : CollectorType.None;

                    // KernelKeywords
                    cp.KernelKeywords = ParseElement(collectorEl, xKernelKw, out string kkVal) && Enum.TryParse(kkVal, true, out KernelKeywords kk)
                        ? kk
                        : KernelKeywords.None;

                    // ProviderName
                    cp.ProviderName = ParseElement(collectorEl, xProvider, out string pnVal)
                        ? pnVal
                        : string.Empty;

                    // UserTraceEventLevel
                    cp.UserTraceEventLevel = ParseElement(collectorEl, xLevel, out string levelVal) && Enum.TryParse(levelVal, true, out UserTraceEventLevel tel)
                        ? tel
                        : UserTraceEventLevel.Informational;

                    // UserKeywords (hex or decimal string → ulong)
                    if (ParseElement(collectorEl, xUserKw, out string ukVal) && !string.IsNullOrEmpty(ukVal))
                    {
                        cp.UserKeywords = ParseUlongKeywords(ukVal);
                    }
                    else
                    {
                        cp.UserKeywords = 0xffffffffffffffff; // match all
                    }

                    // EventIdFilter (optional): comma-separated integers
                    cp.EventIdFilter = ParseEventIdFilter(collectorEl, xEventIdFilter, cp.CollectorGUID);

                    // SystemProviders (optional): list of entries with per-provider settings.
                    // Backward compatibility: supports legacy <ProviderGuid> list as well.
                    cp.SystemProviders = ParseSystemProviders(
                        collectorEl,
                        xSysProvGuids,
                        xSysProvEntry,
                        xSysProvGuid,
                        cp.CollectorGUID);

                    cp.SystemProviderGuids = FlattenProviderGuidList(cp.SystemProviders);

                    // EnableFlags (optional, hex or decimal): bitmask for TraceSetInformation legacy path
                    cp.EnableFlags = ParseElement(collectorEl, xEnableFlags, out string efVal)
                        ? ParseUintHex(efVal)
                        : 0;

                    // InformationClass (optional): TRACE_INFO_CLASS for TraceSetInformation
                    cp.InformationClass = ParseElement(collectorEl, xInformationClass, out string icVal)
                        && int.TryParse(icVal, out int icParsed)
                        ? icParsed
                        : SilkConstants.TraceSystemTraceEnableFlagsInfo;

                    // EnableProviderBinaryTracking (optional, User collectors only):
                    // calls TraceSetInformation(TraceProviderBinaryTracking) after provider enable.
                    // Requires Windows 10 version 1709+.
                    cp.EnableProviderBinaryTracking =
                        ParseElement(collectorEl, xEnableBinaryTracking, out string ebtVal) &&
                        string.Equals(ebtVal, "true", StringComparison.OrdinalIgnoreCase);

                    // EnableStackTracing (optional, Kernel collectors only):
                    // calls TraceSetInformation(TraceStackTracingInfo) after kernel provider enable.
                    // Stack-walk events arrive as separate NDJSON records with Stack1…StackN.
                    cp.EnableStackTracing =
                        ParseElement(collectorEl, xEnableStackTracing, out string estVal) &&
                        string.Equals(estVal, "true", StringComparison.OrdinalIgnoreCase);

                    result.Add(cp);
                }
            }
            catch (Exception ex)
            {
                SilkUtility.WriteError($"Error parsing ETWCollector elements: {ex.Message}");
            }

            if (result.Count == 0)
            {
                SilkUtility.WriteError("Configuration file did not contain any ETWCollector elements");
            }

            return result;
        }

        /// <summary>
        /// Validate all collector parameter sets and the global output path.
        /// Returns true if everything is valid.
        /// </summary>
        public static bool ValidateCollectorParameters(List<CollectorParameters> collectors)
        {
            // Validate output path
            if (string.IsNullOrWhiteSpace(OutputPath))
            {
                SilkUtility.WriteError("No OutputPath specified in configuration");
                return false;
            }

            try
            {
                FileAttributes attr = File.GetAttributes(OutputPath);
                if (attr.HasFlag(FileAttributes.Directory))
                {
                    SilkUtility.WriteError("OutputPath is a directory, not a file");
                    return false;
                }
            }
            catch (FileNotFoundException)
            {
                // File doesn't exist yet — that's OK for append mode
            }
            catch (DirectoryNotFoundException)
            {
                // Directory will be created below
            }

            string outputDir = Path.GetDirectoryName(OutputPath);
            if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            {
                try
                {
                    Directory.CreateDirectory(outputDir);
                    SilkUtility.WriteInfo($"Created output directory: {outputDir}");
                }
                catch (Exception ex)
                {
                    SilkUtility.WriteError($"Failed to create output directory: {ex.Message}");
                    return false;
                }
            }

            if (!SilkUtility.DirectoryHasPermission(outputDir, FileSystemRights.Write))
            {
                SilkUtility.WriteError("No write access to OutputPath directory");
                return false;
            }

            // Validate each collector
            int kernelCount         = 0;
            int systemProviderCount = 0;
            for (int i = 0; i < collectors.Count; i++)
            {
                CollectorParameters c = collectors[i];

                if (c.CollectorType == CollectorType.None)
                {
                    SilkUtility.WriteError($"Collector {c.CollectorGUID}: invalid CollectorType");
                    return false;
                }

                if (c.CollectorType == CollectorType.Kernel)
                {
                    kernelCount++;
                    if (c.KernelKeywords == KernelKeywords.None)
                    {
                        SilkUtility.WriteError($"Collector {c.CollectorGUID}: invalid KernelKeywords");
                        return false;
                    }
                }

                if (c.CollectorType == CollectorType.User)
                {
                    if (string.IsNullOrEmpty(c.ProviderName))
                    {
                        SilkUtility.WriteError($"Collector {c.CollectorGUID}: invalid ProviderName");
                        return false;
                    }

                    if (c.UserKeywords == 0)
                    {
                        SilkUtility.WriteError($"Collector {c.CollectorGUID}: invalid UserKeywords");
                        return false;
                    }
                }

                if (c.CollectorType == CollectorType.SystemProvider)
                {
                    systemProviderCount++;

                    if (c.SystemProviderGuids == null || c.SystemProviderGuids.Count == 0)
                    {
                        SilkUtility.WriteError(
                            $"Collector {c.CollectorGUID}: SystemProvider requires at least one " +
                            "<ProviderGuid> entry inside <SystemProviderGuids>");
                        return false;
                    }

                    if (c.SystemProviders != null)
                    {
                        var seenProviders = new HashSet<Guid>();
                        for (int p = 0; p < c.SystemProviders.Count; p++)
                        {
                            SystemProviderSettings provider = c.SystemProviders[p];

                            if (!seenProviders.Add(provider.ProviderGuid))
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: duplicate SystemProvider GUID {provider.ProviderGuid} found; last entry will still be processed");
                            }

                            if (provider.UserKeywords.HasValue && provider.UserKeywords.Value == 0)
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: provider {provider.ProviderGuid} has UserKeywords=0; that provider may not emit events");
                            }

                            if (provider.EventIdFilter != null && provider.EventIdFilter.Count == 0)
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: provider {provider.ProviderGuid} has empty EventIdFilter; disabling that provider EventId filter");
                                provider.EventIdFilter = null;
                            }

                            if (provider.OpcodeFilter != null && provider.OpcodeFilter.Count == 0)
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: provider {provider.ProviderGuid} has empty OpcodeFilter; disabling that provider Opcode filter");
                                provider.OpcodeFilter = null;
                            }

                            if (provider.EventNameFilter != null && provider.EventNameFilter.Count == 0)
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: provider {provider.ProviderGuid} has empty EventNameFilter; disabling that provider EventName filter");
                                provider.EventNameFilter = null;
                            }

                            if (provider.EventNamePrefixFilter != null && provider.EventNamePrefixFilter.Count == 0)
                            {
                                SilkUtility.WriteWarning(
                                    $"Collector {c.CollectorGUID}: provider {provider.ProviderGuid} has empty EventNamePrefixFilter; disabling that provider EventName prefix filter");
                                provider.EventNamePrefixFilter = null;
                            }

                            c.SystemProviders[p] = provider;
                        }

                        collectors[i] = c;
                    }

                    if (c.EnableFlags == 0)
                    {
                        SilkUtility.WriteWarning(
                            $"Collector {c.CollectorGUID}: SystemProvider — EnableFlags is 0. " +
                            "Legacy path (Win8/10) will not enable any events. " +
                            "Set <EnableFlags> in config (e.g. 0x80000040 for PERF_OB_HANDLE).");
                    }

                    // Inform the operator which ETW path will be used at runtime.
                    // (Actual version check runs in ETWCollector; we don't fail here
                    //  because the legacy fallback covers Windows 8-10.)
                    var summary = new StringBuilder();
                    summary.Append(
                        $"Collector {c.CollectorGUID}: SystemProvider — " +
                        $"{c.SystemProviderGuids.Count} provider GUID(s), " +
                        $"EnableFlags=0x{c.EnableFlags:X8}, InformationClass={c.InformationClass}. " +
                        "Win11+: EnableTraceEx2; Win8/10: TraceSetInformation.");

                    if (c.SystemProviders != null)
                    {
                        foreach (SystemProviderSettings provider in c.SystemProviders)
                        {
                            string keywordLabel = provider.UserKeywords.HasValue
                                ? $"0x{provider.UserKeywords.Value:X16}"
                                : "inherit collector UserKeywords";

                            summary.Append(
                                $" Provider {provider.ProviderGuid}: keywords={keywordLabel}");
                        }
                    }

                    SilkUtility.WriteInfo(summary.ToString());
                }

                // Auto-generate GUID if empty
                if (c.CollectorGUID == Guid.Empty)
                {
                    c.CollectorGUID = Guid.NewGuid();
                    collectors[i] = c;
                }

                if (c.EventIdFilter != null && c.EventIdFilter.Count == 0)
                {
                    SilkUtility.WriteWarning($"Collector {c.CollectorGUID}: EventIdFilter contained no valid numeric IDs — filter disabled");
                    // Disable the empty filter so all events pass through
                    var patched = c;
                    patched.EventIdFilter = null;
                    collectors[i] = patched;
                }

                // Warn about feature flags used on wrong collector types.
                if (c.EnableProviderBinaryTracking && c.CollectorType != CollectorType.User)
                {
                    SilkUtility.WriteWarning(
                        $"Collector {c.CollectorGUID}: EnableProviderBinaryTracking is only " +
                        "supported on User collectors — flag will be ignored");
                }

                if (c.EnableStackTracing && c.CollectorType != CollectorType.Kernel)
                {
                    SilkUtility.WriteWarning(
                        $"Collector {c.CollectorGUID}: EnableStackTracing is only " +
                        "supported on Kernel collectors — flag will be ignored");
                }
            }

            if (kernelCount > 1)
            {
                SilkUtility.WriteError("Only one Kernel collector is supported at a time");
                return false;
            }

            if (systemProviderCount > 1)
            {
                SilkUtility.WriteError("Only one SystemProvider collector is supported at a time");
                return false;
            }

            return true;
        }

        // Helpers
        private static bool ParseElement(XElement parent, XName name, out string value)
        {
            value = null;
            try
            {
                var el = parent.Element(name);
                if (el != null && !string.IsNullOrWhiteSpace(el.Value))
                {
                    value = el.Value.Trim();
                    return true;
                }
            }
            catch { }
            return false;
        }

        private static ulong ParseUlongKeywords(string input)
        {
            try
            {
                if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    return Convert.ToUInt64(input, 16);
                return Convert.ToUInt64(input);
            }
            catch
            {
                return 0xffffffffffffffff;
            }
        }

        /// <summary>
        /// Parses per-provider SystemProvider configuration.
        /// Supports both new and legacy formats:
        /// - New: &lt;SystemProviderGuids&gt;&lt;Provider&gt;...&lt;/Provider&gt;&lt;/SystemProviderGuids&gt;
        /// - Legacy: &lt;SystemProviderGuids&gt;&lt;ProviderGuid&gt;...&lt;/ProviderGuid&gt;&lt;/SystemProviderGuids&gt;
        /// </summary>
        private static List<SystemProviderSettings> ParseSystemProviders(
            XElement parent,
            XName    containerName,
            XName    entryName,
            XName    itemName,
            Guid     collectorGuid)
        {
            var container = parent.Element(containerName);
            if (container == null)
                return null;

            var providers = new List<SystemProviderSettings>();

            // Legacy format: direct ProviderGuid entries.
            foreach (XElement el in container.Elements(itemName))
            {
                string raw = el.Value?.Trim();
                if (string.IsNullOrEmpty(raw))
                    continue;

                if (Guid.TryParse(raw, out Guid g))
                {
                    providers.Add(new SystemProviderSettings
                    {
                        ProviderGuid = g
                    });
                }
                else
                    SilkUtility.WriteWarning(
                        $"Collector {collectorGuid}: SystemProviderGuids — " +
                        $"\"{ raw}\" is not a valid GUID and will be ignored");
            }

            // New format: Provider entries with per-provider settings.
            foreach (XElement entry in container.Elements(entryName))
            {
                string guidText = null;

                if (!TryGetTrimmedValue(entry, XName.Get("Guid"), out guidText) &&
                    !TryGetTrimmedValue(entry, XName.Get("ProviderGuid"), out guidText))
                {
                    XAttribute guidAttr = entry.Attribute(XName.Get("Guid"));
                    if (guidAttr != null)
                        guidText = guidAttr.Value?.Trim();
                }

                if (string.IsNullOrWhiteSpace(guidText) ||
                    !Guid.TryParse(guidText, out Guid providerGuid))
                {
                    SilkUtility.WriteWarning(
                        $"Collector {collectorGuid}: SystemProvider entry without valid Guid/ProviderGuid was ignored");
                    continue;
                }

                var setting = new SystemProviderSettings
                {
                    ProviderGuid = providerGuid
                };

                if (TryGetTrimmedValue(entry, XName.Get("UserKeywords"), out string userKeywordsText))
                    setting.UserKeywords = ParseUlongKeywords(userKeywordsText);

                setting.EventIdFilter = ParseIntCsvElement(entry, XName.Get("EventIdFilter"), collectorGuid, "SystemProvider EventIdFilter");
                setting.OpcodeFilter = ParseIntCsvElement(entry, XName.Get("OpcodeFilter"), collectorGuid, "SystemProvider OpcodeFilter");
                setting.EventNameFilter = ParseStringCsvElement(entry, XName.Get("EventNameFilter"));
                setting.EventNamePrefixFilter = ParseStringCsvElement(entry, XName.Get("EventNamePrefixFilter"));

                providers.Add(setting);
            }

            return providers;
        }

        private static List<Guid> FlattenProviderGuidList(List<SystemProviderSettings> providers)
        {
            if (providers == null)
                return null;

            var result = new List<Guid>();
            var seen = new HashSet<Guid>();
            foreach (SystemProviderSettings provider in providers)
            {
                if (provider.ProviderGuid == Guid.Empty)
                    continue;

                if (seen.Add(provider.ProviderGuid))
                    result.Add(provider.ProviderGuid);
            }

            return result;
        }

        private static HashSet<int> ParseIntCsvElement(
            XElement parent,
            XName elementName,
            Guid collectorGuid,
            string contextLabel)
        {
            if (!TryGetTrimmedValue(parent, elementName, out string value) ||
                string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var result = new HashSet<int>();
            foreach (string token in value.Split(','))
            {
                string trimmed = token.Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                if (int.TryParse(trimmed, out int parsed))
                    result.Add(parsed);
                else
                    SilkUtility.WriteWarning(
                        $"Collector {collectorGuid}: {contextLabel} token \"{trimmed}\" is not a valid integer and will be ignored");
            }

            return result;
        }

        private static HashSet<string> ParseStringCsvElement(XElement parent, XName elementName)
        {
            if (!TryGetTrimmedValue(parent, elementName, out string value) ||
                string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string token in value.Split(','))
            {
                string trimmed = token.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    result.Add(trimmed);
            }

            return result;
        }

        private static bool TryGetTrimmedValue(XElement parent, XName name, out string value)
        {
            value = null;
            XElement el = parent.Element(name);
            if (el == null)
                return false;

            value = el.Value?.Trim();
            return !string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Parses a hex (0x...) or decimal string to uint.
        /// Returns 0 on parse failure.
        /// </summary>
        private static uint ParseUintHex(string input)
        {
            try
            {
                if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    return Convert.ToUInt32(input, 16);
                return Convert.ToUInt32(input);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Parses an optional &lt;EventIdFilter&gt; element containing comma-separated integers.
        /// Returns null when the element is absent or empty (no filter).
        /// Returns a HashSet (possibly empty) when the element is present.
        /// Warns about tokens that cannot be parsed as integers.
        /// </summary>
        private static HashSet<int> ParseEventIdFilter(XElement parent, XName name, Guid collectorGuid)
        {
            var el = parent.Element(name);
            if (el == null || string.IsNullOrWhiteSpace(el.Value))
                return null;

            var result = new HashSet<int>();
            foreach (string token in el.Value.Split(','))
            {
                string trimmed = token.Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                if (int.TryParse(trimmed, out int id))
                {
                    result.Add(id);
                }
                else
                {
                    SilkUtility.WriteWarning($"Collector {collectorGuid}: EventIdFilter token \"{trimmed}\" is not a valid integer and will be ignored");
                }
            }

            return result;
        }
    }
}