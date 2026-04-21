using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
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
            XName xProvider = XName.Get("ProviderName");
            XName xLevel = XName.Get("UserTraceEventLevel");
            XName xUserKw = XName.Get("UserKeywords");

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
            int kernelCount = 0;
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

                // Auto-generate GUID if empty
                if (c.CollectorGUID == Guid.Empty)
                {
                    c.CollectorGUID = Guid.NewGuid();
                    collectors[i] = c;
                }
            }

            if (kernelCount > 1)
            {
                SilkUtility.WriteError("Only one Kernel collector is supported at a time");
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
    }
}