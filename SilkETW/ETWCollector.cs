using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Xml;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace SilkETW
{
    static class ETWCollector
    {
        /// <summary>
        /// Starts an ETW trace session for the given collector parameters.
        /// Events are serialized to JSON and written to the shared <paramref name="writer"/>.
        /// This method blocks until the trace is stopped (via Ctrl+C or error).
        /// </summary>
        public static void StartTrace(CollectorParameters collector, NdjsonFileWriter writer)
        {
            // Elevation check
            if (TraceEventSession.IsElevated() != true)
            {
                SilkUtility.WriteError($"Collector {collector.CollectorGUID}: must be run as Administrator");
                return;
            }

            SilkUtility.WriteInfo($"Collector {collector.CollectorGUID}: starting trace");

            // Session naming
            string sessionName;
            if (collector.CollectorType == CollectorType.Kernel)
            {
                sessionName = KernelTraceEventParser.KernelSessionName;
            }
            else
            {
                sessionName = "SilkETWUserCollector_" + Guid.NewGuid().ToString("N");
            }

            var traceSession = new TraceEventSession(sessionName);
            traceSession.StopOnDispose = true;

            using (var eventSource = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session))
            {
                    var eventParser = new DynamicTraceEventParser(eventSource);

                    eventParser.All += delegate (TraceEvent data)
                    {
                        var eRecord = new EventRecordStruct
                        {
                            ProviderGuid = data.ProviderGuid,
                            ProviderName = data.ProviderName,
                            EventName = data.EventName,
                            Opcode = data.Opcode,
                            OpcodeName = data.OpcodeName,
                            TimeStamp = data.TimeStamp,
                            ThreadID = data.ThreadID,
                            ProcessID = data.ProcessID,
                            ProcessName = data.ProcessName,
                            PointerSize = data.PointerSize,
                            EventDataLength = data.EventDataLength
                        };

                        // Populate process name if undefined
                        if (string.IsNullOrEmpty(eRecord.ProcessName))
                        {
                            try
                            {
                                eRecord.ProcessName = Process.GetProcessById(eRecord.ProcessID).ProcessName;
                            }
                            catch
                            {
                                eRecord.ProcessName = "N/A";
                            }
                        }

                        // Parse event properties from XML representation
                        var eventProperties = new Dictionary<string, string>();
                        try
                        {
                            using (var stringReader = new StringReader(data.ToString()))
                            {
                                var settings = new XmlReaderSettings
                                {
                                    ConformanceLevel = ConformanceLevel.Fragment,
                                    DtdProcessing = DtdProcessing.Prohibit
                                };

                                using (var xmlReader = XmlReader.Create(stringReader, settings))
                                {
                                    while (xmlReader.Read())
                                    {
                                        for (int i = 0; i < xmlReader.AttributeCount; i++)
                                        {
                                            xmlReader.MoveToAttribute(i);
                                            string attrName = xmlReader.Name;
                                            string attrValue = xmlReader.Value;

                                            // Cap max length for event data elements to 10k
                                            if (attrValue.Length > 10000)
                                            {
                                                attrValue = attrValue.Substring(0, 10000);
                                            }

                                            // Avoid duplicate keys (can happen with some providers)
                                            if (!eventProperties.ContainsKey(attrName))
                                            {
                                                eventProperties[attrName] = attrValue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            eventProperties["XmlEventParsing"] = "false";
                            eventProperties["XmlEventParsingError"] = ex.Message;
                        }
                        eRecord.XmlEventData = eventProperties;

                        // Serialize to JSON and enqueue
                        string jsonLine = Newtonsoft.Json.JsonConvert.SerializeObject(eRecord, Newtonsoft.Json.Formatting.None);
                        if (!writer.Enqueue(jsonLine))
                        {
                            SilkUtility.WriteError($"Collector {collector.CollectorGUID}: failed to enqueue event (writer stopped)");
                            TerminateCollector();
                            return;
                        }

                        // Update global counter
                        Interlocked.Increment(ref SilkUtility.RunningEventCount);
                    };

                    // Enable the provider
                    if (collector.CollectorType == CollectorType.Kernel)
                    {
                        traceSession.EnableKernelProvider((KernelTraceEventParser.Keywords)collector.KernelKeywords);
                    }
                    else
                    {
                        traceSession.EnableProvider(
                            collector.ProviderName,
                            (TraceEventLevel)collector.UserTraceEventLevel,
                            collector.UserKeywords);
                    }

                    // Register this instance for cleanup
                    var instance = new CollectorInstance
                    {
                        CollectorGUID = collector.CollectorGUID,
                        EventSource = eventSource,
                        TraceSession = traceSession,
                        EventParseSessionName = sessionName
                    };
                    lock (SilkUtility.CollectorTaskList)
                    {
                        SilkUtility.CollectorTaskList.Add(instance);
                    }

                        // Signal that the thread has started
                        SilkUtility.SignalThreadStarted.Set();

                        // Block: continuously process events
                        eventSource.Process();

                        void TerminateCollector()
                        {
                            eventSource.StopProcessing();
                            try { traceSession?.Stop(); } catch { }
                            try { traceSession?.Dispose(); } catch { }
                        }
                    }
        }
    }
}