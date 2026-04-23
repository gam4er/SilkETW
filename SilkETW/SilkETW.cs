using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Session;
using Spectre.Console;

namespace SilkETW
{
    static class SilkETW
    {
        private static NdjsonFileWriter _writer;
        private static volatile bool _stopping;
        private static int _collectorsStopped;

        static void Main(string[] args)
        {
            SilkUtility.PrintLogo();

            // 1. Read configuration
            List<CollectorParameters> collectors = SilkParameters.ReadXmlConfig();
            if (collectors.Count == 0)
            {
                return;
            }

            // 2. Validate
            if (!SilkParameters.ValidateCollectorParameters(collectors))
            {
                return;
            }

            // 3. Initialize the shared NDJSON writer
            _writer = new NdjsonFileWriter(SilkParameters.OutputPath);
            SilkUtility.WriteInfo($"Output file: {SilkParameters.OutputPath}");

            // 4. Set up Ctrl+C handler
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                if (!_stopping)
                {
                    _stopping = true;
                    SilkUtility.WriteWarning("Stopping collectors...");
                    StopAllCollectors();
                }
            };

            // 5. Start collector threads
            SilkUtility.WriteInfo($"Starting {collectors.Count} collector(s)...\n");

            foreach (CollectorParameters collector in collectors)
            {
                var thread = new Thread(() =>
                {
                    try
                    {
                        string providerDisplay = collector.CollectorType == CollectorType.Kernel
                            ? collector.KernelKeywords.ToString()
                            : collector.ProviderName;   // covers User and SystemProvider

                        SilkUtility.WriteInfo($"  GUID:     {collector.CollectorGUID}");
                        SilkUtility.WriteInfo($"  Type:     {collector.CollectorType}");
                        SilkUtility.WriteInfo($"  Provider: {providerDisplay}");

                        ETWCollector.StartTrace(collector, _writer);
                    }
                    catch (Exception ex)
                    {
                        SilkUtility.WriteError($"Collector {collector.CollectorGUID} crashed: {ex.Message}");
                    }
                })
                {
                    IsBackground = true,
                    Name = $"Collector_{collector.CollectorGUID:N}"
                };

                thread.Start();
                SilkUtility.CollectorThreadList.Add(thread);

                // Wait for the thread to signal it has started the trace session
                SilkUtility.SignalThreadStarted.WaitOne();
                SilkUtility.SignalThreadStarted.Reset();
            }

            // 6. Live status display — spinner with event counters until stopped
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("green"))
                .Start("Collecting ETW events (Ctrl+C to stop)...", ctx =>
                {
                    while (!_stopping)
                    {
                        long count = Interlocked.Read(ref SilkUtility.RunningEventCount);
                        long written = _writer.LinesWritten;
                        ctx.Status($"Collecting ETW events (Ctrl+C to stop)  |  Events captured: {count}  |  Written to disk: {written}");

                        // Check if all collector threads have exited unexpectedly
                        if (SilkUtility.CollectorThreadList.All(t => !t.IsAlive))
                        {
                            break;
                        }

                        Thread.Sleep(500);
                    }
                });

            if (!_stopping && SilkUtility.CollectorThreadList.All(t => !t.IsAlive))
            {
                SilkUtility.WriteWarning("All collectors have terminated unexpectedly.");
            }

            // 7. Cleanup — stop trace sessions and wait for threads
            StopAllCollectors();

            // Read final stats before disposing the writer
            long finalCount = Interlocked.Read(ref SilkUtility.RunningEventCount);
            long finalWritten = _writer?.LinesWritten ?? 0;
            Exception writerError = _writer?.LastError;

            // Flush and dispose the writer
            _writer?.Dispose();

            AnsiConsole.MarkupLine($"[green]Total events captured: {finalCount}  |  Written to disk: {finalWritten}[/]");

            if (writerError != null)
            {
                SilkUtility.WriteError($"Writer error occurred: {writerError.Message}");
            }

            SilkUtility.WriteInfo("Done.");
        }

        private static void StopAllCollectors()
        {
            // Guard against double invocation (Ctrl+C handler + main thread)
            if (Interlocked.Exchange(ref _collectorsStopped, 1) == 1)
                return;

            // Stop all running trace sessions
            lock (SilkUtility.CollectorTaskList)
            {
                foreach (CollectorInstance task in SilkUtility.CollectorTaskList)
                {
                    try
                    {
                        // Stop event processing first so the blocking Process() call returns
                        task.EventSource.StopProcessing();
                    }
                    catch { }

                    try
                    {
                        // For SystemProvider collectors the session is native; stop it via P/Invoke.
                        if (task.NativeTraceHandle != 0)
                        {
                            ETWCollector.StopNativeSession(
                                task.NativeTraceHandle,
                                task.EventParseSessionName,
                                task.CollectorGUID);
                        }
                        else
                        {
                            // Kernel / User collectors use the managed TraceEventSession wrapper.
                            task.TraceSession?.Stop();
                            task.TraceSession?.Dispose();
                        }
                        SilkUtility.WriteInfo($"Collector {task.CollectorGUID}: stopped");
                    }
                    catch (Exception ex)
                    {
                        SilkUtility.WriteError($"Error stopping collector {task.CollectorGUID}: {ex.Message}");
                    }
                }
                SilkUtility.CollectorTaskList.Clear();
            }

            // Wait for threads to finish (short timeout since they are background threads)
            foreach (Thread thread in SilkUtility.CollectorThreadList)
            {
                if (thread.IsAlive)
                    thread.Join(TimeSpan.FromSeconds(3));
            }
        }
    }
}
