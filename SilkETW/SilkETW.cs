using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
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

        // =====================================================================
        // P/Invoke — Windows console control handler
        // Covers CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT
        // which Console.CancelKeyPress does NOT handle.
        // Ref: https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler
        // =====================================================================

        private delegate bool ConsoleCtrlHandlerDelegate(uint dwCtrlType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandlerDelegate handler, bool add);

        // Keep a static reference so the delegate is not garbage-collected
        private static readonly ConsoleCtrlHandlerDelegate _consoleCtrlHandler = OnConsoleCtrl;

        private const uint CTRL_C_EVENT       = 0;
        private const uint CTRL_BREAK_EVENT   = 1;
        private const uint CTRL_CLOSE_EVENT   = 2;
        private const uint CTRL_LOGOFF_EVENT  = 5;
        private const uint CTRL_SHUTDOWN_EVENT = 6;

        private static bool OnConsoleCtrl(uint dwCtrlType)
        {
            if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT ||
                dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT ||
                dwCtrlType == CTRL_SHUTDOWN_EVENT)
            {
                if (!_stopping)
                {
                    _stopping = true;
                    SilkUtility.WriteWarning("Stopping collectors...");
                    StopAllCollectors();
                    _writer?.Dispose();
                }
                // Return true to suppress the default handler (prevents abrupt termination
                // for CTRL_CLOSE_EVENT — gives threads ~5 s to flush and exit).
                return true;
            }
            return false;
        }

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

            // 4. Set up shutdown handlers
            //    a) SetConsoleCtrlHandler handles Ctrl+C, Ctrl+Break, window-close (✕),
            //       logoff and system shutdown — all signals that Console.CancelKeyPress misses.
            SetConsoleCtrlHandler(_consoleCtrlHandler, true);

            //    b) Console.CancelKeyPress is kept as a belt-and-suspenders fallback.
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

            //    c) AppDomain.ProcessExit fires on Environment.Exit() and unhandled
            //       exceptions reaching the CLR top-level handler.
            AppDomain.CurrentDomain.ProcessExit += (sender, e) =>
            {
                if (!_stopping)
                {
                    _stopping = true;
                    StopAllCollectors();
                    _writer?.Dispose();
                }
            };

            // 5. Purge any stale SilkETW sessions left by a previous forcibly-terminated run
            PurgeStaleSessions(collectors);

            // 6. Start collector threads
            SilkUtility.WriteInfo($"Starting {collectors.Count} collector(s)...\n");

            foreach (CollectorParameters collector in collectors)
            {
                SilkUtility.RegisterCollectorStats(collector);

                var thread = new Thread(() =>
                {
                    try
                    {
                        string providerDisplay = collector.CollectorType == CollectorType.Kernel
                            ? collector.KernelKeywords.ToString()
                            : collector.CollectorType == CollectorType.SystemProvider
                                ? (collector.SystemProviderGuids == null || collector.SystemProviderGuids.Count == 0
                                    ? "N/A"
                                    : string.Join(",", collector.SystemProviderGuids))
                                : collector.ProviderName;

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

            // 7. Live status display
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

            // 8. Cleanup
            StopAllCollectors();

            // Read final stats before disposing the writer
            long finalCount = Interlocked.Read(ref SilkUtility.RunningEventCount);
            long finalWritten = _writer?.LinesWritten ?? 0;
            Exception writerError = _writer?.LastError;

            // Flush and dispose the writer
            _writer?.Dispose();

            AnsiConsole.MarkupLine($"[green]Total events captured: {finalCount}  |  Written to disk: {finalWritten}[/]");

            SilkUtility.WriteInfo("Per-collector counters (accepted / filtered / written / lost):");
            foreach (CollectorParameters collector in collectors)
            {
                if (!SilkUtility.CollectorStats.TryGetValue(collector.CollectorGUID, out CollectorRuntimeStats stats))
                {
                    SilkUtility.WriteWarning($"Collector {collector.CollectorGUID}: no runtime stats were collected");
                    continue;
                }

                SilkUtility.WriteInfo(
                    $"Collector {collector.CollectorGUID} [{stats.CollectorType}] " +
                    $"{stats.ProviderDisplay} => {stats.Accepted} / {stats.FilteredOut} / {stats.Written} / {stats.Lost}");
            }

            if (writerError != null)
            {
                SilkUtility.WriteError($"Writer error occurred: {writerError.Message}");
            }

            SilkUtility.WriteInfo("Done.");
        }

        /// <summary>
        /// Finds and stops any ETW sessions left behind by a previous run that was
        /// forcibly terminated (task kill, power loss, crash).
        ///
        /// SystemProvider sessions: anything whose name starts with
        ///   <see cref="SilkConstants.SystemProviderSessionPrefix"/>
        ///   This covers both the new fixed name and old random-GUID names from earlier builds.
        ///
        /// Kernel session: stopped only when the current config contains a Kernel collector,
        ///   since "NT Kernel Logger" is a shared system-wide name.
        /// </summary>
        private static void PurgeStaleSessions(List<CollectorParameters> collectors)
        {
            bool hasKernelCollector = collectors.Any(c => c.CollectorType == CollectorType.Kernel);

            try
            {
                IList<string> activeSessions = TraceEventSession.GetActiveSessionNames();
                foreach (string name in activeSessions)
                {
                    if (name.StartsWith(SilkConstants.SystemProviderSessionPrefix,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        SilkUtility.WriteWarning(
                            $"Startup purge: stopping stale SystemProvider session \"{name}\"");
                        ETWCollector.StopSessionByName(name);
                    }
                }

                if (hasKernelCollector)
                {
                    // "NT Kernel Logger" is the single kernel session slot.
                    // TraceEventSession.Stop() by name is the cleanest way via the managed API.
                    const string kernelSessionName = "NT Kernel Logger";
                    if (activeSessions.Any(n =>
                            string.Equals(n, kernelSessionName, StringComparison.OrdinalIgnoreCase)))
                    {
                        SilkUtility.WriteWarning(
                            $"Startup purge: stopping stale Kernel session \"{kernelSessionName}\"");
                        try
                        {
                            using (var ts = new TraceEventSession(kernelSessionName))
                                ts.Stop();
                        }
                        catch (Exception ex)
                        {
                            SilkUtility.WriteWarning(
                                $"Startup purge: could not stop \"{kernelSessionName}\": {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                SilkUtility.WriteWarning($"Startup purge failed: {ex.Message}");
            }
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
