using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;

namespace SilkETW
{
    /// <summary>
    /// Thread-safe, buffered writer for NDJSON output.
    /// All collector threads enqueue lines via <see cref="Enqueue"/>;
    /// a dedicated background thread drains the queue and writes to disk.
    /// </summary>
    sealed class NdjsonFileWriter : IDisposable
    {
        private readonly BlockingCollection<string> _queue;
        private readonly Thread _writerThread;
        private readonly string _filePath;
        private volatile bool _disposed;

        /// <summary>
        /// Total number of lines successfully written to disk.
        /// </summary>
        public long LinesWritten => Interlocked.Read(ref _linesWritten);
        private long _linesWritten;

        /// <summary>
        /// Last exception that occurred during writing, if any.
        /// </summary>
        public Exception LastError { get; private set; }

        public NdjsonFileWriter(string filePath, int boundedCapacity = 50_000)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));

            _filePath = filePath;
            _queue = new BlockingCollection<string>(boundedCapacity);

            _writerThread = new Thread(DrainLoop)
            {
                Name = "NdjsonWriter",
                IsBackground = true
            };
            _writerThread.Start();
        }

        /// <summary>
        /// Enqueue a single JSON line for writing. Thread-safe.
        /// Returns false if the writer has been disposed.
        /// </summary>
        public bool Enqueue(string jsonLine)
        {
            if (_disposed)
                return false;

            try
            {
                _queue.Add(jsonLine);
                return true;
            }
            catch (InvalidOperationException)
            {
                // Collection was marked as complete
                return false;
            }
        }

        /// <summary>
        /// Background thread loop: drains the queue and writes to the file.
        /// Uses StreamWriter with AutoFlush disabled; flushes after each
        /// batch drain for a balance between throughput and durability.
        /// </summary>
        private void DrainLoop()
        {
            try
            {
                using (var sw = new StreamWriter(_filePath, append: true, encoding: new System.Text.UTF8Encoding(false)))
                {
                    sw.AutoFlush = false;

                    foreach (string line in _queue.GetConsumingEnumerable())
                    {
                        sw.WriteLine(line);
                        Interlocked.Increment(ref _linesWritten);

                        // Drain any remaining items that are already queued
                        // before flushing to disk (batch-write optimization).
                        while (_queue.TryTake(out string extra))
                        {
                            sw.WriteLine(extra);
                            Interlocked.Increment(ref _linesWritten);
                        }

                        sw.Flush();
                    }
                }
            }
            catch (Exception ex)
            {
                LastError = ex;
                SilkUtility.WriteError($"NDJSON writer fatal error: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _queue.CompleteAdding();

            // Wait for the writer thread to finish draining
            if (_writerThread.IsAlive)
                _writerThread.Join(TimeSpan.FromSeconds(10));

            _queue.Dispose();
        }
    }
}