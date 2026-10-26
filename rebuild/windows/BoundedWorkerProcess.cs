using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RkRebuild
{
    internal sealed class WorkerProcessResult
    {
        public int ExitCode { get; }
        public string StandardOutput { get; }
        public string StandardError { get; }

        internal WorkerProcessResult(int exitCode, string standardOutput, string standardError)
        {
            ExitCode = exitCode;
            StandardOutput = standardOutput;
            StandardError = standardError;
        }
    }

    internal static class BoundedWorkerProcess
    {
        internal const int MaximumOutputCharacters = 8192;
        private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(2);

        // A timeout cannot cancel synchronous native I/O. Terminating this owned helper
        // is the isolation boundary; no other processes (including descendants) are killed.
        internal static async Task<WorkerProcessResult> RunAsync(string executable,
            IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            if (executable == null) throw new ArgumentNullException(nameof(executable));
            if (string.IsNullOrWhiteSpace(executable)) throw new ArgumentException("An executable is required.", nameof(executable));
            if (arguments == null) throw new ArgumentNullException(nameof(arguments));
            if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
                throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be positive and at most 30 seconds.");

            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            foreach (string argument in arguments)
            {
                if (argument == null) throw new ArgumentException("Arguments cannot contain null.", nameof(arguments));
                startInfo.ArgumentList.Add(argument);
            }

            cancellationToken.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);
            using var process = new Process { StartInfo = startInfo };
            bool started = false;
            Task completion = null;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                started = process.Start();
                if (!started) throw new InvalidOperationException("The worker could not be started.");

                var readFailure = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
                Task<string> stdout = ReadBoundedAsync(process.StandardOutput, readFailure);
                Task<string> stderr = ReadBoundedAsync(process.StandardError, readFailure);
                completion = Task.WhenAll(stdout, stderr, process.WaitForExitAsync());
                // WhenAll alone would hide an overflowing pipe until the worker exits.
                Task winner = await Task.WhenAny(completion, readFailure.Task).WaitAsync(deadline.Token).ConfigureAwait(false);
                if (winner == readFailure.Task) throw await readFailure.Task.ConfigureAwait(false);
                await completion.ConfigureAwait(false);
                return new WorkerProcessResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested)
            {
                if (cancellationToken.IsCancellationRequested)
                    throw new OperationCanceledException(cancellationToken);
                throw new TimeoutException("The worker exceeded its time limit.");
            }
            finally
            {
                if (started)
                {
                    // Cleanup must not replace the original timeout, cancellation or pipe error.
                    try
                    {
                        if (!process.HasExited) process.Kill(entireProcessTree: false);
                        await process.WaitForExitAsync().WaitAsync(CleanupTimeout).ConfigureAwait(false);
                    }
                    catch { }
                }
                if (completion != null)
                {
                    // Observe late pipe failures, including those caused by disposal after
                    // bounded cleanup. Never wait indefinitely for an inherited pipe handle.
                    _ = completion.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                        TaskScheduler.Default);
                }
            }
        }

        private static async Task<string> ReadBoundedAsync(StreamReader reader, TaskCompletionSource<Exception> failure)
        {
            try
            {
                var text = new StringBuilder();
                var buffer = new char[1024];
                int count;
                while ((count = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) != 0)
                {
                    if (count > MaximumOutputCharacters - text.Length)
                        throw new InvalidDataException("Worker output exceeded the per-stream character limit.");
                    text.Append(buffer, 0, count);
                }
                return text.ToString();
            }
            catch (Exception ex)
            {
                failure.TrySetResult(ex);
                throw;
            }
        }
    }
}
