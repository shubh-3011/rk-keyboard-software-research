using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace RkRebuild
{
    internal sealed class WirelessLightingTransactionResult
    {
        private readonly byte[] before;
        private readonly byte[] after;
        public byte[] Before => (byte[])before.Clone();
        public byte[] After => (byte[])after.Clone();
        public int ConfigurationReportsWritten { get; }
        public bool NoOp => ConfigurationReportsWritten == 0;
        public bool Verified => true;
        internal WirelessLightingTransactionResult(byte[] before, byte[] after, int reports)
        {
            this.before = (byte[])before.Clone(); this.after = (byte[])after.Clone();
            ConfigurationReportsWritten = reports;
        }
    }

    internal sealed class WirelessLightingTransactionException : IOException
    {
        public int WritesAttempted { get; }
        public bool MutationUncertain => WritesAttempted != 0;
        internal WirelessLightingTransactionException(int writes, Exception cause)
            : base("Lighting transaction failed. " + (writes == 0 ? "No configuration write was attempted. " :
                "Device mutation is uncertain; no restoration is claimed. ") +
                "Inspect/requery the device before another attempt; no retry or rollback was performed.", cause)
        { WritesAttempted = writes; }
    }

    internal static class WirelessLightingTransaction
    {
        // Exact installed 4.06 SHA-256 c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6:
        // lighting caller 0x40DE16 pushes 0x0F as the delay argument; 0x40D8A1-AF
        // calls 0x459A80 before EACH frame, including the first. That helper uses
        // QueryPerformanceCounter/Frequency and a 1000.0 multiplier at 0x5DAAD8.
        // Use an asynchronous minimum 15 ms delay, not the vendor's busy wait.
        // Saved rk406-wireless-lighting-roundtrip-frida-2026-10-26.json has
        // alternating WriteFile/dispatch command-04 frame indices 0..9 in both phases.
        private static readonly TimeSpan FrameDelay = TimeSpan.FromMilliseconds(15);
        private static readonly TimeSpan MaximumTimeout = TimeSpan.FromSeconds(15);

        // Caller MUST match independent model/revision evidence before calling;
        // metadata validation is not protocol certification. One handle throughout.
        internal static async Task<WirelessLightingTransactionResult> ApplyAsync(HidEndpoint endpoint,
            byte[] expectedBaseline, byte targetMode, TimeSpan timeout, CancellationToken ct = default)
        {
            WirelessLightingReader.ValidateEndpoint(endpoint);
            byte[] baseline = ValidateArguments(expectedBaseline, targetMode, timeout);
            using var deadline = CreateDeadline(timeout, ct);
            try
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (!OperatingSystem.IsWindows())
                    throw new PlatformNotSupportedException("Lighting HID transport requires Windows.");
                using var stream = new FileStream(endpoint.DevicePath, FileMode.Open, FileAccess.ReadWrite,
                    FileShare.ReadWrite, bufferSize: 20, FileOptions.Asynchronous);
                return await RunAsync(stream, baseline, targetMode, deadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) { throw Failure(ex, ct); }
        }

        // Offline seam; caller owns and exclusively uses a fresh duplex stream.
        internal static async Task<WirelessLightingTransactionResult> ApplyToStreamAsync(Stream stream,
            byte[] baseline, byte targetMode, TimeSpan timeout, CancellationToken ct = default)
        {
            byte[] expected = ValidateArguments(baseline, targetMode, timeout);
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanWrite)
                throw new ArgumentException("A readable and writable stream is required.", nameof(stream));
            using var deadline = CreateDeadline(timeout, ct);
            try { return await RunAsync(stream, expected, targetMode, deadline.Token).ConfigureAwait(false); }
            catch (Exception ex) { throw Failure(ex, ct); }
        }

        private static byte[] ValidateArguments(byte[] baseline, byte targetMode, TimeSpan timeout)
        {
            if (baseline == null) throw new ArgumentNullException(nameof(baseline));
            if (baseline.Length != 128 || baseline[126] != 0x5a || baseline[127] != 0xa5 || baseline[10] > 1)
                throw new ArgumentException("Expected a signed 128-byte mode-0/1 lighting baseline.", nameof(baseline));
            if (targetMode > 1) throw new ArgumentOutOfRangeException(nameof(targetMode));
            if (timeout < TimeSpan.Zero || timeout > MaximumTimeout)
                throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be zero to fifteen seconds.");
            return (byte[])baseline.Clone();
        }

        private static CancellationTokenSource CreateDeadline(TimeSpan timeout, CancellationToken ct)
        {
            var source = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (timeout == TimeSpan.Zero) source.Cancel(); else source.CancelAfter(timeout);
            return source;
        }

        private static WirelessLightingTransactionException Failure(Exception ex, CancellationToken ct)
        {
            int writes = ex is WirelessLightingTransactionException failure ? failure.WritesAttempted : 0;
            Exception cause = ex is WirelessLightingTransactionException wrapped ? wrapped.InnerException : ex;
            if (cause is OperationCanceledException && !ct.IsCancellationRequested)
                cause = new TimeoutException("Lighting transaction deadline expired.", cause);
            return new WirelessLightingTransactionException(writes, cause);
        }

        private static async Task<WirelessLightingTransactionResult> RunAsync(Stream stream, byte[] baseline,
            byte mode, CancellationToken token)
        {
            int attempted = 0;
            // Wrapper does not prefetch, drain, cache, or dispose the caller's stream.
            // Its skip budget spans BOTH queries and ALL echoes, not each wait.
            var reports = new ReportStream(stream);
            try
            {
                token.ThrowIfCancellationRequested();
                // Match the recovered child Apply wrapper's settling window:
                // 0x40E73E/0x40E74D waits 200 ms before entering the orchestrator.
                await Task.Delay(TimeSpan.FromMilliseconds(200), token).ConfigureAwait(false);
                byte[] before = await WirelessLightingReader.ReadFromStreamAsync(reports, MaximumTimeout, token).ConfigureAwait(false);
                if (!before.AsSpan().SequenceEqual(baseline))
                    throw new InvalidDataException("Lighting baseline is stale; configuration was not written.");
                if (before[10] == mode)
                    return new WirelessLightingTransactionResult(before, before, 0);
                byte[] patched = (byte[])before.Clone();
                patched[10] = mode; // The ONLY mutable offset exposed by this API.
                reports.ExpectedCommand = 4;
                foreach (byte[] frame in Rk3632Codec.EncodeRequest(4, 0, patched))
                {
                    await Task.Delay(FrameDelay, token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    attempted++; // A throwing/cancelled WriteAsync may already have reached the device.
                    await reports.WriteAsync(frame.AsMemory(), token).ConfigureAwait(false);
                    await reports.FlushAsync(token).ConfigureAwait(false);
                    while (true)
                    {
                        byte[] echo = new byte[20];
                        int offset = 0;
                        while (offset < echo.Length)
                        {
                            int read = await reports.ReadAsync(echo.AsMemory(offset), token).ConfigureAwait(false);
                            if (read == 0) throw new EndOfStreamException("Incomplete lighting echo.");
                            offset += read;
                        }
                        if (echo[1] != 4) continue;
                        if (!echo.AsSpan().SequenceEqual(frame)) throw new InvalidDataException("Lighting echo differs from the exact written frame.");
                        break;
                    }
                }
                reports.ExpectedCommand = 0x44;
                // The same wrapper waits 50 ms after applying (0x40E786/0x40E78A).
                // A verification query is our addition; do not issue it inside
                // the device's observed post-apply settling interval.
                await Task.Delay(TimeSpan.FromMilliseconds(50), token).ConfigureAwait(false);
                byte[] after = await WirelessLightingReader.ReadFromStreamAsync(reports, MaximumTimeout, token).ConfigureAwait(false);
                if (!after.AsSpan().SequenceEqual(patched)) throw new InvalidDataException("Lighting readback differs from the complete intended block.");
                token.ThrowIfCancellationRequested();
                return new WirelessLightingTransactionResult(before, after, attempted);
            }
            catch (Exception ex) { throw new WirelessLightingTransactionException(attempted, ex); }
        }

        private sealed class ReportStream : Stream
        {
            private readonly Stream inner;
            private readonly byte[] record = new byte[20];
            private int offset;
            private int skipped;
            internal byte ExpectedCommand = 0x44;
            internal ReportStream(Stream inner) { this.inner = inner; }
            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            {
                ct.ThrowIfCancellationRequested();
                int read = await inner.ReadAsync(buffer.Slice(0, Math.Min(buffer.Length, 20 - offset)), ct).ConfigureAwait(false);
                buffer.Slice(0, read).CopyTo(record.AsMemory(offset));
                offset += read;
                if (offset == 20)
                {
                    offset = 0;
                    if (record[0] == 0xff) throw new IOException("Device disconnect marker received.");
                    if ((record[2] & 0x80) != 0) throw new InvalidDataException("Device response error flag received.");
                    if (record[1] != ExpectedCommand && ++skipped > WirelessLightingReader.MaximumSkippedFrames)
                        throw new InvalidDataException("Transaction exceeded the global unrelated-report limit.");
                }
                return read;
            }
            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => inner.WriteAsync(buffer, ct);
            public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
            public override void Flush() => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
