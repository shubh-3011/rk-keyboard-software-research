using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using RkRebuild;

internal static class WirelessLightingTransactionTests
{
    private static int assertions;
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(2);
    private static byte[] original;
    private static byte[] changed;
    private static byte[][] capturedWrites;
    private static void Check(bool value, string message)
    { assertions++; if (!value) throw new Exception(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T ex) { assertions++; return ex; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    private static Task<WirelessLightingTransactionResult> Apply(Duplex stream, byte target = 1,
        TimeSpan? timeout = null, CancellationToken ct = default) =>
        WirelessLightingTransaction.ApplyToStreamAsync(stream, original, target, timeout ?? Bound, ct);
    private static async Task<WirelessLightingTransactionException> Failure(Duplex stream, int writes,
        Type cause, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var ex = await Throws<WirelessLightingTransactionException>(() => Apply(stream, timeout: timeout, ct: ct));
        Check(ex.WritesAttempted == writes && ex.MutationUncertain == (writes != 0), "honest write accounting");
        Check(cause.IsInstanceOfType(ex.InnerException), "preserved cause: " + ex.InnerException);
        Check(ex.Message.Contains("Inspect/requery") && ex.Message.Contains("no retry or rollback"), "recovery warning");
        Check(stream.ConfigWrites == writes && !stream.Disposed, "no retries, rollback, or stream disposal");
        return ex;
    }
    private static async Task<int> Main()
    {
        using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,
            "fixtures", "rk406-wireless-lighting-roundtrip.json")));
        var phase = fixture.RootElement.GetProperty("Phases").GetProperty("select-first-effect");
        original = Convert.FromHexString(phase.GetProperty("ReadBlockHex").GetString());
        changed = Convert.FromHexString(phase.GetProperty("WriteBlockHex").GetString());
        capturedWrites = phase.GetProperty("WriteFramesHex").EnumerateArray().Select(x => Convert.FromHexString(x.GetString())).ToArray();
        Check(original.Length == 128 && original.Where((b, i) => b != changed[i]).Count() == 1 && changed[10] == 1,
            "reviewed fixture changes only mode offset 0A");
        foreach (int chunk in new[] { 1, 7, 20 })
        {
            using var s = new Duplex { Chunk = chunk };
            var watch = Stopwatch.StartNew();
            var result = await Apply(s);
            Check(s.Writes.Count == 12 && s.Queries == 2 && s.ConfigWrites == 10, "query + ten frames + final query");
            Check(s.Writes[0].SequenceEqual(WirelessLightingProtocol.CreateQuery()) &&
                s.Writes[11].SequenceEqual(WirelessLightingProtocol.CreateQuery()), "exact query bytes");
            for (int i = 0; i < 10; i++) Check(s.Writes[i + 1].SequenceEqual(capturedWrites[i]), "captured write " + i);
            Check(result.Before.SequenceEqual(original) && result.After.SequenceEqual(changed) &&
                result.Verified && !result.NoOp && result.ConfigurationReportsWritten == 10, "verified result");
            result.Before[0] ^= 1; result.After[0] ^= 1;
            Check(result.Before.SequenceEqual(original) && result.After.SequenceEqual(changed), "immutable result snapshots");
            Check(watch.Elapsed >= TimeSpan.FromMilliseconds(140), "ten pre-frame 15ms delays");
            Check(s.Flushes == 12 && !s.Disposed, "same caller-owned stream flushed");
        }
        // Reverse transition is the same constrained operation, not a rollback path.
        using (var s = new Duplex { Current = (byte[])changed.Clone(), Readback = original })
        {
            var result = await WirelessLightingTransaction.ApplyToStreamAsync(s, changed, 0, Bound);
            Check(result.After.SequenceEqual(original) && s.ConfigWrites == 10, "explicit mode 1 to 0");
        }
        using (var s = new Duplex())
        {
            var result = await Apply(s, 0);
            Check(result.NoOp && result.Verified && result.Before.SequenceEqual(result.After) && s.Writes.Count == 1,
                "no-op still queries fresh state, no config write or extra query");
        }
        foreach (int offset in new[] { 0, 10, 125 })
        {
            using var s = new Duplex(); s.Current[offset] ^= 1;
            await Failure(s, 0, typeof(InvalidDataException));
            Check(s.Queries == 1, "stale baseline fails before config write");
        }
        using (var s = new Duplex())
        {
            foreach (byte[] bad in new[] { null, new byte[127], new byte[129], new byte[128] })
                await Throws<ArgumentException>(() => WirelessLightingTransaction.ApplyToStreamAsync(s, bad, 1, Bound));
            var badMode = (byte[])original.Clone(); badMode[10] = 2;
            await Throws<ArgumentException>(() => WirelessLightingTransaction.ApplyToStreamAsync(s, badMode, 1, Bound));
            foreach (byte mode in new byte[] { 2, 255 })
                await Throws<ArgumentOutOfRangeException>(() => Apply(s, mode));
            foreach (TimeSpan t in new[] { TimeSpan.FromTicks(-1), TimeSpan.FromSeconds(16) })
                await Throws<ArgumentOutOfRangeException>(() => Apply(s, timeout: t));
            await Throws<ArgumentNullException>(() => WirelessLightingTransaction.ApplyToStreamAsync(null, original, 1, Bound));
            using var readOnly = new MemoryStream(original, false);
            await Throws<ArgumentException>(() => WirelessLightingTransaction.ApplyToStreamAsync(readOnly, original, 1, Bound));
            await Throws<ArgumentNullException>(() => WirelessLightingTransaction.ApplyAsync(null, original, 1, Bound));
            var badEndpoint = new HidEndpoint("opaque", null, null, "");
            await Throws<ArgumentException>(() => WirelessLightingTransaction.ApplyAsync(badEndpoint, original, 1, Bound));
            Check(s.Writes.Count == 0 && s.Reads == 0, "invalid arguments perform zero I/O");
            await Failure(s, 0, typeof(TimeoutException), TimeSpan.Zero);
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Failure(s, 0, typeof(OperationCanceledException), ct: cancelled.Token);
            Check(s.Writes.Count == 0 && s.Reads == 0, "pre-cancel and zero timeout perform zero I/O");
        }
        foreach (int stop in new[] { 0, 1, 4 })
        {
            using var s = new Duplex { BlockAfter = stop };
            using var cts = new CancellationTokenSource();
            Task pending = Apply(s, ct: cts.Token);
            await s.Blocked.Task.WaitAsync(Bound); cts.Cancel();
            var ex = await Throws<WirelessLightingTransactionException>(() => pending);
            Check(ex.WritesAttempted == stop && ex.MutationUncertain == (stop > 0) &&
                ex.InnerException is OperationCanceledException, "pending-read cancellation accounting");
            Check(s.ConfigWrites == stop && !s.Disposed, "cancel has no recovery writes");
        }
        foreach (int stop in new[] { 0, 1, 4 })
        {
            using var s = new Duplex { BlockAfter = stop };
            await Failure(s, stop, typeof(TimeoutException), TimeSpan.FromMilliseconds(600));
        }
        foreach (bool block in new[] { false, true })
        {
            using var s = new Duplex { FailConfigWrite = !block, BlockConfigWrite = block };
            await Failure(s, 1, block ? typeof(TimeoutException) : typeof(IOException), TimeSpan.FromMilliseconds(500));
        }
        // Each differing echo byte is rejected, including checksum, padding and command-04 status.
        foreach (int offset in new[] { 0, 2, 3, 4, 5, 19 })
        {
            using var s = new Duplex { EchoMutation = b => b[offset] ^= 1 };
            await Failure(s, 1, typeof(InvalidDataException));
        }
        using (var s = new Duplex { EchoMutation = b => b[2] |= 0x80 })
            await Failure(s, 1, typeof(InvalidDataException));
        using (var s = new Duplex { Readback = original })
        {
            await Failure(s, 10, typeof(InvalidDataException));
            Check(s.Queries == 2, "mismatched final readback never retries or restores");
        }
        using (var s = new Duplex { Readback = (byte[])changed.Clone() })
        {
            s.Readback[111] ^= 1;
            await Failure(s, 10, typeof(InvalidDataException));
        }
        using (var s = new Duplex { UnrelatedPerWrite = 5 })
            Check((await Apply(s)).Verified, "60 unrelated reports across phases accepted");
        using (var s = new Duplex { UnrelatedPerWrite = 5, FinalQueryExtra = 4 })
            Check((await Apply(s)).Verified, "exactly 64 unrelated reports globally accepted");
        using (var s = new Duplex { UnrelatedPerWrite = 5, FinalQueryExtra = 5 })
            await Failure(s, 10, typeof(InvalidDataException));
        using (var s = new Duplex { UnrelatedPerWrite = 6 })
            await Failure(s, 10, typeof(InvalidDataException)); // 66th during config frame 9
        using (var s = new Duplex { UnrelatedPerWrite = 65 })
            await Failure(s, 0, typeof(InvalidDataException));
        using (var s = new Duplex { ErrorStatus = true })
            await Failure(s, 0, typeof(InvalidDataException));
        using (var s = new Duplex { Chunk = 1, EndEcho = true })
            await Failure(s, 1, typeof(EndOfStreamException));
        using (var s = new Duplex { BlockConfigWrite = true })
        {
            using var cts = new CancellationTokenSource();
            var pending = Apply(s, ct: cts.Token);
            await s.Blocked.Task.WaitAsync(Bound); cts.Cancel();
            var ex = await Throws<WirelessLightingTransactionException>(() => pending);
            Check(ex.WritesAttempted == 1 && ex.MutationUncertain && ex.InnerException is OperationCanceledException &&
                s.ConfigWrites == 1, "cancellation during native-style pending config write remains uncertain");
        }
        using (var s = new Duplex())
        {
            var ex = await Throws<WirelessLightingTransactionException>(() => Apply(s, timeout: TimeSpan.FromMilliseconds(275)));
            // Includes the initial 200-ms settling window. On a heavily delayed
            // runner the deadline can expire before query 1, which is also safe.
            Check(ex.InnerException is TimeoutException && ex.WritesAttempted >= 0 && ex.WritesAttempted < 10 &&
                s.Queries <= 1, "single deadline includes settling and all pacing, not renewed per frame");
        }
        // Snapshot baseline before the first asynchronous wait; caller mutation cannot authorize other offsets.
        using (var s = new Duplex { PauseFirstQuery = true })
        {
            byte[] supplied = (byte[])original.Clone();
            var pending = WirelessLightingTransaction.ApplyToStreamAsync(s, supplied, 1, Bound);
            await s.Blocked.Task.WaitAsync(Bound); supplied[0] ^= 1;
            s.ReleaseQuery();
            Check((await pending).After.SequenceEqual(changed), "baseline cloned before awaiting I/O");
        }
        Console.WriteLine("WirelessLightingTransaction: " + assertions + " assertions passed (offline; no devices opened).");
        return 0;
    }

    // Interactive duplex: responses become available ONLY after the associated write.
    // A missing echo blocks reads instead of returning EOF, exposing unsafe send-all behavior.
    private sealed class Duplex : Stream
    {
        private readonly Channel<byte[]> incoming = Channel.CreateUnbounded<byte[]>();
        private byte[] active;
        private int offset;
        public byte[] Current = (byte[])original.Clone();
        public byte[] Readback;
        public readonly List<byte[]> Writes = new List<byte[]>();
        public readonly TaskCompletionSource<bool> Blocked = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ConfigWrites, Queries, Flushes, Reads;
        public int Chunk = 20, BlockAfter = -1, UnrelatedPerWrite, FinalQueryExtra;
        public bool Disposed, FailConfigWrite, BlockConfigWrite, ErrorStatus, EndEcho, PauseFirstQuery;
        public Action<byte[]> EchoMutation;
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        private void Enqueue(byte[] b) => incoming.Writer.TryWrite((byte[])b.Clone());
        private void Query(byte[] block)
        {
            // Query response checksum is deliberately not generated by request checksum rules.
            foreach (byte[] b in Rk3632Codec.EncodeRequest(0x44, 0, block)) { b[19] = 0xbd; Enqueue(b); }
        }
        public void ReleaseQuery() => Query(Current);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            Check(active == null && !incoming.Reader.TryPeek(out _), "previous response fully consumed before next write");
            byte[] b = buffer.ToArray(); Writes.Add(b);
            Check(b.Length == 20 && (b[1] == 4 || b.SequenceEqual(WirelessLightingProtocol.CreateQuery())), "no arbitrary command writes");
            if (b[1] == 0x44) Queries++; else ConfigWrites++;
            int unrelated = UnrelatedPerWrite + (b[1] == 0x44 && Queries == 2 ? FinalQueryExtra : 0);
            for (int i = 0; i < unrelated; i++) { var status = new byte[20]; status[0] = 0x13; status[1] = 0x0a; Enqueue(status); }
            if (ErrorStatus) { var status = new byte[20]; status[1] = 0x0a; status[2] = 0x80; Enqueue(status); }
            if (b[1] == 4 && FailConfigWrite) throw new IOException("Injected write failure after attempt.");
            if (b[1] == 4 && BlockConfigWrite)
            { Blocked.TrySetResult(true); await Task.Delay(System.Threading.Timeout.Infinite, ct); }
            if ((b[1] == 0x44 && Queries == 1 && BlockAfter == 0) ||
                (b[1] == 4 && ConfigWrites == BlockAfter)) { Blocked.TrySetResult(true); return; }
            if (b[1] == 0x44)
            {
                if (PauseFirstQuery && Queries == 1) { Blocked.TrySetResult(true); return; }
                Query(Queries == 1 ? Current : Readback ?? changed);
            }
            else
            {
                if (EndEcho) { incoming.Writer.TryComplete(); return; }
                EchoMutation?.Invoke(b); Enqueue(b);
            }
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            Reads++; ct.ThrowIfCancellationRequested();
            if (active == null)
            {
                if (!await incoming.Reader.WaitToReadAsync(ct)) return 0;
                active = await incoming.Reader.ReadAsync(ct); offset = 0;
            }
            int count = Math.Min(Math.Min(buffer.Length, Chunk), active.Length - offset);
            active.AsMemory(offset, count).CopyTo(buffer); offset += count;
            if (offset == active.Length) active = null;
            return count;
        }
        public override Task FlushAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); Flushes++; return Task.CompletedTask; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override void Flush() => throw new Exception("Synchronous I/O forbidden");
        public override int Read(byte[] buffer, int offset, int count) => throw new Exception("Synchronous I/O forbidden");
        public override void Write(byte[] buffer, int offset, int count) => throw new Exception("Synchronous I/O forbidden");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
