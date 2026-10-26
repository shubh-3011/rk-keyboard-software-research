using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using RkRebuild;

internal static class WirelessLightingTests
{
    private static int assertions;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    // First complete incoming command-44 block from reviewed lighting_report events:
    // .research/rk406-lighting-hit-test-roundtrip-2026-10-26.json.
    // Source SHA-256 c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6.
    private static readonly string[] Captured = {
        "13440A000E0003030400000404070000200100FB",
        "13440A010E000000000000040400FF14000000DD",
        "13440A020E0000000003000000000000000000C6",
        "13440A030E0000000000000000FF0100000025E9",
        "13440A040EFFFF141714171417141714171417C5",
        "13440A050E1417141714171417141714171417F3",
        "13440A060E141714171417141714171417044714",
        "13440A070E0747074707440744074407440744DB",
        "13440A080E074407440404040404040404040487",
        "13440A09025AA5000000000000000000000000BD"
    };

    private static List<byte[]> Frames() => Captured.Select(Convert.FromHexString).ToList();
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new Exception(message);
    }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T) { assertions++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }

    private static async Task<int> Main()
    {
        byte[] query = WirelessLightingProtocol.CreateQuery();
        Check(Convert.ToHexString(query) == "1344010000000000000000000000000000000058", "exact captured query");
        query[1] = 0;
        Check(WirelessLightingProtocol.CreateQuery()[1] == 0x44, "fresh query storage");
        byte[] expected = Convert.FromHexString(string.Concat(Captured.Select((s, i) => s.Substring(10, i == 9 ? 4 : 28))));
        byte[] decoded = WirelessLightingProtocol.DecodeBlock(Frames());
        Check(decoded.Length == 128 && decoded.SequenceEqual(expected), "captured block including signature");
        decoded[0] ^= 0xff;
        Check(WirelessLightingProtocol.DecodeBlock(Frames()).SequenceEqual(expected), "fresh decoded storage");
        Throws<ArgumentNullException>(() => WirelessLightingProtocol.DecodeBlock(null));
        foreach (int count in new[] { 0, 1, 9, 11 })
        {
            var frames = Frames();
            if (count < 10) frames.RemoveRange(count, 10 - count); else frames.Add(frames[0]);
            Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(frames));
        }
        foreach (int index in Enumerable.Range(0, 10))
        {
            foreach (var mutation in new Action<byte[]>[] {
                f => f[0] = 0x12, f => f[1] = 0x45, f => f[2] = 0x8a,
                f => f[2] = 9, f => f[2] = 11, f => f[3] = (byte)((index + 1) % 10),
                f => f[4] = 0, f => f[4] = (byte)(index == 9 ? 14 : 2) })
            {
                var frames = Frames(); mutation(frames[index]);
                Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(frames));
            }
            foreach (int length in new[] { 0, 19, 21 })
            {
                var frames = Frames(); frames[index] = new byte[length];
                Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(frames));
            }
            var missing = Frames(); missing[index] = null;
            Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(missing));
        }
        var duplicate = Frames(); duplicate[4] = duplicate[3];
        Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(duplicate));
        var reordered = Frames(); (reordered[2], reordered[3]) = (reordered[3], reordered[2]);
        Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(reordered));
        foreach (int offset in new[] { 5, 6 })
        {
            var frames = Frames(); frames[9][offset] ^= 1;
            Throws<InvalidDataException>(() => WirelessLightingProtocol.DecodeBlock(frames));
        }
        var uncheckedBytes = Frames();
        foreach (byte[] frame in uncheckedBytes) { frame[19] ^= 0xff; frame[4] |= 0xf0; }
        uncheckedBytes[9][7] = 0x99;
        Check(WirelessLightingProtocol.DecodeBlock(uncheckedBytes).SequenceEqual(expected), "checksum, high length nibble and padding are not invented constraints");

        Check(typeof(WirelessLightingReader).GetMethod("ReadFromStreamAsync", BindingFlags.Public | BindingFlags.Static) == null,
            "stream seam is not public");
        Check(typeof(WirelessLightingReader).GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly).Length == 1,
            "only public reader operation is ReadAsync");
        TestMetadata();

        foreach (int chunk in new[] { 1, 7, 20 })
        {
            using var stream = new FakeStream(Frames(), chunk);
            Check((await WirelessLightingReader.ReadFromStreamAsync(stream, Timeout)).SequenceEqual(expected), "stream block, chunk " + chunk);
            CheckQuery(stream);
            Check(stream.PositionRead == 200 && !stream.Disposed, "exact block and caller-owned stream");
        }
        // Exactly 64 unrelated reports are permitted, including status 0A.
        var status = new byte[20]; status[0] = 0x13; status[1] = 0x0a;
        var unrelated = new byte[20]; unrelated[0] = 0x13; unrelated[1] = 0x22;
        var interleaved = new List<byte[]>();
        for (int i = 0; i < 64; i++) interleaved.Add(i % 2 == 0 ? status : unrelated);
        interleaved.AddRange(Frames()); interleaved.Add(status);
        using (var stream = new FakeStream(interleaved))
        {
            Check((await WirelessLightingReader.ReadFromStreamAsync(stream, Timeout)).SequenceEqual(expected), "64 skipped records accepted");
            Check(stream.PositionRead == 74 * 20, "no trailing read"); CheckQuery(stream);
        }
        using (var stream = new FakeStream(Enumerable.Repeat(status, 65).Concat(Frames())))
        {
            await ThrowsAsync<InvalidDataException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout));
            Check(stream.PositionRead == 65 * 20, "65th skip fails immediately"); CheckQuery(stream);
        }
        var between = Frames(); between.Insert(5, status);
        using (var stream = new FakeStream(between))
            Check((await WirelessLightingReader.ReadFromStreamAsync(stream, Timeout)).SequenceEqual(expected), "status interleaved within response");
        foreach (int length in new[] { 0, 1, 19, 20, 199 })
        {
            using var stream = new FakeStream(Frames(), truncate: length);
            await ThrowsAsync<EndOfStreamException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout));
            CheckQuery(stream);
        }
        foreach (var mutation in new Action<List<byte[]>>[] {
            f => f[0][2] = 9, f => f[0][2] = 0x8a, f => f[0][0] = 0,
            f => f[1][3] = 0, f => f[1][3] = 2, f => f[1][4] = 2,
            f => f[9][5] = 0 })
        {
            var frames = Frames(); mutation(frames);
            using var stream = new FakeStream(frames);
            await ThrowsAsync<InvalidDataException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout));
            CheckQuery(stream);
        }
        using (var stream = new FakeStream(Frames()))
        {
            foreach (TimeSpan invalid in new[] { TimeSpan.FromTicks(-1), TimeSpan.FromSeconds(15).Add(TimeSpan.FromTicks(1)), System.Threading.Timeout.InfiniteTimeSpan })
                await ThrowsAsync<ArgumentOutOfRangeException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, invalid));
            await ThrowsAsync<TimeoutException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, TimeSpan.Zero));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await ThrowsAsync<OperationCanceledException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout, cancelled.Token));
            Check(stream.Writes.Count == 0 && stream.PositionRead == 0, "no I/O for invalid bounds, zero deadline or pre-cancellation");
        }
        await ThrowsAsync<ArgumentNullException>(() => WirelessLightingReader.ReadFromStreamAsync(null, Timeout));
        using (var readOnly = new MemoryStream(new byte[1], writable: false))
            await ThrowsAsync<ArgumentException>(() => WirelessLightingReader.ReadFromStreamAsync(readOnly, Timeout));
        using (var stream = new FakeStream(Frames()))
        {
            await WirelessLightingReader.ReadFromStreamAsync(stream, TimeSpan.FromSeconds(15));
            CheckQuery(stream);
        }
        await TestCancellationAndTimeout();
        Console.WriteLine("WirelessLighting: " + assertions + " assertions passed (offline; no devices opened).");
        return 0;
    }

    private static void CheckQuery(FakeStream stream)
    {
        Check(stream.Writes.Count == 1 && stream.Writes[0].SequenceEqual(WirelessLightingProtocol.CreateQuery()), "query written once, no extra commands");
        Check(stream.Flushes == 1, "query flushed once");
    }

    private static HidEndpoint Endpoint(string path = "opaque-token", ushort vid = 0x258a, ushort pid = 0x3632,
        ushort page = 0xff02, ushort usage = 2, ushort input = 20, ushort output = 20, string error = "") =>
        new HidEndpoint(path, new WindowsHidDiscovery.HiddAttributes { VendorID = vid, ProductID = pid },
            new WindowsHidDiscovery.HidpCaps { UsagePage = page, Usage = usage, InputReportByteLength = input, OutputReportByteLength = output }, error);

    private static void TestMetadata()
    {
        WirelessLightingReader.ValidateEndpoint(Endpoint());
        WirelessLightingReader.ValidateEndpoint(Endpoint(path: "opaque-not-parsed", vid: 0x1234, pid: 0xabcd));
        Check(true, "valid metadata; catalogue matching remains caller precondition, path not parsed");
        Throws<ArgumentNullException>(() => WirelessLightingReader.ValidateEndpoint(null));
        foreach (var endpoint in new[] { Endpoint(path: null), Endpoint(path: ""), Endpoint(path: " "), Endpoint(path: "opaque\0token"),
            Endpoint(vid: 0), Endpoint(pid: 0), Endpoint(page: 1), Endpoint(usage: 6), Endpoint(page: 0xff00),
            Endpoint(input: 19), Endpoint(input: 64), Endpoint(output: 19), Endpoint(output: 64), Endpoint(error: "failure"),
            new HidEndpoint("opaque", null, null, "") })
            Throws<ArgumentException>(() => WirelessLightingReader.ValidateEndpoint(endpoint));
    }

    private static async Task TestCancellationAndTimeout()
    {
        // Test cancellation during both write and read, with a deterministic
        // handshake rather than a sleep or a real device.
        foreach (bool blockWrite in new[] { false, true })
        {
            using var stream = new FakeStream(Frames(), blockRead: !blockWrite, blockWrite: blockWrite);
            using var cancellation = new CancellationTokenSource();
            Task<byte[]> pending = WirelessLightingReader.ReadFromStreamAsync(stream, Timeout, cancellation.Token);
            await stream.Blocked.Task;
            cancellation.Cancel();
            await ThrowsAsync<OperationCanceledException>(() => pending);
            Check(stream.Writes.Count == 1 && !stream.Disposed, "cancellation does not retry or take stream ownership");
        }
        foreach (bool blockWrite in new[] { false, true })
        {
            using var stream = new FakeStream(Frames(), blockRead: !blockWrite, blockWrite: blockWrite);
            await ThrowsAsync<TimeoutException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, TimeSpan.FromMilliseconds(50)));
            Check(stream.Writes.Count == 1 && !stream.Disposed, "deadline bounds pending I/O without retry");
        }
        using (var stream = new FakeStream(Frames()) { FailWrite = true })
        {
            await ThrowsAsync<IOException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout));
            Check(stream.Writes.Count == 1 && stream.PositionRead == 0, "failed write never retries or reads");
        }
        using (var stream = new FakeStream(Frames()) { FailRead = true })
        {
            await ThrowsAsync<IOException>(() => WirelessLightingReader.ReadFromStreamAsync(stream, Timeout));
            CheckQuery(stream);
        }
    }

    private sealed class FakeStream : Stream
    {
        private readonly byte[] data;
        private readonly int chunk;
        private readonly bool blockRead;
        private readonly bool blockWrite;
        public readonly List<byte[]> Writes = new List<byte[]>();
        public readonly TaskCompletionSource<bool> Blocked = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public int PositionRead { get; private set; }
        public int Flushes { get; private set; }
        public bool Disposed { get; private set; }
        public bool FailWrite { get; set; }
        public bool FailRead { get; set; }
        public FakeStream(IEnumerable<byte[]> frames, int chunk = 20, int truncate = -1, bool blockRead = false, bool blockWrite = false)
        {
            data = frames.SelectMany(f => f).ToArray();
            if (truncate >= 0) Array.Resize(ref data, truncate);
            this.chunk = chunk; this.blockRead = blockRead; this.blockWrite = blockWrite;
        }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailRead) throw new IOException("Injected read failure.");
            if (blockRead) await Block(cancellationToken);
            int count = Math.Min(Math.Min(chunk, buffer.Length), data.Length - PositionRead);
            data.AsMemory(PositionRead, count).CopyTo(buffer);
            PositionRead += count;
            return count;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(buffer.ToArray());
            if (FailWrite) throw new IOException("Injected write failure.");
            if (blockWrite) await Block(cancellationToken);
        }
        private async Task Block(CancellationToken token)
        {
            Blocked.TrySetResult(true);
            await Task.Delay(System.Threading.Timeout.Infinite, token);
        }
        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Flushes++; return Task.CompletedTask;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override void Flush() => throw new Exception("Unexpected synchronous I/O");
        public override int Read(byte[] buffer, int offset, int count) => throw new Exception("Unexpected synchronous I/O");
        public override void Write(byte[] buffer, int offset, int count) => throw new Exception("Unexpected synchronous I/O");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
