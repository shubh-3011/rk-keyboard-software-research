using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using RkRebuild;

internal static class G5FeatureTests
{
    private static int checks;
    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition) throw new Exception(message);
    }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    private static void Equal(byte[] actual, byte[] expected, string message)
        => Check(actual.AsSpan().SequenceEqual(expected), message);

    private static void Fixtures()
    {
        // Manually written headers, not generated via a second codec.
        var one = new byte[520];
        new byte[] { 9, 3, 0xA7, 0, 1, 0, 3, 0, 0x10, 0x20, 0xFF }.CopyTo(one, 0);
        Equal(G5FeatureCodec.BuildRequestPacket(9, 1, 3, 0xA7, 3, 0,
            new byte[] { 0x10, 0x20, 0xFF }), one, "three-byte write fixture");
        var final = new byte[520];
        new byte[] { 0xAB, 0xCD, 0xEF, 0, 2, 1, 1, 0, 0x42 }.CopyTo(final, 0);
        Equal(G5FeatureCodec.BuildRequestPacket(0xAB, 1, 0xCD, 0xEF, 513, 1,
            new byte[] { 0x42 }), final, "513-byte final chunk fixture");
        var query = new byte[520];
        new byte[] { 9, 0x84, 0, 0, 1, 0, 0x80, 0 }.CopyTo(query, 0);
        Equal(G5FeatureCodec.BuildRequestPacket(9, 2, 0x84, 0, 128, 0,
            ReadOnlySpan<byte>.Empty), query, "0x40FAD0 query wire fixture");
        var full = new byte[520];
        new byte[] { 0, 0xFF, 0x80, 0, 0xFF, 0xFE, 0, 2 }.CopyTo(full, 0);
        Equal(G5FeatureCodec.BuildRequestPacket(0, 2, 0xFF, 0x80, 130560, 254,
            ReadOnlySpan<byte>.Empty), full, "maximum count/index/full length fixture");
    }

    private static void Boundaries()
    {
        // Every supported transfer size (1..130560), first AND last packet.
        // Covers every partial chunk length and all 255 packet-count transitions.
        for (int total = 1; total <= G5FeatureCodec.MaxTransferBytes; total++)
        {
            int count = (total + 511) / 512;
            foreach (int index in new[] { 0, count - 1 })
            {
                byte[] r = G5FeatureCodec.BuildRequestPacket(0x11, 2, 0x82, 0x37,
                    total, index, ReadOnlySpan<byte>.Empty);
                int n = Math.Min(512, total - index * 512);
                Check(r.Length == 520 && r[0] == 0x11 && r[1] == 0x82 && r[2] == 0x37
                    && r[3] == 0 && r[4] == count && r[5] == index
                    && r[6] + 256 * r[7] == n, "all-size header");
                Check(r.AsSpan(8).IndexOfAnyExcept((byte)0) < 0, "read requests are zero filled");
            }
        }
        // Every write chunk size; checksum-looking bytes must remain literal data.
        for (int n = 1; n <= 512; n++)
        {
            var data = new byte[n];
            for (int i = 0; i < n; i++) data[i] = (byte)(i * 17 + 3);
            byte[] before = (byte[])data.Clone();
            byte[] r = G5FeatureCodec.BuildRequestPacket(9, 1, 5, 6, n, 0, data);
            Check(r.AsSpan(8, n).SequenceEqual(data), "write payload");
            Check(r.AsSpan(8 + n).IndexOfAnyExcept((byte)0) < 0, "zero tail");
            Equal(data, before, "input immutable");
            Check(r[3] == 0 && r[5] == 0, "no checksum injected");
        }
        // All packet indices, not just the endpoints.
        for (int i = 0; i < 255; i++)
            Check(G5FeatureCodec.BuildRequestPacket(1, 2, 2, 3, 130560, i,
                ReadOnlySpan<byte>.Empty)[5] == i, "all indices");
        foreach (int bad in new[] { int.MinValue, -1, 0, 130561, int.MaxValue })
            Throws<ArgumentOutOfRangeException>(() => G5FeatureCodec.BuildRequestPacket(1, 2, 3, 4, bad, 0, Array.Empty<byte>()));
        foreach (int op in new[] { int.MinValue, -1, 0, 3, int.MaxValue })
            Throws<ArgumentOutOfRangeException>(() => G5FeatureCodec.BuildRequestPacket(1, op, 3, 4, 1, 0, Array.Empty<byte>()));
        foreach (int index in new[] { -1, 1, int.MaxValue })
            Throws<ArgumentOutOfRangeException>(() => G5FeatureCodec.BuildRequestPacket(1, 2, 3, 4, 1, index, Array.Empty<byte>()));
        Throws<ArgumentException>(() => G5FeatureCodec.BuildRequestPacket(1, 1, 3, 4, 1, 0, Array.Empty<byte>()));
        Throws<ArgumentException>(() => G5FeatureCodec.BuildRequestPacket(1, 1, 3, 4, 1, 0, new byte[2]));
        Throws<ArgumentException>(() => G5FeatureCodec.BuildRequestPacket(1, 2, 3, 4, 1, 0, new byte[1]));
    }

    private static void Responses()
    {
        var response = new byte[520];
        Array.Fill(response, (byte)0xFF);
        response[1] = 0x84;
        // Deliberately inconsistent ID/option/status/count/index/length/signature:
        // the source does NOT reject these. Do not add invented integrity checks.
        Check(G5FeatureCodec.MatchesVendorReadCommand(response, 0x84), "command-only vendor predicate");
        for (int n = 1; n <= 512; n++)
            Check(G5FeatureCodec.CopyReadPayload(response, 0x84, n).Length == n, "response copy bounds");
        Check(!G5FeatureCodec.MatchesVendorReadCommand(response, 4), "wrong command");
        Check(!G5FeatureCodec.MatchesVendorReadCommand(new byte[519], 0), "short response");
        Check(!G5FeatureCodec.MatchesVendorReadCommand(new byte[521], 0), "long response");
        Throws<ArgumentException>(() => G5FeatureCodec.CopyReadPayload(response, 4, 128));
        Throws<ArgumentOutOfRangeException>(() => G5FeatureCodec.CopyReadPayload(response, 0x84, 0));
        Throws<ArgumentOutOfRangeException>(() => G5FeatureCodec.CopyReadPayload(response, 0x84, 513));
    }

    // Optional local source validation: reads only the caller-specified PE file.
    // SHA binds the whole source; RVA witnesses bind selected instructions to
    // true entries. No vendor process is started and no HID handles are opened.
    private static void ValidateSource(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        Check(Convert.ToHexString(SHA256.HashData(bytes)).Equals(G5FeatureCodec.SourceSha256,
            StringComparison.OrdinalIgnoreCase), "exact installed 4.06 hash");
        using var pe = new PEReader(new MemoryStream(bytes, false));
        Check(pe.PEHeaders.PEHeader.ImageBase == 0x400000, "image base");
        void Witness(int va, string hex)
        {
            byte[] expected = Convert.FromHexString(hex);
            byte[] actual = pe.GetSectionData(va - 0x400000).GetContent(0, expected.Length).ToArray();
            Equal(actual, expected, "source witness " + va.ToString("X"));
        }
        Witness(0x40F700, "81EC1C020000A16016600033C4898424180200008B842420020000558BAC24340200005733FF3BEF89442408894C2410");
        Witness(0x40F7ED, "68080200008D4424246A0050E8121616008A8424540200008A8C24400200008A9424480200008844242E8B4424208854242D884C242C0FB64C24288BD38844243140C1FA0883C40CC644242300884C242489442414885C24268854242783FE0175198B44241885C0741103C753508D44243050E88B4A160083C40C");
        Witness(0x40F8FA, "8A4424218B8C243C0200003AC8757F8B4424");
        Witness(0x40FB8E, "8854241CC644241D84C644241E00C644241F00C644242001885C242288442423");
        Witness(0x40ECE3, "C7062CBA5C00"); // constructor vtable
        Witness(0x40ED2E, "895E08895E0466894622"); // handles and path initialization
        Witness(0x40F433, "894704"); // primary handle store
        Witness(0x40F443, "8A56E48B4C24148897D0020000"); // report ID store
        Witness(0x40F530, "668B4C2430668B54242033C066898F480200008B4F046689974A020000"); // ID words
        Witness(0x40F517, "8B5424146AFF558D47226804010000508954242C"); // inline path/capacity
        Witness(0x40F680, "0FB791480200008B4424043BD08B5424085675140FB7B14A0200003BF2"); // ID comparison
    }

    private static int Main(string[] args)
    {
        Fixtures();
        Boundaries();
        Responses();
        if (args.Length == 1) ValidateSource(args[0]);
        else if (args.Length != 0) throw new ArgumentException("Optional sole argument: exact DeviceDriver.exe path");
        Console.WriteLine("PASS G5Feature: " + checks + " checks; all 130560 supported transfer lengths; source validation "
            + (args.Length == 1 ? "PASS" : "NOT REQUESTED"));
        return 0;
    }
}
