using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class LightingWritePolicyTests
{
    private static int checks;
    private static void Check(bool condition, string name) { checks++; if (!condition) throw new Exception(name); }
    private static void Reject(Action action) { checks++; try { action(); } catch { return; } throw new Exception("Expected rejection"); }
    private static HidEndpoint Endpoint(ushort vid = 0x258a, ushort pid = 0x0150, ushort version = 518,
        ushort usagePage = 0xff02, ushort usage = 2, ushort input = 20, ushort output = 20, string error = "") =>
        new HidEndpoint("opaque-test-token", new WindowsHidDiscovery.HiddAttributes { VendorID = vid, ProductID = pid, VersionNumber = version },
            new WindowsHidDiscovery.HidpCaps { UsagePage = usagePage, Usage = usage, InputReportByteLength = input, OutputReportByteLength = output }, error);
    private static string Report(HidEndpoint endpoint, byte[] block) => JsonSerializer.Serialize(new {
        Format = "rk-rebuild-experimental-lighting-read", SchemaVersion = 1, SettingsWritesPerformed = false,
        endpoint.VendorId, endpoint.ProductId, endpoint.VersionNumber, endpoint.UsagePage, endpoint.Usage,
        LightingBlockHex = Convert.ToHexString(block)
    });

    private static void Main()
    {
        using Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("LightingFixture.json");
        using JsonDocument fixture = JsonDocument.Parse(resource);
        byte[] baseline = Convert.FromHexString(fixture.RootElement.GetProperty("Phases").GetProperty("select-first-effect").GetProperty("ReadBlockHex").GetString());
        HidEndpoint endpoint = Endpoint();
        using Stream reconnectedResource = Assembly.GetExecutingAssembly().GetManifestResourceStream("ReconnectedFixture.json");
        using JsonDocument reconnected = JsonDocument.Parse(reconnectedResource);
        byte[] second = Convert.FromHexString(reconnected.RootElement.GetProperty("Phases").GetProperty("select-first-effect").GetProperty("ReadBlockHex").GetString());
        Check(!second.SequenceEqual(baseline), "second independently observed configuration differs");
        Check(LightingWritePolicy.Rejection(endpoint, second, 1) == null, "second complete observed fingerprint enabled");
        for (int index = 0; index < 128; index++)
        {
            if (index == 10) continue;
            byte[] changed = (byte[])second.Clone(); changed[index] ^= 1;
            Check(LightingWritePolicy.Rejection(endpoint, changed, 1) != null, "second fingerprint rejects unknown bytes " + index);
        }
        byte[] snapshot = (byte[])baseline.Clone();
        for (byte current = 0; current <= 1; current++)
        {
            byte[] block = (byte[])baseline.Clone(); block[10] = current;
            for (byte target = 0; target <= 1; target++) Check(LightingWritePolicy.Rejection(endpoint, block, target) == null, "observed modes only");
        }
        for (int index = 0; index < 128; index++)
        {
            if (index == 10) continue;
            byte[] block = (byte[])baseline.Clone(); block[index] ^= 1;
            Check(LightingWritePolicy.Rejection(endpoint, block, 1) != null, "all unobserved bytes fail closed " + index);
        }
        for (int mode = 2; mode < 256; mode++)
        {
            Check(LightingWritePolicy.Rejection(endpoint, baseline, (byte)mode) != null, "target mode rejected");
            byte[] block = (byte[])baseline.Clone(); block[10] = (byte)mode;
            Check(LightingWritePolicy.Rejection(endpoint, block, 0) != null, "current mode rejected");
        }
        foreach (HidEndpoint other in new[] { Endpoint(vid: 1), Endpoint(pid: 1), Endpoint(version: 519), Endpoint(usagePage: 1), Endpoint(usage: 6), Endpoint(input: 8), Endpoint(output: 2), Endpoint(error: "unavailable") })
            Check(LightingWritePolicy.Rejection(other, baseline, 1) != null, "metadata alone cannot enable writes");
        Check(LightingWritePolicy.Rejection(null, baseline, 1) != null, "null endpoint");
        Check(LightingWritePolicy.Rejection(endpoint, null, 1) != null, "null baseline");
        Check(LightingWritePolicy.Rejection(endpoint, new byte[127], 1) != null, "short baseline");
        Check(baseline.SequenceEqual(snapshot), "policy did not mutate caller data");
        string report = Report(endpoint, baseline);
        Check(LightingBaseline.Parse(report, endpoint).SequenceEqual(baseline), "matching baseline parsed");
        Reject(() => LightingBaseline.Parse(report, Endpoint(version: 519)));
        Reject(() => LightingBaseline.Parse(report.Replace("\"SchemaVersion\":1", "\"SchemaVersion\":2"), endpoint));
        Reject(() => LightingBaseline.Parse(report.Replace("\"SettingsWritesPerformed\":false", "\"SettingsWritesPerformed\":true"), endpoint));
        Reject(() => LightingBaseline.Parse(report.Replace("\"SchemaVersion\":1", "\"SchemaVersion\":1,\"SchemaVersion\":1"), endpoint));
        Reject(() => LightingBaseline.Parse("[]", endpoint));
        Reject(() => LightingBaseline.Parse(null, endpoint));
        Reject(() => LightingBaseline.Parse(new string(' ', 65537), endpoint));
        Reject(() => LightingBaseline.Parse(report.Replace(Convert.ToHexString(baseline), "00"), endpoint));
        Reject(() => LightingBaseline.Parse(report.Replace(Convert.ToHexString(baseline), new string('Q', 256)), endpoint));
        byte[] badSignature = (byte[])baseline.Clone(); badSignature[127] = 0;
        Reject(() => LightingBaseline.Parse(Report(endpoint, badSignature), endpoint));
        Console.WriteLine("PASS lighting write policy: " + checks + " checks; no device calls.");
    }
}
