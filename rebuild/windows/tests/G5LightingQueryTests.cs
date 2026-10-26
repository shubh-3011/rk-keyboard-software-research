using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class G5LightingQueryTests
{
    private static int checks;
    private static void Check(bool value, string reason) { checks++; if (!value) throw new Exception(reason); }
    private static void Reject(Action action) { checks++; try { action(); } catch { return; } throw new Exception("Expected rejection"); }
    private static void Main()
    {
        Check(Marshal.SizeOf<G5FeatureMetadata.NativeCapability>() == 72, "native capability stride");
        Check(Marshal.OffsetOf<G5FeatureMetadata.NativeCapability>("ReportId").ToInt32() == 2, "report ID offset");
        for (int value = 0; value <= 255; value++)
        {
            byte id = (byte)value;
            byte[] request = G5LightingQueryProtocol.CreateQuery(id);
            byte[] expected = new byte[520]; expected[0] = id; expected[1] = 0x84; expected[4] = 1; expected[6] = 128;
            Check(request.SequenceEqual(expected), "complete fixed query request");
            byte[] response = (byte[])request.Clone(); response[8 + 126] = 0x5a; response[8 + 127] = 0xa5;
            byte[] block = G5LightingQueryProtocol.Decode(id, response);
            Check(block.Length == 128 && block[126] == 0x5a && block[127] == 0xa5, "signature and payload extraction");
            response[8] = 27; Check(block[0] == 0, "returned block is detached");
            byte[] wrongId = (byte[])response.Clone(); wrongId[0] ^= 1;
            Reject(() => G5LightingQueryProtocol.Decode(id, wrongId));
        }
        Reject(() => G5LightingQueryProtocol.Decode(9, null));
        Reject(() => G5LightingQueryProtocol.Decode(9, new byte[519]));
        byte[] invalid = G5LightingQueryProtocol.CreateQuery(9);
        Reject(() => G5LightingQueryProtocol.Decode(9, invalid));
        invalid[134] = 0x5a; invalid[135] = 0xa5; invalid[1] = 4;
        Reject(() => G5LightingQueryProtocol.Decode(9, invalid));
        Reject(() => G5FeatureMetadata.ValidateEndpoint(null));
        var attributes = new WindowsHidDiscovery.HiddAttributes { VendorID = 0x258a, ProductID = 0x01af, VersionNumber = 8457 };
        var caps = new WindowsHidDiscovery.HidpCaps { UsagePage = 0xff02, Usage = 2, FeatureReportByteLength = 520, InputReportByteLength = 8 };
        G5FeatureMetadata.ValidateEndpoint(new HidEndpoint("opaque", attributes, caps, ""));
        caps.FeatureReportByteLength = 1032;
        Reject(() => G5FeatureMetadata.ValidateEndpoint(new HidEndpoint("opaque", attributes, caps, "")));
        caps.FeatureReportByteLength = 520; caps.UsagePage = 1; caps.Usage = 6;
        Reject(() => G5FeatureMetadata.ValidateEndpoint(new HidEndpoint("opaque", attributes, caps, "")));
        using Stream source = Assembly.GetExecutingAssembly().GetManifestResourceStream("NativeG5Query.json");
        using JsonDocument native = JsonDocument.Parse(source);
        JsonElement live = native.RootElement;
        byte liveId = Convert.ToByte(live.GetProperty("ReportIdHex").GetString(), 16);
        byte[] header = Convert.FromHexString(live.GetProperty("ResponseHeaderHex").GetString());
        byte[] payload = Convert.FromHexString(live.GetProperty("LightingBlockHex").GetString());
        Check(live.GetProperty("SetFeatureCalls").GetInt32() == 1 && live.GetProperty("GetFeatureCalls").GetInt32() == 1 && !live.GetProperty("SettingsWritesPerformed").GetBoolean(), "native fixture query scope");
        Check(header.Length == 8 && payload.Length == 128 && header[0] == liveId && header[1] == 0x84, "observed header/payload boundary");
        // Only the header and 128-byte lighting payload were retained. All
        // unretained feature-report padding is deliberately synthetic hostile
        // filler here, NOT claimed to be an observed 520-byte response.
        byte[] partialFixture = Enumerable.Repeat((byte)0xa7, 520).ToArray();
        header.CopyTo(partialFixture, 0); payload.CopyTo(partialFixture, 8);
        Check(G5LightingQueryProtocol.Decode(liveId, partialFixture).SequenceEqual(payload), "observed payload is extracted from byte 8, never from padding");
        Console.WriteLine("PASS G5 lighting query: " + checks + " offline checks; no hardware accessed.");
    }
}
