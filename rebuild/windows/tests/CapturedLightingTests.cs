using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class CapturedLightingTests
{
    private static int checks;
    private static void Check(bool condition, string name) { checks++; if (!condition) throw new Exception(name); }
    private static byte[][] Frames(JsonElement phase, string name) => phase.GetProperty(name).EnumerateArray().Select(value => Convert.FromHexString(value.GetString())).ToArray();
    private static void Main()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("LightingFixture.json");
        using JsonDocument document = JsonDocument.Parse(stream);
        JsonElement root = document.RootElement;
        Check(root.GetProperty("BinarySha256").GetString() == "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6", "exact source snapshot");
        JsonElement phases = root.GetProperty("Phases");
        foreach (string name in new[] { "select-first-effect", "restore-original-effect" })
        {
            JsonElement phase = phases.GetProperty(name);
            Check(WirelessLightingProtocol.CreateQuery().SequenceEqual(Frames(phase, "QueryFramesHex").Single()), "actual outgoing query fixture");
            byte[][] responses = Frames(phase, "ReadFramesHex");
            byte[] decoded = WirelessLightingProtocol.DecodeBlock(responses);
            Check(Convert.ToHexString(decoded).Equals(phase.GetProperty("ReadBlockHex").GetString(), StringComparison.OrdinalIgnoreCase), "actual dispatcher response fixture");
            Check(responses.Any(frame => (frame.Take(19).Sum(value => value) & 255) != frame[19]), "do not invent an additive response checksum rule");
            byte[] write = Convert.FromHexString(phase.GetProperty("WriteBlockHex").GetString());
            byte[][] encoded = Rk3632Codec.EncodeRequest(4, 0, write);
            byte[][] actual = Frames(phase, "WriteFramesHex");
            Check(encoded.Length == actual.Length, "actual outgoing packet count");
            for (int index = 0; index < encoded.Length; index++)
                Check(encoded[index].SequenceEqual(actual[index]), "full byte-for-byte outgoing command-4 fixture " + index);
            byte[][] echoes = Frames(phase, "EchoFramesHex");
            Check(echoes.Length == actual.Length, "echo count");
            for (int index = 0; index < echoes.Length; index++)
            {
                Check(echoes[index].SequenceEqual(actual[index]), "observed echo fixture");
                Check(Rk3632Codec.InspectResponse(echoes[index], 4) == Rk3632ResponseKind.Match, "bounded response predicate");
            }
            int[] changed = Enumerable.Range(0, 128).Where(index => decoded[index] != write[index]).ToArray();
            Check(changed.SequenceEqual(new[] { 10 }), "only mode offset changed, not inferred from UI label");
        }
        JsonElement first = phases.GetProperty("select-first-effect"), restore = phases.GetProperty("restore-original-effect");
        Check(first.GetProperty("WriteBlockHex").GetString() == restore.GetProperty("ReadBlockHex").GetString(), "later device query reflects first write");
        Check(first.GetProperty("ReadBlockHex").GetString() == restore.GetProperty("WriteBlockHex").GetString(), "restoration output equals original block");
        Console.WriteLine("PASS captured lighting: " + checks + " assertions; no hardware opened by tests.");
    }
}
