using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Text.Json;
using RkRebuild;

internal static class Program
{
    private static int _passed;
    private static void Check(bool condition, string label)
    {
        if (!condition) throw new Exception("FAIL: " + label);
        _passed++;
    }
    private static void Reject(Action action, string label)
    {
        try { action(); } catch { _passed++; return; }
        throw new Exception("FAIL (accepted invalid input): " + label);
    }
    private static void Main()
    {
        MacroTimeline timeline = new MacroTimeline { Name = "Unicode Ω draft", LoopMode = "count", LoopCount = 99, Steps = new List<MacroStep> {
            new MacroStep { Kind = "key", Action = "A down", DelayMs = 0 },
            new MacroStep { Kind = "mouse", Action = "left click", DelayMs = 25 },
            new MacroStep { Kind = "delay", Action = "", DelayMs = 60000 }
        } };
        string json = MacroTimelineCodec.Export(timeline);
        MacroTimeline copy = MacroTimelineCodec.Import(json);
        Check(MacroTimelineCodec.Export(copy) == json, "deterministic JSON round trip");
        Check(copy.Steps.Count == 3 && copy.Steps[2].DelayMs == 60000 && copy.Name == timeline.Name && copy.LoopCount == 99, "all row types, bounds and metadata preserved");
        copy.Steps[0].Action = "changed";
        Check(timeline.Steps[0].Action == "A down", "import is independent");
        MacroTimelineCodec.Move(copy.Steps, 0, 1);
        Check(copy.Steps[0].Kind == "mouse" && copy.Steps[1].Action == "changed", "move down");
        MacroTimelineCodec.Move(copy.Steps, 1, -1);
        Check(copy.Steps[0].Action == "changed", "move up");
        MacroTimelineCodec.Move(copy.Steps, 0, -1);
        MacroTimelineCodec.Move(copy.Steps, -1, 1);
        Check(copy.Steps[0].Action == "changed", "out of bounds moves are no-ops");
        Reject(() => MacroTimelineCodec.Import("{}"), "missing envelope");
        Reject(() => MacroTimelineCodec.Import("null"), "null root");
        Reject(() => MacroTimelineCodec.Import(json.Replace("rk-rebuild-local-timeline", "keydeck-macro-v1")), "foreign format");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"SchemaVersion\": 1", "\"SchemaVersion\": 2")), "future schema");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"Name\":", "\"Unexpected\": 1, \"Name\":")), "unknown members");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"DelayMs\": 25", "\"Other\": 25")), "missing required delay");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"Name\":", "\"Name\": \"duplicate\", \"Name\":")), "duplicate properties");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"DelayMs\": 25", "\"DelayMs\": 2.5")), "fractional milliseconds");
        Reject(() => MacroTimelineCodec.Import(json.Replace("\"DelayMs\": 25", "\"DelayMs\": \"25\"")), "string milliseconds");
        Reject(() => MacroTimelineCodec.Import(new string(' ', MacroTimelineCodec.MaxBytes + 1)), "byte bound");
        Reject(() => MacroTimelineCodec.Import(new string('Ω', MacroTimelineCodec.MaxBytes / 2 + 1)), "UTF-8 byte bound");
        Reject(() => MacroTimelineCodec.Import("{"), "malformed JSON");
        Reject(() => MacroTimelineCodec.Validate(null), "null timeline");
        foreach (int bad in new[] { -1, 60001 })
            Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Steps = new List<MacroStep> { new MacroStep { DelayMs = bad } } }), "invalid delay");
        foreach (int bad in new[] { 0, 100 })
            Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { LoopCount = bad }), "invalid count");
        Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { LoopMode = "play-now" }), "unknown mode");
        Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Name = " " }), "blank name");
        Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Name = new string('x', 49) }), "name bound");
        Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Steps = null }), "null steps");
        Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Steps = new List<MacroStep> { null } }), "null row");
        foreach (MacroStep step in new[] { new MacroStep { Kind = "native" }, new MacroStep { Action = " " }, new MacroStep { Action = null }, new MacroStep { Action = new string('x', 101) }, new MacroStep { Kind = "delay", Action = "not empty" } })
            Reject(() => MacroTimelineCodec.Validate(new MacroTimeline { Steps = new List<MacroStep> { step } }), "invalid row shape");
        MacroTimeline max = new MacroTimeline { Steps = Enumerable.Range(0, 200).Select(i => new MacroStep()).ToList() };
        Check(MacroTimelineCodec.Import(MacroTimelineCodec.Export(max)).Steps.Count == 200, "200 rows round trip");
        max.Steps.Add(new MacroStep());
        Reject(() => MacroTimelineCodec.Export(max), "201 rows");
        Check(MacroTimelineCodec.Import(MacroTimelineCodec.Export(new MacroTimeline())).Steps.Count == 0, "empty draft valid");
        string fixture = Path.Combine(AppContext.BaseDirectory, "macro-test-fixture.json");
        try
        {
            File.WriteAllText(fixture, json, new UTF8Encoding(true));
            Check(MacroTimelineCodec.Export(MacroTimelineCodec.ReadFile(fixture)) == json, "bounded file read with UTF-8 BOM");
            File.WriteAllBytes(fixture, new byte[MacroTimelineCodec.MaxBytes + 1]);
            Reject(() => MacroTimelineCodec.ReadFile(fixture), "oversized file");
            File.WriteAllBytes(fixture, new byte[] { 0xFF, 0xFF });
            Reject(() => MacroTimelineCodec.ReadFile(fixture), "invalid UTF-8 file");
        }
        finally { if (File.Exists(fixture)) File.Delete(fixture); }
        // Same additive settings shape: old notes survive deserialization and reserialization.
        LegacySettings old = JsonSerializer.Deserialize<LegacySettings>("{\"MacroDrafts\":{\"021E\":[\"keep me\"]}}");
        old.MacroTimelines["021E"] = new List<MacroTimeline> { timeline };
        LegacySettings saved = JsonSerializer.Deserialize<LegacySettings>(JsonSerializer.Serialize(old));
        Check(saved.MacroDrafts["021E"][0] == "keep me" && saved.MacroTimelines["021E"][0].Steps.Count == 3, "separate legacy and structured settings round trip");
        Console.WriteLine("PASS: " + _passed + " macro model/validation checks (no WPF, capture, playback, or device access).");
    }
    public sealed class LegacySettings
    {
        public Dictionary<string, List<string>> MacroDrafts { get; set; } = new Dictionary<string, List<string>>();
        public Dictionary<string, List<MacroTimeline>> MacroTimelines { get; set; } = new Dictionary<string, List<MacroTimeline>>();
    }
}
