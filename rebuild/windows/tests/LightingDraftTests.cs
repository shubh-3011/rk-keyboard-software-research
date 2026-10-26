using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class LightingDraftTests
{
    private static int checks;
    private static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    private static void Reject(Action action, string label)
    {
        bool rejected = false;
        try { action(); } catch (InvalidDataException) { rejected = true; }
        Check(rejected, label);
    }
    private static void Main()
    {
        Check(LightingDraftRules.ParseByteList(null).Length == 0, "absent table is not invented");
        Check(LightingDraftRules.ParseByteList("0, 4,0xFF").SequenceEqual(new[] { 0, 4, 255 }), "explicit decimal and hex");
        foreach (string invalid in new[] { "0,", "-1", "256", "0x100", "x", String.Join(',', Enumerable.Repeat("1", 21)) })
            Reject(() => LightingDraftRules.ParseByteList(invalid), "invalid byte list");
        int[] ui = { 0, 4, 8, 12, 16, 20 };
        LightingDraft draft = new LightingDraft { ProfileSlot = 1, BrightnessIndex = 5 };
        LightingDraftRules.Validate(draft, new[] { 1, 3 }, ui);
        Check(LightingDraftRules.OutputValue(draft, new[] { 0, 1, 2, 3, 4, 9 }) == 9, "output is not display percentage");
        Check(LightingDraftRules.OutputValue(draft, new[] { 0 }) == null, "missing output index has no guessed fallback");
        LightingDraft clone = JsonSerializer.Deserialize<LightingDraft>(JsonSerializer.Serialize(draft));
        Check(clone.ProfileSlot == 1 && clone.BrightnessIndex == 5 && clone.CatalogSnapshot == "hub-4.6", "round trip snapshot binding");
        clone.CatalogSnapshot = "installed-4.06";
        Reject(() => LightingDraftRules.Validate(clone, new[] { 1 }, ui), "version mismatch");
        draft.ProfileSlot = 2;
        Reject(() => LightingDraftRules.Validate(draft, new[] { 1, 3 }, ui), "missing slot not normalized");
        draft.ProfileSlot = 1;
        foreach (int invalid in new[] { -1, 6 })
        {
            draft.BrightnessIndex = invalid;
            Reject(() => LightingDraftRules.Validate(draft, new[] { 1 }, ui), "brightness index bounds");
        }
        using (Stream source = Assembly.GetExecutingAssembly().GetManifestResourceStream("TestProfiles.json"))
        using (JsonDocument catalog = JsonDocument.Parse(source))
        {
            int profiles = 0;
            foreach (JsonElement model in catalog.RootElement.GetProperty("models").EnumerateArray())
            {
                profiles++;
                JsonElement options = model.GetProperty("profileData").GetProperty("options");
                foreach (string name in new[] { "LightUI", "LightHW" })
                    if (options.TryGetProperty(name, out JsonElement raw))
                        Check(LightingDraftRules.ParseByteList(raw.GetString()).Length > 0, "real explicit lookup " + name);
            }
            Check(profiles == 265, "all 265 embedded catalog profiles inspected, not hardware validated");
        }
        Console.WriteLine(checks + " lighting draft/model checks passed; no device was accessed.");
    }
}
