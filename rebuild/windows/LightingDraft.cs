using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace RkRebuild
{
    // Local draft coordinates refer only to the embedded Hub 4.6 catalog.
    // No transport bytes, physical percentages, or hardware state are inferred.
    internal sealed class LightingDraft
    {
        public string CatalogSnapshot { get; set; } = "hub-4.6";
        public int ProfileSlot { get; set; }
        public int BrightnessIndex { get; set; }
    }

    internal static class LightingDraftRules
    {
        public static int[] ParseByteList(string raw)
        {
            if (String.IsNullOrWhiteSpace(raw)) return Array.Empty<int>();
            string[] parts = raw.Split(',');
            if (parts.Length > 20) throw new InvalidDataException("Lighting lookup table exceeds 20 entries.");
            int[] values = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                string token = parts[i].Trim();
                bool hex = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                if (!Int32.TryParse(hex ? token.Substring(2) : token, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.Integer,
                                    CultureInfo.InvariantCulture, out int number) || number < 0 || number > 255)
                    throw new InvalidDataException("Lighting lookup entries must be explicit bytes; no guessed fallback was applied.");
                values[i] = number;
            }
            return values;
        }

        public static void Validate(LightingDraft draft, IReadOnlyCollection<int> slots, int[] displayValues)
        {
            if (draft == null || draft.CatalogSnapshot != "hub-4.6") throw new InvalidDataException("This draft is not bound to the Hub 4.6 catalog.");
            if (slots == null || !slots.Contains(draft.ProfileSlot)) throw new InvalidDataException("Draft slot is not declared by this profile.");
            if (displayValues == null || displayValues.Length == 0 || draft.BrightnessIndex < 0 || draft.BrightnessIndex >= displayValues.Length)
                throw new InvalidDataException("Draft brightness index is outside this profile's explicit LightUI table.");
        }

        public static int? OutputValue(LightingDraft draft, int[] outputValues)
        {
            if (draft == null || outputValues == null || draft.BrightnessIndex < 0 || draft.BrightnessIndex >= outputValues.Length) return null;
            return outputValues[draft.BrightnessIndex];
        }
    }
}
