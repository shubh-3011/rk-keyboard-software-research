using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace RkRebuild
{
    internal enum CompatibilityStatus
    {
        CataloguedOnly
    }

    // A source declaration, not evidence of a tested device or a writable protocol.
    internal sealed class CompatibilityEntry
    {
        public string SourceSnapshot { get; }
        public string ProfileId { get; }
        public string DescriptorId { get; }
        public string ModelName { get; }
        public string Connection { get; }
        public string VendorId { get; }
        public string ProductId { get; }
        public string UsagePage { get; }
        public string Usage { get; }
        public string DeclaredProtocol { get; }
        public bool IsSpecialized { get; }
        public CompatibilityStatus Status => CompatibilityStatus.CataloguedOnly;
        public bool HardwareWritesAllowed => false;

        internal CompatibilityEntry(string snapshot, string profileId, string descriptorId,
            string modelName, string connection, string vendorId, string productId,
            string usagePage, string usage, string protocol, bool specialized)
        {
            SourceSnapshot = snapshot;
            ProfileId = profileId;
            DescriptorId = descriptorId;
            ModelName = modelName;
            Connection = connection;
            VendorId = vendorId;
            ProductId = productId;
            UsagePage = usagePage;
            Usage = usage;
            DeclaredProtocol = protocol;
            IsSpecialized = specialized;
        }
    }

    internal sealed class CompatibilityCatalog
    {
        public IReadOnlyList<CompatibilityEntry> Entries { get; }
        public bool HardwareWritesAllowed => false;

        private CompatibilityCatalog(List<CompatibilityEntry> entries)
        {
            Entries = entries.AsReadOnly();
        }

        public static CompatibilityCatalog Load(string hubJson, string driveJson)
        {
            var entries = new List<CompatibilityEntry>();
            using (JsonDocument hub = JsonDocument.Parse(hubJson))
            {
                string vendor = NormalizeHex(Text(hub.RootElement, "vendorId"));
                if (TryArray(hub.RootElement, "models", out JsonElement models))
                {
                    int index = 0;
                    foreach (JsonElement model in models.EnumerateArray())
                    {
                        string code = Text(model, "code");
                        bool direct = model.TryGetProperty("isDirectPid", out JsonElement flag)
                            && flag.ValueKind == JsonValueKind.True;
                        entries.Add(new CompatibilityEntry("hub-4.6", code, "models[" + index++ + "]",
                            Text(model, "name"), Text(model, "connection"),
                            direct ? vendor : "", direct ? NormalizeHex(code) : "",
                            "", "", Text(model, "protocol_type"), false));
                    }
                }
            }
            using (JsonDocument drive = JsonDocument.Parse(driveJson))
            {
                AddDrive(entries, drive.RootElement, "models", false);
                AddDrive(entries, drive.RootElement, "specializedKeyboardProfiles", true);
            }
            return new CompatibilityCatalog(entries);
        }

        // Return every exact declaration; shared IDs never select a family or protocol.
        public IReadOnlyList<CompatibilityEntry> Match(string vendorId, string productId)
        {
            string vendor = NormalizeHex(vendorId);
            string product = NormalizeHex(productId);
            var matches = new List<CompatibilityEntry>();
            if (vendor.Length != 0 && product.Length != 0)
                foreach (CompatibilityEntry entry in Entries)
                    if (entry.VendorId == vendor && entry.ProductId == product)
                        matches.Add(entry);
            return matches.AsReadOnly();
        }

        private static void AddDrive(List<CompatibilityEntry> entries, JsonElement root,
            string arrayName, bool specialized)
        {
            if (!TryArray(root, arrayName, out JsonElement models)) return;
            int index = 0;
            foreach (JsonElement model in models.EnumerateArray())
            {
                string descriptor = arrayName + "[" + index++ + "]";
                // The mouseModels array is deliberately never read. Also exclude explicit
                // non-keyboard records if a future source mixes descriptor types.
                string deviceType = Text(model, "device_type");
                if (deviceType.Length != 0 && !String.Equals(deviceType, "Keyboard", StringComparison.OrdinalIgnoreCase))
                    continue;
                string profile = Text(model, "profile_id");
                entries.Add(new CompatibilityEntry("rk-drive-2026-10-18",
                    profile.Length == 0 ? descriptor : profile, descriptor,
                    Text(model, "name"), Text(model, "connection"),
                    Identity(model, "vendor_id"), Identity(model, "product_id"),
                    Identity(model, "usage_page"), Identity(model, "usage"),
                    Text(model, "protocol_type"), specialized));
            }
        }

        private static bool TryArray(JsonElement root, string name, out JsonElement value)
        {
            return root.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.Array;
        }

        private static string Text(JsonElement item, string name)
        {
            return item.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() : "";
        }

        private static string Identity(JsonElement item, string name)
        {
            // An invalid explicitly supplied hex identity must not silently fall back.
            if (item.TryGetProperty(name + "_hex", out JsonElement hex))
                return hex.ValueKind == JsonValueKind.String ? NormalizeHex(hex.GetString()) : "";
            if (!item.TryGetProperty(name, out JsonElement value)) return "";
            if (value.ValueKind == JsonValueKind.String) return NormalizeHex(value.GetString());
            return value.ValueKind == JsonValueKind.Number && value.TryGetUInt16(out ushort number)
                ? number.ToString("X4", CultureInfo.InvariantCulture) : "";
        }

        private static string NormalizeHex(string value)
        {
            if (value == null) return "";
            string digits = value.Trim();
            if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) digits = digits.Substring(2);
            if (digits.Length < 1 || digits.Length > 4) return "";
            foreach (char digit in digits)
                if (!((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') || (digit >= 'A' && digit <= 'F')))
                    return "";
            return UInt16.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort number)
                ? number.ToString("X4", CultureInfo.InvariantCulture) : "";
        }
    }
}
