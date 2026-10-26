using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace RkRebuild
{
    internal static class LightingBaseline
    {
        public static byte[] Parse(string json, HidEndpoint endpoint)
        {
            if (endpoint == null) throw new ArgumentNullException(nameof(endpoint));
            if (json == null || json.Length > 65536) throw new ArgumentException("Lighting baseline report exceeds its size limit.");
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            // Reject duplicate properties instead of silently accepting last-wins metadata.
            var names = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("Baseline contains duplicate fields.");
            if (root.GetProperty("Format").GetString() != "rk-rebuild-experimental-lighting-read" ||
                root.GetProperty("SchemaVersion").GetInt32() != 1 || root.GetProperty("SettingsWritesPerformed").GetBoolean() ||
                !String.Equals(root.GetProperty("VendorId").GetString(), endpoint.VendorId, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(root.GetProperty("ProductId").GetString(), endpoint.ProductId, StringComparison.OrdinalIgnoreCase) ||
                root.GetProperty("VersionNumber").GetUInt16() != endpoint.VersionNumber ||
                root.GetProperty("UsagePage").GetString() != endpoint.UsagePage || root.GetProperty("Usage").GetString() != endpoint.Usage)
                throw new InvalidDataException("Baseline is not a matching native lighting-read report.");
            string hex = root.GetProperty("LightingBlockHex").GetString();
            if (hex == null || hex.Length != 256) throw new InvalidDataException("Baseline must contain exactly 128 bytes.");
            byte[] block = Convert.FromHexString(hex);
            if (block[126] != 0x5a || block[127] != 0xa5) throw new InvalidDataException("Baseline signature is invalid.");
            return block;
        }

        public static byte[] Load(string path, HidEndpoint endpoint)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            byte[] buffer = new byte[65537];
            int count = 0, read;
            while (count < buffer.Length && (read = stream.Read(buffer, count, buffer.Length - count)) != 0) count += read;
            if (count > 65536) throw new InvalidDataException("Lighting baseline report exceeds its size limit.");
            return Parse(new UTF8Encoding(false, true).GetString(buffer, 0, count).TrimStart('\uFEFF'), endpoint);
        }
    }
}
