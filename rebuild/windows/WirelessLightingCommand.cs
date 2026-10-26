using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace RkRebuild
{
    internal static class WirelessLightingCommand
    {
        public static void RequireVendorUtilityClosed()
        {
            Process[] processes = Process.GetProcessesByName("DeviceDriver");
            try
            {
                if (processes.Length != 0) throw new InvalidOperationException("Close the RK vendor utility normally before querying; competing readers can consume each other's replies.");
            }
            finally { foreach (Process process in processes) process.Dispose(); }
        }

        public static async Task<string> ReadAsync(string identity)
        {
            if (identity == null || !Regex.IsMatch(identity, "^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}$"))
                throw new ArgumentException("Use an explicit VID:PID, such as the identity shown by HID diagnostics.");
            RequireVendorUtilityClosed();
            string[] parts = identity.Split(':');
            CompatibilityCatalog catalog = CompatibilityResources.Load();
            if (catalog.Match(parts[0], parts[1]).Count == 0)
                throw new InvalidOperationException("This identity is absent from the keyboard catalogues; no probe was sent.");
            HidDiscoveryResult discovery = WindowsHidDiscovery.Enumerate();
            HidEndpoint[] candidates = discovery.Endpoints.Where(endpoint =>
                endpoint.VendorId.Equals(parts[0], StringComparison.OrdinalIgnoreCase) &&
                endpoint.ProductId.Equals(parts[1], StringComparison.OrdinalIgnoreCase) &&
                endpoint.UsagePage == "FF02" && endpoint.Usage == "0002" &&
                endpoint.InputReportBytes == 20 && endpoint.OutputReportBytes == 20 && String.IsNullOrEmpty(endpoint.Error)).ToArray();
            if (candidates.Length != 1)
                throw new InvalidOperationException("Need exactly one matching 20-byte vendor endpoint; found " + candidates.Length + ". No query was sent.");
            HidEndpoint selected = candidates[0];
            byte[] block = await WirelessLightingReader.ReadAsync(selected, TimeSpan.FromSeconds(8));
            return JsonSerializer.Serialize(new {
                Format = "rk-rebuild-experimental-lighting-read", SchemaVersion = 1,
                selected.VendorId, selected.ProductId, selected.VersionNumber, selected.UsagePage, selected.Usage,
                LightingBlockHex = Convert.ToHexString(block), SettingsWritesPerformed = false,
                QueryCommand = "44", Transport = "20-byte wireless configuration endpoint",
                Boundary = "An explicit query request was sent. This is lighting configuration, not firmware, and does not establish a physical model from a shared ID. No guessed response checksum was applied."
            }, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
