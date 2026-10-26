using System;
using System.Linq;
using System.Text.Json;

namespace RkRebuild
{
    internal static class HidDiagnostics
    {
        public static string Report(HidDiscoveryResult discovery, CompatibilityCatalog catalog)
        {
            return JsonSerializer.Serialize(new {
                Format = "rk-rebuild-hid-metadata", SchemaVersion = 1,
                Scope = "HID endpoint metadata only; no input reports or feature/output commands; no serial strings or device paths exported",
                HardwareWritesAllowed = false,
                Errors = discovery.Errors,
                Endpoints = discovery.Endpoints.Select((endpoint, index) => new {
                    SnapshotIndex = index, endpoint.VendorId, endpoint.ProductId, endpoint.VersionNumber,
                    endpoint.UsagePage, endpoint.Usage, endpoint.InputReportBytes, endpoint.OutputReportBytes,
                    endpoint.FeatureReportBytes, endpoint.Error,
                    CatalogueCandidates = catalog.Match(endpoint.VendorId, endpoint.ProductId)
                }).ToArray()
            }, new JsonSerializerOptions { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
        }
    }
}
