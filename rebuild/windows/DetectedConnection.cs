using System;
using System.Collections.Generic;
using System.Linq;

namespace RkRebuild
{
    internal enum LightingQueryKind { None, Wireless20, G5Feature520, Ambiguous }

    // Presence is independent of model certainty and permission to write.
    internal sealed class DetectedConnection
    {
        public string Identity { get; init; }
        public string[] CandidateModels { get; init; }
        public int EndpointCount { get; init; }
        public LightingQueryKind QueryKind { get; init; }
        public string QueryStatus { get; init; }
        public bool HasMetadataErrors { get; init; }

        internal static IReadOnlyList<DetectedConnection> Build(HidDiscoveryResult discovery, CompatibilityCatalog catalog)
        {
            if (discovery == null) return Array.Empty<DetectedConnection>();
            var knownVendors = catalog.Entries.Select(entry => entry.VendorId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return discovery.Endpoints.Where(endpoint => endpoint.VendorId.Length == 4 && endpoint.ProductId.Length == 4
                && knownVendors.Contains(endpoint.VendorId))
                .GroupBy(endpoint => endpoint.VendorId + ":" + endpoint.ProductId, StringComparer.OrdinalIgnoreCase)
                .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Select(group => {
                    var endpoints = group.ToArray();
                    var candidates = catalog.Match(endpoints[0].VendorId, endpoints[0].ProductId);
                    var usable = endpoints.Where(endpoint => String.IsNullOrEmpty(endpoint.Error)
                        && endpoint.UsagePage == "FF02" && endpoint.Usage == "0002").ToArray();
                    int wireless = usable.Count(endpoint => endpoint.InputReportBytes == 20 && endpoint.OutputReportBytes == 20);
                    int g5 = usable.Count(endpoint => endpoint.FeatureReportBytes == 520 && endpoint.OutputReportBytes == 0 && endpoint.InputReportBytes <= 20);
                    // No chooser can safely distinguish identical endpoints using VID/PID alone.
                    LightingQueryKind kind = candidates.Count == 0 ? LightingQueryKind.None
                        : wireless + g5 > 1 ? LightingQueryKind.Ambiguous
                        : wireless == 1 ? LightingQueryKind.Wireless20
                        : g5 == 1 ? LightingQueryKind.G5Feature520 : LightingQueryKind.None;
                    return new DetectedConnection {
                        Identity = group.Key, EndpointCount = endpoints.Length,
                        CandidateModels = candidates.Select(entry => entry.ModelName).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(name => name).ToArray(),
                        HasMetadataErrors = endpoints.Any(endpoint => !String.IsNullOrEmpty(endpoint.Error)),
                        QueryKind = kind,
                        QueryStatus = kind == LightingQueryKind.Wireless20 ? "20-byte configuration interface detected. Lighting query available; keyboard response not checked yet."
                            : kind == LightingQueryKind.G5Feature520 ? "520-byte G5 configuration interface detected. Lighting query available; keyboard response not checked yet."
                            : kind == LightingQueryKind.Ambiguous ? "Multiple configuration interfaces share this identity. Query blocked; disconnect duplicate devices before rescanning."
                            : candidates.Count == 0 ? "Device present, but this product ID is not in the keyboard catalogue. No protocol probe will be sent."
                            : "Device present. No supported lighting-query interface was found; configuration controls remain unavailable."
                    };
                }).ToArray();
        }
    }
}
