using System;
using System.Security.Cryptography;

namespace RkRebuild
{
    // Operation-specific evidence, NOT a model-identification or certification list.
    // The initial rule is deliberately narrower than the read-query eligibility:
    // a shared VID/PID or a manually selected reference profile never enables writes.
    internal static class LightingWritePolicy
    {
        public const string Evidence = "rk406-wireless-lighting-roundtrip-frida-2026-10-26";
        private const string ObservedNormalizedBlockSha256 = "B6E940753F8E26A8F9232418DE25C11A77E6A00B4517DAFB077EFB6E824F09FD";
        private const string ReconnectedNormalizedBlockSha256 = "ABB54C49BFF203B2E04B8C70F443F890F30C07147F500F23986DBD771AE2072E";

        public static string Rejection(HidEndpoint endpoint, byte[] baseline, byte targetMode)
        {
            if (targetMode > 1) return "Only observed wire modes 0 and 1 are permitted; other effects are not validated.";
            if (endpoint == null || !String.IsNullOrEmpty(endpoint.Error) || endpoint.VendorId != "258A" ||
                endpoint.ProductId != "0150" || endpoint.VersionNumber != 518 || endpoint.UsagePage != "FF02" ||
                endpoint.Usage != "0002" || endpoint.InputReportBytes != 20 || endpoint.OutputReportBytes != 20)
                return "Endpoint metadata does not match the retained operation evidence. No configuration write is permitted.";
            if (baseline == null || baseline.Length != 128 || baseline[126] != 0x5a || baseline[127] != 0xa5 || baseline[10] > 1)
                return "A complete, observed-layout lighting baseline in wire mode 0 or 1 is required.";
            byte[] normalized = (byte[])baseline.Clone();
            normalized[10] = 0;
            string fingerprint = Convert.ToHexString(SHA256.HashData(normalized));
            // A second COMPLETE configuration was independently observed after
            // reconnection, again with only mode changing. Do not mask or invent
            // semantics for the unknown bytes that differ between these states.
            if (fingerprint != ObservedNormalizedBlockSha256 && fingerprint != ReconnectedNormalizedBlockSha256)
                return "Lighting block differs from the validated configuration fingerprint. Writes remain disabled; do not substitute a reference profile or an old block.";
            return null;
        }

        public static void Require(HidEndpoint endpoint, byte[] baseline, byte targetMode)
        {
            string rejection = Rejection(endpoint, baseline, targetMode);
            if (rejection != null) throw new InvalidOperationException(rejection);
        }
    }
}
