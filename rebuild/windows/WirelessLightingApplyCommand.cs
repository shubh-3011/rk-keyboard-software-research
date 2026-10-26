using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace RkRebuild
{
    internal static class WirelessLightingApplyCommand
    {
        public static Task<string> ApplyAsync(string identity, string baselineReportPath, byte targetMode) =>
            ApplyCoreAsync(identity, endpoint => LightingBaseline.Load(baselineReportPath, endpoint), targetMode);

        public static Task<string> ApplyReportAsync(string identity, string baselineJson, byte targetMode) =>
            ApplyCoreAsync(identity, endpoint => LightingBaseline.Parse(baselineJson, endpoint), targetMode);

        private static async Task<string> ApplyCoreAsync(string identity, Func<HidEndpoint, byte[]> loadBaseline, byte targetMode)
        {
            if (targetMode > 1) throw new ArgumentOutOfRangeException(nameof(targetMode), "Only observed wire modes 0 and 1 are enabled.");
            using var lease = LightingOperationLease.Acquire();
            HidEndpoint endpoint = WirelessLightingCommand.ResolveEndpoint(identity);
            byte[] baseline = loadBaseline(endpoint);
            LightingWritePolicy.Require(endpoint, baseline, targetMode);
            // The transport re-queries on the same handle and refuses any stale byte.
            // Policy checks never substitute reference-profile data for current state.
            WirelessLightingTransactionResult operation = await WirelessLightingTransaction.ApplyAsync(endpoint, baseline, targetMode, TimeSpan.FromSeconds(12)).ConfigureAwait(false);
            return JsonSerializer.Serialize(new {
                Format = "rk-rebuild-experimental-lighting-apply", SchemaVersion = 1,
                endpoint.VendorId, endpoint.ProductId, endpoint.VersionNumber, endpoint.UsagePage, endpoint.Usage,
                BaselineBlockHex = Convert.ToHexString(operation.Before), VerifiedBlockHex = Convert.ToHexString(operation.After),
                ModeBefore = baseline[10], ModeAfter = targetMode, ChangedOffset = 10,
                ConfigurationReportsSent = operation.ConfigurationReportsWritten, NoOp = operation.NoOp,
                VerifiedByQuery = operation.Verified, Evidence = LightingWritePolicy.Evidence,
                Boundary = "Only a validated mode byte was patched; every other byte was preserved. Successful writes require echoes and full-block readback. This operation is not a universal model certification."
            }, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
