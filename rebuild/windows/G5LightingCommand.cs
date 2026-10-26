using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace RkRebuild
{
    internal static class G5LightingCommand
    {
        public static async Task<string> ReadAsync(string identity, CancellationToken cancellationToken = default)
        {
            ValidateIdentity(identity);
            cancellationToken.ThrowIfCancellationRequested();
            WirelessLightingCommand.RequireVendorUtilityClosed();
            string executable = Environment.ProcessPath;
            if (String.IsNullOrEmpty(executable)) throw new InvalidOperationException("Cannot locate the application's own feature-query worker.");
            var arguments = new List<string>();
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                string assembly = Assembly.GetEntryAssembly()?.Location;
                if (String.IsNullOrEmpty(assembly)) throw new InvalidOperationException("Cannot locate the application assembly for the worker.");
                arguments.Add(assembly);
            }
            arguments.Add("--internal-g5-lighting-query"); arguments.Add(identity);
            // A task timeout cannot interrupt a synchronous HidD call. Native
            // calls run only in our disposable helper; the runner kills that
            // specific child on deadline/cancellation, never a vendor process.
            WorkerProcessResult worker = await BoundedWorkerProcess.RunAsync(executable, arguments, TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            if (worker.ExitCode == 124) throw new TimeoutException("G5 feature query exceeded its isolated worker deadline.");
            if (worker.ExitCode != 0) throw new IOException("G5 lighting query worker failed; no settings command was sent. " + SafeWorkerError(worker.StandardOutput));
            ValidateReport(worker.StandardOutput);
            return worker.StandardOutput;
        }

        private static string SafeWorkerError(string output)
        {
            try { using JsonDocument json = JsonDocument.Parse(output); return json.RootElement.GetProperty("ErrorCode").GetString(); }
            catch { return "Worker result unavailable."; }
        }

        internal static void ValidateReport(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (root.GetProperty("Format").GetString() != "rk-rebuild-experimental-g5-lighting-read" || root.GetProperty("SchemaVersion").GetInt32() != 1 || root.GetProperty("SettingsWritesPerformed").GetBoolean())
                throw new InvalidDataException("Invalid G5 query worker result.");
            string hex = root.GetProperty("LightingBlockHex").GetString();
            if (hex == null || hex.Length != 256) throw new InvalidDataException("G5 worker did not return a complete lighting block.");
            byte[] block = Convert.FromHexString(hex);
            if (block[126] != 0x5a || block[127] != 0xa5) throw new InvalidDataException("G5 worker returned an invalid lighting signature.");
        }

        internal static void ValidateIdentity(string identity)
        {
            if (identity == null || !Regex.IsMatch(identity, "\\A[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}\\z"))
                throw new ArgumentException("Specify an explicit four-digit hexadecimal VID:PID.");
        }

        private static HidEndpoint ResolveEndpoint(string identity)
        {
            ValidateIdentity(identity);
            WirelessLightingCommand.RequireVendorUtilityClosed();
            string[] parts = identity.Split(':');
            if (CompatibilityResources.Load().Match(parts[0], parts[1]).Count == 0)
                throw new InvalidOperationException("Identity is absent from keyboard catalogues; no query was sent.");
            HidEndpoint[] endpoints = WindowsHidDiscovery.Enumerate().Endpoints.Where(endpoint =>
                endpoint.VendorId.Equals(parts[0], StringComparison.OrdinalIgnoreCase) && endpoint.ProductId.Equals(parts[1], StringComparison.OrdinalIgnoreCase) &&
                endpoint.UsagePage == "FF02" && endpoint.Usage == "0002" && endpoint.FeatureReportBytes == 520 && endpoint.OutputReportBytes == 0 && endpoint.InputReportBytes <= 20 && String.IsNullOrEmpty(endpoint.Error)).ToArray();
            if (endpoints.Length != 1) throw new InvalidOperationException("Need exactly one eligible 520-byte G5 vendor endpoint; no query was sent.");
            return endpoints[0];
        }

        // Invoked before any WPF/application/settings startup. An independent
        // self-watchdog also bounds direct invocation of this internal command.
        public static int RunWorker(string identity)
        {
            using var watchdog = new Timer(_ => Environment.Exit(124), null, TimeSpan.FromSeconds(8), Timeout.InfiniteTimeSpan);
            try
            {
                using var lease = LightingOperationLease.Acquire();
                HidEndpoint endpoint = ResolveEndpoint(identity);
                byte[] ids = G5FeatureMetadata.FeatureReportIds(endpoint);
                if (ids.Length != 1) throw new InvalidDataException("Feature report ID is absent or ambiguous; no query was sent.");
                byte id = ids[0];
                var response = QueryNative(endpoint, id);
                Console.Out.Write(JsonSerializer.Serialize(new {
                    Format = "rk-rebuild-experimental-g5-lighting-read", SchemaVersion = 1,
                    endpoint.VendorId, endpoint.ProductId, endpoint.VersionNumber, endpoint.UsagePage, endpoint.Usage,
                    endpoint.FeatureReportBytes, ReportIdHex = id.ToString("X2"), LightingBlockHex = Convert.ToHexString(response.Block),
                    ResponseHeaderHex = Convert.ToHexString(response.Header), SetFeatureCalls = 1, GetFeatureCalls = 1,
                    SettingsWritesPerformed = false, QueryCommand = "84",
                    Boundary = "One active SetFeature query and one GetFeature; no settings writes, retries, input-report reads, fallback protocol or firmware commands. Not model certification."
                }));
                Console.Out.Flush(); return 0;
            }
            catch (Exception error)
            {
                // Never return opaque device paths, native exception strings,
                // user text, serials or arbitrary report bytes through pipes.
                string code = error is InvalidDataException ? "InvalidOrAmbiguousProtocolMetadata" :
                    error is ArgumentException ? "InvalidEndpointOrIdentity" :
                    error is InvalidOperationException ? "OperationPreconditionFailed" : "NativeFeatureQueryFailed";
                Console.Out.Write(JsonSerializer.Serialize(new { Format = "rk-g5-worker-error", ErrorCode = code }));
                Console.Out.Flush(); return 1;
            }
        }

        private static (byte[] Block, byte[] Header) QueryNative(HidEndpoint endpoint, byte reportId)
        {
            G5FeatureMetadata.ValidateEndpoint(endpoint);
            using SafeFileHandle handle = CreateFileW(endpoint.DevicePath, 0xc0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (handle.IsInvalid) throw new IOException("Feature handle unavailable.");
            // Native 0x40FAD0: default 25-ms pre/post waits. No QPC busy wait,
            // no vendor retry/fallthrough quirk, and no arbitrary-command API.
            Thread.Sleep(25);
            byte[] report = G5LightingQueryProtocol.CreateQuery(reportId);
            if (!HidD_SetFeature(handle, report, report.Length)) throw new IOException("Feature query request failed.");
            Thread.Sleep(25);
            report[0] = reportId;
            if (!HidD_GetFeature(handle, report, report.Length)) throw new IOException("Feature query response failed.");
            return (G5LightingQueryProtocol.Decode(reportId, report), report.AsSpan(0, 8).ToArray());
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("hid.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_SetFeature(SafeFileHandle handle, [In] byte[] report, int length);
        [DllImport("hid.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_GetFeature(SafeFileHandle handle, [In, Out] byte[] report, int length);
    }
}
