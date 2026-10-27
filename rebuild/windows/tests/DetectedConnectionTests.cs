using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class DetectedConnectionTests
{
    private static int checks;
    private static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    private static HidEndpoint Endpoint(ushort vendor = 0x1234, ushort product = 1,
        ushort page = 0xff02, ushort usage = 2, ushort input = 20, ushort output = 20,
        ushort feature = 0, string error = "") => new HidEndpoint("opaque-not-for-display",
            new WindowsHidDiscovery.HiddAttributes { VendorID = vendor, ProductID = product, VersionNumber = 1 },
            new WindowsHidDiscovery.HidpCaps { UsagePage = page, Usage = usage, InputReportByteLength = input,
                OutputReportByteLength = output, FeatureReportByteLength = feature }, error);
    private static HidDiscoveryResult Discovery(params HidEndpoint[] endpoints) => new HidDiscoveryResult(endpoints.ToList(), new List<string>());
    private static string Resource(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
    private static int Main(string[] args)
    {
        try
        {
            var catalog = CompatibilityCatalog.Load("""
                {"vendorId":"1234","models":[
                  {"code":"0001","name":"Keyboard A","isDirectPid":true},
                  {"code":"0001","name":"Keyboard B","isDirectPid":true},
                  {"code":"0002","name":"Keyboard C","isDirectPid":true}]}
                """, "{}");
            Check(DetectedConnection.Build(null, catalog).Count == 0, "Initial state has no invented device");
            Check(DetectedConnection.Build(Discovery(), catalog).Count == 0, "Empty snapshot");
            var receiver = DetectedConnection.Build(Discovery(Endpoint(), Endpoint(page: 1, usage: 6, input: 9, output: 2)), catalog).Single();
            Check(receiver.Identity == "1234:0001" && receiver.EndpointCount == 2, "Collections grouped, not miscounted as keyboards");
            Check(receiver.CandidateModels.SequenceEqual(new[] { "Keyboard A", "Keyboard B" }), "Shared identity is detected without selecting a model");
            Check(receiver.QueryKind == LightingQueryKind.Wireless20, "Shared model ID does not hide a query interface");
            Check(receiver.QueryStatus.Contains("not checked yet"), "Presence never claims keyboard responsiveness");
            var g5 = DetectedConnection.Build(Discovery(Endpoint(input: 8, output: 0, feature: 520)), catalog).Single();
            Check(g5.QueryKind == LightingQueryKind.G5Feature520, "Feature interface query available");
            foreach (var endpoints in new[] {
                Discovery(Endpoint(), Endpoint()),
                Discovery(Endpoint(), Endpoint(input: 8, output: 0, feature: 520)),
                Discovery(Endpoint(input: 8, output: 0, feature: 520), Endpoint(input: 8, output: 0, feature: 520)) })
                Check(DetectedConnection.Build(endpoints, catalog).Single().QueryKind == LightingQueryKind.Ambiguous, "Duplicate/mixed interfaces cannot be picked by VID/PID");
            foreach (var endpoint in new[] {
                Endpoint(error: "metadata failed"), Endpoint(page: 1), Endpoint(usage: 1),
                Endpoint(input: 19), Endpoint(output: 19), Endpoint(input: 21, output: 0, feature: 520),
                Endpoint(input: 8, output: 0, feature: 519) })
                Check(DetectedConnection.Build(Discovery(endpoint), catalog).Single().QueryKind == LightingQueryKind.None, "Unsupported shape or failed metadata cannot expose a query");
            Check(DetectedConnection.Build(Discovery(Endpoint(error: "metadata failed")), catalog).Single().HasMetadataErrors, "Metadata failure remains visible");
            var unknown = DetectedConnection.Build(Discovery(Endpoint(product: 999)), catalog).Single();
            Check(unknown.CandidateModels.Length == 0 && unknown.QueryKind == LightingQueryKind.None, "Unknown product is visible but not probed");
            Check(DetectedConnection.Build(Discovery(Endpoint(vendor: 0x9876)), catalog).Count == 0, "Unrelated vendor is not called RK");
            Check(DetectedConnection.Build(Discovery(Endpoint(product: 1), Endpoint(product: 2)), catalog).Count == 2, "Multiple different keyboards stay visible");
            Check(!catalog.HardwareWritesAllowed && catalog.Entries.All(entry => !entry.HardwareWritesAllowed), "Discovery does not grant writes");

            string root = Directory.GetCurrentDirectory();
            while (!File.Exists(Path.Combine(root, "rebuild", "windows", "RKRebuild.cs")))
                root = Directory.GetParent(root)?.FullName ?? throw new Exception("Repository not found");
            string app = File.ReadAllText(Path.Combine(root, "rebuild", "windows", "RKRebuild.cs"));
            string ui = File.ReadAllText(Path.Combine(root, "rebuild", "windows", "DeviceConnectionPage.cs"));
            Check(!app.Contains("_page = \"Compatibility\""), "First launch must not bury devices behind catalogue");
            foreach (string page in new[] { "RenderDevice", "RenderLighting" }) {
                int start = app.IndexOf("private void " + page + "()", StringComparison.Ordinal);
                Check(start >= 0 && app.Substring(start, 120).Contains("RenderDeviceConnections();"), "Live controls first on " + page);
            }
            Check(app.Contains("Detected device · \" + connected.Identity"), "Ambiguous detected device is not headed selected profile");
            Check(ui.Contains("if (_offlineUiSmoke || _lightingQueryRunning) return;"), "No offline/overlapping query");
            Check(ui.Contains("G5LightingCommand.ReadAsync") && ui.Contains("WirelessLightingCommand.ReadAsync"), "Real existing readers, not cosmetic handlers");
            Check(ui.Contains("Read current lighting") && ui.Contains("Lighting read failed:"), "Read action and failure visible without export dialogs");
            Check(ui.Contains("AddObservedLightingActionsAsync"), "Existing exact-fingerprint write gate reused, not replaced");
            Check(app.Contains("UpdateConnectionStatus();") && app.Contains("WindowsHidDiscovery.Enumerate()"), "Connection status updated through existing HID discovery");
            if (args.Contains("--live-metadata")) {
                var actual = DetectedConnection.Build(WindowsHidDiscovery.Enumerate(), CompatibilityCatalog.Load(Resource("Hub.json"), Resource("Drive.json")));
                Console.WriteLine(JsonSerializer.Serialize(actual.Select(device => new {
                    device.Identity, device.EndpointCount, device.QueryStatus,
                    QueryKind = device.QueryKind.ToString(), CandidateCount = device.CandidateModels.Length,
                    device.HasMetadataErrors
                }), new JsonSerializerOptions { WriteIndented = true }));
            }
            Console.WriteLine("PASS: " + checks + " device-presence/classification/UI contracts. " + (args.Contains("--live-metadata") ? "Live metadata only; no protocol reports sent." : "No hardware accessed."));
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.Message); return 1; }
    }
}
