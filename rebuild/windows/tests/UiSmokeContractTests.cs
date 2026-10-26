using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

// Source contracts intentionally require no WPF/vendor/hardware dependencies.
internal static class UiSmokeContractTests
{
    private static int _checks;
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        _checks++;
    }

    private static void GuardBefore(string source, string method, string effect)
    {
        int start = source.IndexOf(method, StringComparison.Ordinal);
        Check(start >= 0, "Missing method: " + method);
        int guard = source.IndexOf("if (_offlineUiSmoke)", start, StringComparison.Ordinal);
        int action = source.IndexOf(effect, start, StringComparison.Ordinal);
        Check(guard > start && action > guard, "Offline guard must precede " + effect);
        Check(source.Substring(guard, action - guard).Contains("return;"), "Guard must return before " + effect);
    }

    private static int Main(string[] args)
    {
        try
        {
            string root = args.Length > 0 ? Path.GetFullPath(args[0]) : Directory.GetCurrentDirectory();
            while (!File.Exists(Path.Combine(root, "rebuild", "windows", "RKRebuild.cs")))
                root = Directory.GetParent(root)?.FullName ?? throw new Exception("Repository root not found.");
            string app = File.ReadAllText(Path.Combine(root, "rebuild", "windows", "RKRebuild.cs"));
            string smoke = File.ReadAllText(Path.Combine(root, "rebuild", "windows", "UiSmoke.cs"));
            Check(app.IndexOf("UiSmoke.Run(args)", StringComparison.Ordinal) < app.IndexOf("SettingsStore.Load()", StringComparison.Ordinal), "Smoke must bypass persisted settings load.");
            Check(!app.Contains("SettingsStore.Save(_settings)"), "Every RKRebuild.cs MainWindow save must use guarded SaveSettings.");
            Check(Regex.Matches(smoke, @"SettingsStore\.Save\(_settings\)").Count == 1, "Only one guarded persistence boundary.");
            GuardBefore(smoke, "private void SaveSettings()", "SettingsStore.Save(_settings)");
            GuardBefore(app, "private async void RefreshPnpDevices(bool redraw)", "Task.Run");
            GuardBefore(app, "private async void LoadDriveImage", "new HttpClient");
            GuardBefore(app, "private void SetStartup(bool enabled)", "Registry.CurrentUser");
            Check(app.Contains("if (!_offlineUiSmoke) _tray = BuildTray();"), "No offline tray.");
            Check(Regex.IsMatch(app, @"if \(!_offlineUiSmoke\)\s*\{\s*RefreshPnpDevices\(true\);\s*_pnpTimer"), "No offline initial PnP or timer.");
            Check(app.Contains("_settings.ResourceRoot = UiSmoke.NewMissingResourceRoot();\n            else if"), "Offline resource root bypasses vendor discovery.");
            Check(smoke.Contains("FileMode.CreateNew"), "Never overwrite report.");
            Check(smoke.IndexOf("FileMode.CreateNew", StringComparison.Ordinal) < smoke.IndexOf("ModelCatalog.Load()", StringComparison.Ordinal), "Reserve report before application work.");
            Check(!smoke.Contains("SettingsStore.Load("), "No persisted settings load in harness.");
            Check(smoke.Contains("new AppSettings { SelectedCode = profile }"), "Fresh in-memory settings.");
            Check(smoke.Contains("RenderMode.SoftwareOnly") && smoke.Contains("Left = -10000, Top = -10000") && smoke.Contains("ShowInTaskbar = false"), "Software/offscreen configuration.");
            Check(smoke.Contains("TimeSpan.FromSeconds(20)") && smoke.Contains("Environment.Exit(124)"), "Independent hard watchdog.");
            Check(smoke.Contains("bitmap.Render(visual)") && smoke.Contains("bitmap.CopyPixels") && smoke.Contains("SHA256.HashData(pixels)"), "Hash actual rendered pixels.");
            Check(smoke.Contains("_allowClose = true;") && smoke.Contains("app.Shutdown();"), "Close window and dispatcher safely.");
            Check(!smoke.Contains("MessageBox.Show("), "Headless failure path.");
            string[] pages = { "Compatibility", "Device", "Key mapping", "Lighting", "Macros", "RK Drive editor", "Models", "RK Drive directory", "Preferences" };
            foreach (string page in pages) Check(smoke.Contains("\"" + page + "\""), "Missing page " + page);
            if (args.Length > 1)
            {
                using var report = JsonDocument.Parse(File.ReadAllText(args[1]));
                JsonElement data = report.RootElement;
                Check(data.GetProperty("Passed").GetBoolean(), "Runtime smoke passed.");
                Check(data.GetProperty("MissingVendorResources").GetBoolean(), "Missing vendor resource root.");
                foreach (string flag in new[] { "SettingsPersistence", "Network", "DeviceAccess", "StartupRegistryAccess", "TrayCreated" })
                    Check(!data.GetProperty(flag).GetBoolean(), "Disabled boundary: " + flag);
                var rendered = data.GetProperty("Pages").EnumerateArray().ToArray();
                Check(rendered.Select(page => page.GetProperty("Page").GetString()).SequenceEqual(pages), "All nine pages in order.");
                foreach (var page in rendered)
                {
                    Check(page.GetProperty("Passed").GetBoolean(), "Page passed.");
                    Check(page.GetProperty("PageChildCount").GetInt32() > 0, "Nonempty page.");
                    Check(page.GetProperty("DistinctPixelColors").GetInt32() > 16, "Nontrivial pixels.");
                    Check(page.GetProperty("PixelSha256").GetString().Length == 64, "SHA256 present.");
                }
                Check(rendered.Select(page => page.GetProperty("PixelSha256").GetString()).Distinct().Count() == 9, "Pages render distinct visuals.");
                var guards = data.GetProperty("Guards");
                Check(guards.GetProperty("Passed").GetBoolean(), "Runtime guards passed.");
                foreach (string counter in new[] { "SettingsSavesSuppressed", "ImageRequestsSuppressed", "PnpRequestsSuppressed", "StartupRequestsSuppressed" })
                    Check(guards.GetProperty(counter).GetInt32() > 0, "Exercised guard: " + counter);
            }
            Console.WriteLine("PASS: " + _checks + " offline UI smoke contract checks.");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.Message); return 1; }
    }
}
