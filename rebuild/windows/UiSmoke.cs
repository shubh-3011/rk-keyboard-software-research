using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace RkRebuild
{
    // This runs only our own WPF UI. No buttons, hardware operations or dialogs are invoked.
    internal static class UiSmoke
    {
        internal static string NewMissingResourceRoot()
        {
            string path;
            do { path = Path.Combine(Path.GetTempPath(), "rk-ui-smoke-missing-" + Guid.NewGuid().ToString("N")); }
            while (Directory.Exists(path) || File.Exists(path));
            return path; // Deliberately never create it; relative vendor-asset fallback is impossible.
        }

        internal static int Run(string[] args)
        {
            try
            {
                if (args.Length != 2) throw new ArgumentException("Usage: RK-Rebuild.exe --ui-smoke-test <new-json-path>");
                // Reserve before WPF, catalogues, settings or any other application work.
                using FileStream output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var watchdog = new System.Threading.Timer(_ => Environment.Exit(124), null, TimeSpan.FromSeconds(20), Timeout.InfiniteTimeSpan);
                var elapsed = Stopwatch.StartNew();
                var pages = new List<UiSmokePage>();
                MainWindow window = null;
                Application app = null;
                string error = null;
                UiSmokeGuards guards = null;
                string profile = null;
                try
                {
                    RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                    ModelCatalog catalog = ModelCatalog.Load();
                    // Stable embedded reference, not a connected-device or persisted/S98 preference.
                    profile = catalog.Models.OrderBy(item => item.Code, StringComparer.Ordinal).First().Code;
                    var settings = new AppSettings { SelectedCode = profile };
                    app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    app.DispatcherUnhandledException += (sender, failure) =>
                    {
                        error = failure.Exception.ToString();
                        failure.Handled = true;
                        if (window != null) window.CloseUiSmoke();
                        app.Shutdown(1);
                    };
                    window = new MainWindow(catalog, DriveDirectory.Load(), AppearancePhoto.Load(), settings, offlineUiSmoke: true)
                    {
                        ShowInTaskbar = false, ShowActivated = false,
                        WindowStartupLocation = WindowStartupLocation.Manual,
                        Left = -10000, Top = -10000
                    };
                    app.Startup += async (sender, startup) =>
                    {
                        try
                        {
                            window.Show();
                            foreach (string page in new[] { "Compatibility", "Device", "Key mapping", "Lighting", "Macros", "RK Drive editor", "Models", "RK Drive directory", "Preferences" })
                            {
                                // Let WPF process bindings/templates between actual page changes.
                                await Dispatcher.Yield(DispatcherPriority.Background);
                                pages.Add(window.RenderUiSmokePage(page));
                            }
                            guards = window.AuditUiSmokeGuards();
                        }
                        catch (Exception failure) { error = failure.ToString(); }
                        finally
                        {
                            window.CloseUiSmoke();
                            app.Shutdown();
                        }
                    };
                    app.Run();
                }
                catch (Exception failure) { error = failure.ToString(); }
                finally
                {
                    if (window != null) window.CloseUiSmoke();
                    if (app != null) app.Shutdown();
                }
                bool passed = error == null && pages.Count == 9 && pages.All(page => page.Passed) && guards != null && guards.Passed;
                using var writer = new StreamWriter(output, new UTF8Encoding(false));
                writer.Write(JsonSerializer.Serialize(new
                {
                    Format = "rk-rebuild-offline-ui-smoke", SchemaVersion = 1, Passed = passed,
                    MissingVendorResources = guards?.MissingVendorResources ?? false,
                    SettingsPersistence = false, Network = false, DeviceAccess = false,
                    StartupRegistryAccess = false, TrayCreated = false,
                    ReferenceProfile = profile, Rendering = "WPF RenderTargetBitmap / SoftwareOnly / offscreen",
                    ElapsedMs = elapsed.Elapsed.TotalMilliseconds, HardTimeoutSeconds = 20,
                    TimeoutExitCode = 124,
                    Scope = "Page construction, layout and actual visual rendering only. No button interaction, device validation, performance/lag certification or complete manual workflow claim.",
                    Guards = guards, Pages = pages, Error = error
                }, new JsonSerializerOptions { WriteIndented = true }));
                return passed ? 0 : 1;
            }
            catch (Exception failure)
            {
                Console.Error.WriteLine(failure.Message);
                return 1; // Never route smoke errors through the normal MessageBox startup handler.
            }
        }
    }

    internal sealed class UiSmokePage
    {
        public string Page { get; set; }
        public bool Passed { get; set; }
        public int PageChildCount { get; set; }
        public int PixelWidth { get; set; }
        public int PixelHeight { get; set; }
        public int DistinctPixelColors { get; set; }
        public string PixelSha256 { get; set; }
        public double ElapsedMs { get; set; }
        public string Error { get; set; }
    }

    internal sealed class UiSmokeGuards
    {
        public bool Passed { get; set; }
        public bool MissingVendorResources { get; set; }
        public bool NoTray { get; set; }
        public bool NoPnpTimer { get; set; }
        public int SettingsSavesSuppressed { get; set; }
        public int ImageRequestsSuppressed { get; set; }
        public int PnpRequestsSuppressed { get; set; }
        public int StartupRequestsSuppressed { get; set; }
        public int IndependentNavigationGlyphs { get; set; }
        public bool NavigationAccessible { get; set; }
    }

    internal sealed partial class MainWindow
    {
        private readonly bool _offlineUiSmoke;
        private int _smokeSettingsSavesSuppressed;
        private int _smokeImageRequestsSuppressed;
        private int _smokePnpRequestsSuppressed;
        private int _smokeStartupRequestsSuppressed;

        private void SaveSettings()
        {
            if (_offlineUiSmoke) { _smokeSettingsSavesSuppressed++; return; }
            SettingsStore.Save(_settings);
        }

        internal UiSmokePage RenderUiSmokePage(string page)
        {
            if (!_offlineUiSmoke) throw new InvalidOperationException("Offline smoke window required.");
            var timer = Stopwatch.StartNew();
            var result = new UiSmokePage { Page = page };
            try
            {
                SetPage(page);
                UpdateLayout();
                var visual = (FrameworkElement)Content;
                visual.UpdateLayout();
                int width = (int)Math.Ceiling(visual.ActualWidth);
                int height = (int)Math.Ceiling(visual.ActualHeight);
                if (width <= 0 || height <= 0) throw new InvalidOperationException("Empty WPF layout.");
                var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(visual);
                byte[] pixels = new byte[checked(width * height * 4)];
                bitmap.CopyPixels(pixels, width * 4, 0);
                var colors = new HashSet<uint>();
                for (int offset = 0; offset < pixels.Length; offset += 4)
                    colors.Add(BitConverter.ToUInt32(pixels, offset));
                result.PageChildCount = _pageBody.Children.Count;
                result.PixelWidth = width;
                result.PixelHeight = height;
                result.DistinctPixelColors = colors.Count;
                result.PixelSha256 = Convert.ToHexString(SHA256.HashData(pixels));
                result.Passed = result.PageChildCount > 0 && colors.Count > 16;
            }
            catch (Exception failure) { result.Error = failure.ToString(); }
            result.ElapsedMs = timer.Elapsed.TotalMilliseconds;
            return result;
        }

        internal UiSmokeGuards AuditUiSmokeGuards()
        {
            if (!_offlineUiSmoke) throw new InvalidOperationException("Offline smoke window required.");
            // Explicitly exercise the no-op guards, including normally user-triggered saves.
            SaveSettings();
            RefreshPnpDevices(false);
            SetStartup(false);
            bool missing = !Directory.Exists(_settings.ResourceRoot) && !File.Exists(_settings.ResourceRoot);
            var navigation = FindVisualButtons(this).Where(button => button.Content is System.Windows.Controls.Grid grid
                && grid.Children.OfType<System.Windows.Controls.Viewbox>().Any()).ToArray();
            int glyphs = navigation.Count(button => ((System.Windows.Controls.Grid)button.Content).Children
                .OfType<System.Windows.Controls.Viewbox>().Any(box => box.Child is System.Windows.Shapes.Path path
                    && path.Data != null && !path.Data.Bounds.IsEmpty && path.ActualWidth > 0));
            bool accessible = navigation.Length == 9 && navigation.All(button =>
                !String.IsNullOrWhiteSpace(System.Windows.Automation.AutomationProperties.GetName(button))
                && !String.IsNullOrWhiteSpace(button.ToolTip as string) && button.Focusable);
            return new UiSmokeGuards
            {
                Passed = missing && _tray == null && _pnpTimer == null && !_pnpScanRunning
                    && _smokeSettingsSavesSuppressed > 0 && _smokeImageRequestsSuppressed > 0
                    && _smokePnpRequestsSuppressed > 0 && _smokeStartupRequestsSuppressed > 0
                    && glyphs == 9 && accessible,
                IndependentNavigationGlyphs = glyphs, NavigationAccessible = accessible,
                MissingVendorResources = missing, NoTray = _tray == null, NoPnpTimer = _pnpTimer == null,
                SettingsSavesSuppressed = _smokeSettingsSavesSuppressed,
                ImageRequestsSuppressed = _smokeImageRequestsSuppressed,
                PnpRequestsSuppressed = _smokePnpRequestsSuppressed,
                StartupRequestsSuppressed = _smokeStartupRequestsSuppressed
            };
        }

        internal void CloseUiSmoke()
        {
            if (!_offlineUiSmoke) throw new InvalidOperationException("Offline smoke window required.");
            _allowClose = true;
            Close();
        }
    }
}
