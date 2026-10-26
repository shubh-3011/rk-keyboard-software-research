using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace RkRebuild
{
    internal static class CompatibilityResources
    {
        private static string Read(string name)
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (stream == null) throw new InvalidDataException("Missing embedded compatibility source: " + name);
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8)) return reader.ReadToEnd();
            }
        }

        public static CompatibilityCatalog Load()
        {
            return CompatibilityCatalog.Load(Read("RkRebuild.Profiles.json"), Read("RkRebuild.DriveCatalog.json"));
        }

        public static string Report(CompatibilityCatalog catalog)
        {
            return JsonSerializer.Serialize(new {
                Format = "rk-rebuild-compatibility-catalog", SchemaVersion = 1,
                Scope = "General Royal Kludge compatibility research, not a single-keyboard build",
                EvidenceBoundary = "Catalogue declarations only; no model/revision has certified hardware writes in this release. Shared identities remain ambiguous.",
                Entries = catalog.Entries
            }, new JsonSerializerOptions { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
        }
    }

    internal sealed partial class MainWindow
    {
        private CompatibilityCatalog _compatibility;
        private bool _lightingQueryRunning;

        private void RenderCompatibility()
        {
            if (_compatibility == null) _compatibility = CompatibilityResources.Load();
            AddIntro("Royal Kludge compatibility", "One application for multiple RK models and protocol families. A catalogued model is not yet a hardware-validated model; picking a profile or photo never unlocks writes.");
            _pageBody.Children.Add(CardWithText(_compatibility.Entries.Count + " source entries · Hub 4.6 profiles and RK Drive keyboard connection descriptors kept separate · no firmware/revision inferred from a shared VID/PID."));
            string[] present = _pnpDevices.SelectMany(device => _compatibility.Match(device.VendorId, device.ProductId)
                .Select(entry => device.Identity + " → " + entry.ModelName + " [" + entry.SourceSnapshot + "]"))
                .Distinct().OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
            _pageBody.Children.Add(CardWithText(present.Length == 0
                ? "No present PnP identity matched these snapshots. The catalogue below is still available for every model; this does not prove that no RK device is connected."
                : "Present PnP catalogue candidates (not confirmed physical models):\n" + String.Join("\n", present)));
            WrapPanel actions = new WrapPanel { Margin = new Thickness(0, 10, 0, 10) };
            TextBox search = new TextBox { Width = 340, Height = 32, Margin = new Thickness(0, 0, 12, 0), ToolTip = "Filter by model, VID/PID, snapshot, connection or declared protocol" };
            actions.Children.Add(search);
            Button export = ActionButton("Export full compatibility catalogue", false);
            export.Click += delegate {
                SaveFileDialog dialog = new SaveFileDialog { FileName = "rk-compatibility.json", Filter = "JSON catalogue (*.json)|*.json" };
                if (dialog.ShowDialog(this) != true) return;
                try { File.WriteAllText(dialog.FileName, CompatibilityResources.Report(_compatibility), new UTF8Encoding(false)); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "Catalogue export", MessageBoxButton.OK, MessageBoxImage.Warning); }
            };
            actions.Children.Add(export);
            Button inspectHid = ActionButton("Inspect HID endpoint metadata", false);
            inspectHid.Margin = new Thickness(10, 0, 0, 0);
            actions.Children.Add(inspectHid);
            _pageBody.Children.Add(actions);
            StackPanel endpointPanel = new StackPanel();
            _pageBody.Children.Add(endpointPanel);
            inspectHid.Click += async delegate {
                inspectHid.IsEnabled = false;
                endpointPanel.Children.Clear();
                endpointPanel.Children.Add(Paragraph("Inspecting endpoint capabilities only; no report reads or writes…", 12));
                try
                {
                    HidDiscoveryResult found = await Task.Run(() => WindowsHidDiscovery.Enumerate());
                    endpointPanel.Children.Clear();
                    var candidates = found.Endpoints.Select(endpoint => new {
                        endpoint.VendorId, endpoint.ProductId, endpoint.VersionNumber, endpoint.UsagePage, endpoint.Usage,
                        endpoint.InputReportBytes, endpoint.OutputReportBytes, endpoint.FeatureReportBytes,
                        CatalogueCandidates = _compatibility.Match(endpoint.VendorId, endpoint.ProductId).Count,
                        endpoint.Error
                    }).Where(endpoint => endpoint.CatalogueCandidates > 0).ToArray();
                    endpointPanel.Children.Add(Paragraph(found.Endpoints.Count + " HID endpoints inspected; " + candidates.Length + " match catalogue identities; " + found.Errors.Count + " discovery errors. These are candidates, not verified writable endpoints.", 12));
                    DataGrid endpoints = new DataGrid { AutoGenerateColumns = true, IsReadOnly = true, CanUserAddRows = false, CanUserDeleteRows = false,
                        Height = 180, ItemsSource = candidates, HeadersVisibility = DataGridHeadersVisibility.Column };
                    endpointPanel.Children.Add(endpoints);
                    string[] wirelessIds = candidates.Where(endpoint => endpoint.UsagePage == "FF02" && endpoint.Usage == "0002" && endpoint.InputReportBytes == 20 && endpoint.OutputReportBytes == 20)
                        .Select(endpoint => endpoint.VendorId + ":" + endpoint.ProductId).Distinct().ToArray();
                    foreach (string identity in wirelessIds)
                    {
                        Button read = ActionButton("Experimental lighting query · " + identity, false);
                        read.Click += async delegate {
                            if (_lightingQueryRunning) return;
                            if (MessageBox.Show(this, "This sends the recovered command 44 to query a lighting block, but does not apply settings or read firmware. Close the vendor utility first. Shared device IDs do not prove model compatibility. Continue?", "Experimental configuration query", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                            _lightingQueryRunning = true;
                            read.IsEnabled = false;
                            try
                            {
                                string report = await Task.Run(() => WirelessLightingCommand.ReadAsync(identity));
                                endpointPanel.Children.Add(Paragraph("Received a complete 128-byte lighting block with the expected signature. No settings were applied. This validates this query, not every workflow/model.", 12));
                                await AddObservedLightingActionsAsync(endpointPanel, identity, report);
                                SaveFileDialog save = new SaveFileDialog { FileName = "rk-lighting-read.json", Filter = "Lighting read report (*.json)|*.json" };
                                if (save.ShowDialog(this) == true) File.WriteAllText(save.FileName, report, new UTF8Encoding(false));
                            }
                            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Lighting query unavailable", MessageBoxButton.OK, MessageBoxImage.Warning); }
                            finally { _lightingQueryRunning = false; read.IsEnabled = true; }
                        };
                        endpointPanel.Children.Add(read);
                    }
                }
                catch (Exception ex) { endpointPanel.Children.Clear(); endpointPanel.Children.Add(Paragraph("Endpoint inspection failed: " + ex.Message, 12)); }
                finally { inspectHid.IsEnabled = true; }
            };
            DataGrid grid = new DataGrid {
                AutoGenerateColumns = false, IsReadOnly = true, CanUserAddRows = false, CanUserDeleteRows = false,
                EnableRowVirtualization = true, EnableColumnVirtualization = true, Height = 460,
                ItemsSource = _compatibility.Entries, HeadersVisibility = DataGridHeadersVisibility.Column
            };
            foreach (string property in new[] { "ModelName", "SourceSnapshot", "ProfileId", "Connection", "VendorId", "ProductId", "UsagePage", "Usage", "DeclaredProtocol", "HardwareWritesAllowed" })
                grid.Columns.Add(new DataGridTextColumn { Header = property, Binding = new System.Windows.Data.Binding(property), Width = DataGridLength.SizeToHeader });
            search.TextChanged += delegate {
                string query = search.Text.Trim();
                grid.ItemsSource = _compatibility.Entries.Where(entry => String.Join(" ", entry.ModelName, entry.SourceSnapshot, entry.ProfileId, entry.Connection,
                    entry.VendorId, entry.ProductId, entry.DeclaredProtocol).Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
            };
            _pageBody.Children.Add(grid);
            _pageBody.Children.Add(Paragraph("Declared protocol labels describe their original source only. Unsupported devices remain visible as unknown; a transport backend requires its own model/revision and feature validation before activation.", 12));
        }

        private async Task AddObservedLightingActionsAsync(StackPanel panel, string identity, string baselineReport)
        {
            HidEndpoint endpoint = await Task.Run(() => WirelessLightingCommand.ResolveEndpoint(identity));
            byte[] block = LightingBaseline.Parse(baselineReport, endpoint);
            string rejection = LightingWritePolicy.Rejection(endpoint, block, 0);
            if (rejection != null)
            {
                panel.Children.Add(Paragraph("Configuration writes remain disabled: " + rejection, 12));
                return;
            }
            panel.Children.Add(Paragraph("Experimental mode control is eligible for this exact configuration fingerprint. Only Off (wire 0) and the observed first effect (wire 1) are enabled. Other models, effects, brightness and colors are not validated by this evidence.", 12));
            var controls = new StackPanel { Orientation = Orientation.Horizontal };
            panel.Children.Add(controls);
            foreach (byte target in new byte[] { 0, 1 })
            {
                byte mode = target;
                Button apply = ActionButton(mode == 0 ? "Apply Off · experimental" : "Apply first effect · experimental", false);
                controls.Children.Add(apply);
                apply.Click += async delegate {
                    if (_lightingQueryRunning) return;
                    if (MessageBox.Show(this, "Apply " + (mode == 0 ? "Off" : "the observed first lighting effect") + " to the keyboard? This writes a 128-byte configuration while changing only its validated mode byte, then verifies readback. A timeout can leave device state uncertain; no automatic rollback is attempted. All other lighting settings are preserved. Continue?", "Confirm experimental hardware write", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                    _lightingQueryRunning = true;
                    controls.IsEnabled = false;
                    try
                    {
                        string result = await Task.Run(() => WirelessLightingApplyCommand.ApplyReportAsync(identity, baselineReport, mode));
                        panel.Children.Add(Paragraph("Hardware mode verified by a fresh, complete lighting query. Re-query before another change; this baseline is now retired.", 12));
                        SaveFileDialog save = new SaveFileDialog { FileName = "rk-lighting-apply.json", Filter = "Verified lighting operation (*.json)|*.json" };
                        if (save.ShowDialog(this) == true) File.WriteAllText(save.FileName, result, new UTF8Encoding(false));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(this, ex.Message + "\n\nDo not assume restoration. Re-query before any further write; no automatic retry or rollback was attempted.", "Lighting operation stopped", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    finally { _lightingQueryRunning = false; } // Retire on both success and uncertainty.
                };
            }
        }
    }
}
