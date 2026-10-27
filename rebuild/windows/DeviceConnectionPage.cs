using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace RkRebuild
{
    internal sealed partial class MainWindow
    {
        private HidDiscoveryResult _deviceEndpoints;
        private IReadOnlyList<DetectedConnection> _detectedConnections = Array.Empty<DetectedConnection>();
        private string _deviceScanError = "";
        private bool _deviceScanCompleted;
        private TextBlock _connectionStatusText;

        private void UpdateConnectionStatus()
        {
            if (_connectionStatusText != null)
                _connectionStatusText.Text = _detectedConnections.Count > 0 || FindKnownRkDevices().Count > 0
                    ? "DEVICE DETECTED" : !String.IsNullOrEmpty(_deviceScanError) ? "SCAN INCOMPLETE" : "NO DEVICE FOUND";
        }

        private void RenderDeviceConnections()
        {
            Border card = Card();
            StackPanel body = new StackPanel { Margin = new Thickness(18) };
            card.Child = body;
            body.Children.Add(Kicker("CONNECTED DEVICES · LIVE WINDOWS DETECTION"));
            var refresh = ActionButton("Rescan devices", false);
            refresh.IsEnabled = !_pnpScanRunning && !_lightingQueryRunning && !_offlineUiSmoke;
            refresh.Click += delegate { _pnpSnapshot = ""; RefreshPnpDevices(true); };
            body.Children.Add(refresh);
            if (!_deviceScanCompleted)
                body.Children.Add(Paragraph(_offlineUiSmoke ? "Device discovery is disabled in offline rendering." : "Looking for connected USB/HID devices…", 13));
            else if (_detectedConnections.Count == 0)
                body.Children.Add(Paragraph(FindKnownRkDevices().Count > 0
                    ? "Windows PnP sees an RK catalogue identity, but no matching HID metadata is available. Check access permissions and rescan; a selected profile is not a device connection."
                    : "No RK catalogue-vendor HID device was found. Check the connection and rescan. Bluetooth and unlisted identities may not expose a supported configuration interface.", 13));
            if (!String.IsNullOrEmpty(_deviceScanError)) body.Children.Add(Paragraph("Discovery incomplete: " + _deviceScanError, 12));
            foreach (DetectedConnection connection in _detectedConnections)
            {
                body.Children.Add(Headline("Detected USB/HID device · " + connection.Identity, 18));
                body.Children.Add(Paragraph(connection.EndpointCount + " HID collections · " + connection.QueryStatus, 12));
                body.Children.Add(Paragraph(connection.CandidateModels.Length == 1
                    ? "Catalogue candidate: " + connection.CandidateModels[0] + ". Physical model/revision is not confirmed by this ID."
                    : connection.CandidateModels.Length > 1
                        ? "Shared USB identity: " + connection.CandidateModels.Length + " possible model labels. Device detection succeeded; exact model is unconfirmed."
                        : "No matching keyboard model is declared in the catalogue.", 12));
                if (connection.HasMetadataErrors) body.Children.Add(Paragraph("Some collections could not be inspected. Only fresh, unambiguous metadata may be used by a query.", 11));
                if (connection.QueryKind != LightingQueryKind.Wireless20 && connection.QueryKind != LightingQueryKind.G5Feature520) continue;
                var read = ActionButton("Read current lighting · " + connection.Identity, true);
                read.IsEnabled = !_lightingQueryRunning && !_offlineUiSmoke;
                body.Children.Add(read);
                var result = new StackPanel();
                body.Children.Add(result);
                read.Click += async delegate {
                    if (_offlineUiSmoke || _lightingQueryRunning) return;
                    if (MessageBox.Show(this, "Close the RK vendor utility normally first. This sends one lighting-configuration query to " + connection.Identity + ", not a settings write or firmware command. Continue?", "Read current lighting", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                    _lightingQueryRunning = true; read.IsEnabled = false; refresh.IsEnabled = false;
                    result.Children.Clear();
                    result.Children.Add(Paragraph("Reading keyboard lighting configuration…", 12));
                    try
                    {
                        string report = connection.QueryKind == LightingQueryKind.G5Feature520
                            ? await G5LightingCommand.ReadAsync(connection.Identity)
                            : await Task.Run(() => WirelessLightingCommand.ReadAsync(connection.Identity));
                        result.Children.Clear();
                        result.Children.Add(Paragraph("Keyboard responded: complete 128-byte lighting configuration received. No settings were changed. This confirms communication, not full model support.", 13));
                        if (connection.QueryKind == LightingQueryKind.Wireless20)
                        {
                            try { await AddObservedLightingActionsAsync(result, connection.Identity, report); }
                            catch (Exception error) { result.Children.Add(Paragraph("Lighting read succeeded, but experimental mode controls are unavailable: " + error.Message, 12)); }
                        }
                        else result.Children.Add(Paragraph("General G5 lighting writes are not implemented. Effect, brightness and color controls remain unavailable.", 12));
                        var export = ActionButton("Save lighting read report", false);
                        export.Click += delegate {
                            var save = new SaveFileDialog { FileName = "rk-lighting-read.json", Filter = "Lighting report (*.json)|*.json" };
                            if (save.ShowDialog(this) != true) return;
                            try { File.WriteAllText(save.FileName, report, new UTF8Encoding(false)); }
                            catch (Exception error) { MessageBox.Show(this, error.Message, "Lighting report export", MessageBoxButton.OK, MessageBoxImage.Warning); }
                        };
                        result.Children.Add(export);
                    }
                    catch (Exception error)
                    {
                        result.Children.Clear();
                        result.Children.Add(Paragraph("Lighting read failed: " + error.Message + " No settings write was requested. Check the keyboard is awake, close the vendor utility and rescan before trying again.", 12));
                    }
                    finally { _lightingQueryRunning = false; read.IsEnabled = true; refresh.IsEnabled = true; }
                };
            }
            _pageBody.Children.Add(card);
        }
    }
}
