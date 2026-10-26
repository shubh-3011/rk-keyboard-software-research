using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
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
            _pageBody.Children.Add(actions);
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
    }
}
