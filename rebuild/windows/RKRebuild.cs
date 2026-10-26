using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Data;
using System.Windows.Threading;
using Microsoft.Win32;
using Forms = System.Windows.Forms;
using SystemIcons = System.Drawing.SystemIcons;
using Image = System.Windows.Controls.Image;
using MediaColor = System.Windows.Media.Color;

namespace RkRebuild
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            try
            {
                if (args.Length > 0 && String.Equals(args[0], "--read-wireless-lighting", StringComparison.OrdinalIgnoreCase))
                {
                    if (args.Length != 3) throw new ArgumentException("Usage: RK-Rebuild.exe --read-wireless-lighting <VID:PID> <new-json-path>");
                    if (File.Exists(args[2])) throw new IOException("Output file already exists.");
                    string result = WirelessLightingCommand.ReadAsync(args[1]).GetAwaiter().GetResult();
                    using (FileStream output = new FileStream(args[2], FileMode.CreateNew, FileAccess.Write))
                    using (StreamWriter writer = new StreamWriter(output, new UTF8Encoding(false))) writer.Write(result);
                    return;
                }
                // Headless catalogue export or metadata diagnostics. Neither starts the UI.
                if (args.Length > 0 && (String.Equals(args[0], "--compatibility-report", StringComparison.OrdinalIgnoreCase) || String.Equals(args[0], "--hid-diagnostics", StringComparison.OrdinalIgnoreCase)))
                {
                    if (args.Length != 2) throw new ArgumentException("Usage: RK-Rebuild.exe " + args[0] + " <new-json-path>");
                    // Refuse overwrite BEFORE metadata enumeration, too.
                    if (File.Exists(args[1])) throw new IOException("Output file already exists.");
                    CompatibilityCatalog compatibility = CompatibilityResources.Load();
                    string report = String.Equals(args[0], "--hid-diagnostics", StringComparison.OrdinalIgnoreCase)
                        ? HidDiagnostics.Report(WindowsHidDiscovery.Enumerate(), compatibility)
                        : CompatibilityResources.Report(compatibility);
                    using (FileStream output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
                    using (StreamWriter writer = new StreamWriter(output, new UTF8Encoding(false)))
                        writer.Write(report);
                    return;
                }
                AppSettings settings = SettingsStore.Load();
                ModelCatalog catalog = ModelCatalog.Load();
                DriveDirectory driveDirectory = DriveDirectory.Load();
                List<AppearancePhoto> appearancePhotos = AppearancePhoto.Load();
                Application app = new Application();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                MainWindow window = new MainWindow(catalog, driveDirectory, appearancePhotos, settings);
                if (args.Any(a => String.Equals(a, "--background", StringComparison.OrdinalIgnoreCase)))
                    app.Run();
                else
                    app.Run(window);
            }
            catch (Exception ex)
            {
                if (args.Length > 0 && (String.Equals(args[0], "--compatibility-report", StringComparison.OrdinalIgnoreCase) || String.Equals(args[0], "--hid-diagnostics", StringComparison.OrdinalIgnoreCase) || String.Equals(args[0], "--read-wireless-lighting", StringComparison.OrdinalIgnoreCase)))
                {
                    Console.Error.WriteLine(ex.Message);
                    Environment.ExitCode = 1;
                    return;
                }
                MessageBox.Show("RK Rebuild could not start.\n\n" + ex.Message,
                    "RK Rebuild", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    internal sealed class AppSettings
    {
        public string SelectedCode { get; set; }
        public string ResourceRoot { get; set; }
        public bool StartWithWindows { get; set; }
        public Dictionary<string, string> KeyLabelDrafts { get; set; }
        public Dictionary<string, List<string>> MacroDrafts { get; set; }
        public Dictionary<string, List<MacroTimeline>> MacroTimelines { get; set; }
        public Dictionary<string, LightingDraft> LightingDrafts { get; set; }
        public Dictionary<string, DriveDraft> DriveDrafts { get; set; }
        public Dictionary<string, string> PhotoVariantOverrides { get; set; }
        public Dictionary<string, string> AppearanceVariantOverrides { get; set; }

        public AppSettings()
        {
            SelectedCode = "";
            ResourceRoot = "";
            StartWithWindows = false;
            KeyLabelDrafts = new Dictionary<string, string>();
            MacroDrafts = new Dictionary<string, List<string>>();
            MacroTimelines = new Dictionary<string, List<MacroTimeline>>();
            LightingDrafts = new Dictionary<string, LightingDraft>();
            DriveDrafts = new Dictionary<string, DriveDraft>();
            PhotoVariantOverrides = new Dictionary<string, string>();
            AppearanceVariantOverrides = new Dictionary<string, string>();
        }
    }

    internal sealed class DriveDraft
    {
        public string Layer { get; set; }
        public string Table { get; set; }
        public string Effect { get; set; }
        public int Brightness { get; set; }
        public int Speed { get; set; }
        public string Color { get; set; }
        public bool MixColor { get; set; }
        public int LayoutGroup { get; set; }
        public Dictionary<string, string> KeyMappings { get; set; }

        public DriveDraft()
        {
            Layer = "";
            Table = "";
            Effect = "";
            Brightness = 100;
            Speed = 50;
            Color = "#FFFFFF";
            MixColor = false;
            LayoutGroup = 0;
            KeyMappings = new Dictionary<string, string>();
        }
    }

    internal sealed class DriveDraftPackage
    {
        public int SchemaVersion { get; set; }
        public string SourceBundleSha256 { get; set; }
        public string Model { get; set; }
        public string Connection { get; set; }
        public string VendorId { get; set; }
        public string ProductId { get; set; }
        public string UsagePage { get; set; }
        public string Usage { get; set; }
        public string Protocol { get; set; }
        public bool Specialized { get; set; }
        public string Uuid { get; set; }
        public DriveDraft Draft { get; set; }

        public DriveDraftPackage()
        {
            SchemaVersion = 2;
            SourceBundleSha256 = "";
            Model = "";
            Connection = "";
            VendorId = "";
            ProductId = "";
            UsagePage = "";
            Usage = "";
            Protocol = "";
            Specialized = false;
            Uuid = "";
            Draft = new DriveDraft();
        }
    }

    internal static class SettingsStore
    {
        public static string Folder
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RK-Rebuild"); }
        }
        public static string FilePath { get { return Path.Combine(Folder, "settings.json"); } }

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    AppSettings saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath, Encoding.UTF8));
                    if (saved != null)
                    {
                        if (saved.KeyLabelDrafts == null) saved.KeyLabelDrafts = new Dictionary<string, string>();
                        if (saved.MacroDrafts == null) saved.MacroDrafts = new Dictionary<string, List<string>>();
                        if (saved.MacroTimelines == null) saved.MacroTimelines = new Dictionary<string, List<MacroTimeline>>();
                        if (saved.LightingDrafts == null) saved.LightingDrafts = new Dictionary<string, LightingDraft>();
                        if (saved.DriveDrafts == null) saved.DriveDrafts = new Dictionary<string, DriveDraft>();
                        if (saved.PhotoVariantOverrides == null) saved.PhotoVariantOverrides = new Dictionary<string, string>();
                        if (saved.AppearanceVariantOverrides == null) saved.AppearanceVariantOverrides = new Dictionary<string, string>();
                        foreach (DriveDraft draft in saved.DriveDrafts.Values)
                            if (draft != null && draft.KeyMappings == null) draft.KeyMappings = new Dictionary<string, string>();
                        return saved;
                    }
                }
            }
            catch { }
            return new AppSettings();
        }

        public static void Save(AppSettings settings)
        {
            Directory.CreateDirectory(Folder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        }
    }

    internal sealed class ModelProfile
    {
        public string Code;
        public string Name;
        public string Family;
        public string Region;
        public string LayoutId;
        public bool DirectPid;
        public int KeyCount;
        public bool Rgb;
        public int MacroBuffers;
        public string Screen;
        public List<int> LightingSlots = new List<int>();
        public List<string> Layers = new List<string>();
        public List<LayoutKey> Keys = new List<LayoutKey>();
        public Dictionary<string, string> Options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    internal sealed class PnpKeyboard
    {
        public string VendorId;
        public string ProductId;
        public string InstanceId;
        public string Name;

        public string Identity { get { return VendorId + ":" + ProductId; } }
    }

    internal static class WindowsPnpDiscovery
    {
        private static readonly Regex VendorPattern = new Regex(@"VID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex ProductPattern = new Regex(@"PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private const uint DigcfPresent = 0x00000002;
        private const uint DigcfAllClasses = 0x00000004;
        private const uint SpdrpDeviceDesc = 0x00000000;
        private const uint SpdrpHardwareId = 0x00000001;
        private const uint SpdrpFriendlyName = 0x0000000C;
        private const int ErrorInsufficientBuffer = 122;

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct SpDevInfoData
        {
            public uint Size;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [System.Runtime.InteropServices.DllImport("setupapi.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(IntPtr classGuid, string enumerator, IntPtr parentWindow, uint flags);

        [System.Runtime.InteropServices.DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SpDevInfoData deviceInfoData);

        [System.Runtime.InteropServices.DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceRegistryPropertyW", SetLastError = true)]
        private static extern bool SetupDiGetDeviceRegistryProperty(IntPtr deviceInfoSet, ref SpDevInfoData deviceInfoData,
            uint property, out uint propertyType, IntPtr propertyBuffer, uint propertyBufferSize, out uint requiredSize);

        [System.Runtime.InteropServices.DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        // SetupAPI lists present devices and reads their PnP properties. It never opens a device handle.
        public static List<PnpKeyboard> Enumerate()
        {
            List<PnpKeyboard> devices = new List<PnpKeyboard>();
            IntPtr deviceInfoSet = IntPtr.Zero;
            try
            {
                deviceInfoSet = SetupDiGetClassDevs(IntPtr.Zero, null, IntPtr.Zero, DigcfPresent | DigcfAllClasses);
                if (deviceInfoSet == new IntPtr(-1)) return devices;
                for (uint index = 0; ; index++)
                {
                    SpDevInfoData info = new SpDevInfoData { Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(SpDevInfoData)) };
                    if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, ref info)) break;

                    string hardwareId = ReadProperty(deviceInfoSet, ref info, SpdrpHardwareId);
                    Match vendor = VendorPattern.Match(hardwareId);
                    Match product = ProductPattern.Match(hardwareId);
                    if (!vendor.Success || !product.Success) continue;

                    string name = ReadProperty(deviceInfoSet, ref info, SpdrpFriendlyName);
                    if (String.IsNullOrWhiteSpace(name)) name = ReadProperty(deviceInfoSet, ref info, SpdrpDeviceDesc);
                    devices.Add(new PnpKeyboard {
                        VendorId = vendor.Groups[1].Value.ToUpperInvariant(),
                        ProductId = product.Groups[1].Value.ToUpperInvariant(),
                        InstanceId = hardwareId,
                        Name = String.IsNullOrWhiteSpace(name) ? "USB/HID device" : name
                    });
                }
            }
            catch { }
            finally
            {
                if (deviceInfoSet != IntPtr.Zero && deviceInfoSet != new IntPtr(-1))
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }

            return devices.GroupBy(device => device.Identity, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.OrderByDescending(device => !String.Equals(device.Name, "USB/HID device", StringComparison.OrdinalIgnoreCase)).First())
                .ToList();
        }

        private static string ReadProperty(IntPtr deviceInfoSet, ref SpDevInfoData info, uint property)
        {
            uint type;
            uint required;
            SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref info, property, out type, IntPtr.Zero, 0, out required);
            if (required == 0 || System.Runtime.InteropServices.Marshal.GetLastWin32Error() != ErrorInsufficientBuffer) return "";

            IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)required);
            try
            {
                if (!SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref info, property, out type, buffer, required, out required)) return "";
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(buffer) ?? "";
            }
            finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer); }
        }
    }

    internal sealed class LayoutKey
    {
        public string Id;
        public string Label;
        public double X;
        public double Y;
        public double W;
        public double H;
    }

    internal sealed class DriveEffect
    {
        public string Name;
        public bool Speed;
        public bool Brightness;
        public bool ColorValueDefined;
        public bool MixColor;
        public int SleepValue;
    }

    internal sealed class DriveKeySlot
    {
        public int SlotIndex;
        public string KeySymbol;
        public string EnumSymbol;
        public int? KeyCode;
        public string Label;
    }

    internal sealed class DriveLayerLayout
    {
        public int LayerIndex;
        public string LayerName;
        public string SourceSymbol;
        public string LayoutId;
        public List<DriveKeySlot> KeySlots = new List<DriveKeySlot>();
    }

    internal sealed class DriveLayoutGroup
    {
        public int GroupIndex;
        public List<DriveLayerLayout> Layers = new List<DriveLayerLayout>();

        public override string ToString()
        {
            int slots = Layers.Count == 0 ? 0 : Layers[0].KeySlots.Count;
            return "Layout group " + (GroupIndex + 1) + "  ·  " + slots + " ordered slots";
        }
    }

    internal sealed class DriveKeyChoice
    {
        public int? KeyCode;
        public string Label;
        public string Symbol;
        public string Display;
        public bool IsNoOverride;

        public override string ToString() { return Display; }
    }

    internal sealed class DriveConnection
    {
        public string Connection;
        public string VendorId;
        public string ProductId;
        public string UsagePage;
        public string Usage;
        public string Protocol;
        public bool Specialized;
        public string Uuid;
        public string FirmwareMinimum;
        public bool? HasSideLight;
        public bool HasDeclaredConfiguratorData;
        public int LayoutGroupCount;
        public List<DriveLayoutGroup> LayoutGroups = new List<DriveLayoutGroup>();
        public List<string> Layers = new List<string>();
        public List<int> LayerIds = new List<int>();
        public List<string> Tables = new List<string>();
        public List<DriveEffect> Effects = new List<DriveEffect>();

        public override string ToString()
        {
            return Connection + "  ·  VID " + VendorId + " PID " + ProductId + "  ·  " + Protocol;
        }
    }

    internal sealed class DriveModel
    {
        public string Name;
        public string ImageUrl;
        public List<DriveConnection> Connections = new List<DriveConnection>();
    }

    internal sealed class DriveDirectory
    {
        public int DescriptorCount;
        public int LabelCount;
        public string RetrievedAt;
        public string BundleUrl;
        public string BundleHash;
        public List<DriveModel> Models = new List<DriveModel>();
        public Dictionary<string, List<DriveKeySlot>> KeyLayoutArrays = new Dictionary<string, List<DriveKeySlot>>(StringComparer.OrdinalIgnoreCase);

        public static DriveDirectory Load()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Stream stream = assembly.GetManifestResourceStream("RkRebuild.DriveCatalog.json");
            if (stream == null) throw new InvalidOperationException("The embedded RK Drive catalog is missing.");
            using (stream)
            using (JsonDocument document = JsonDocument.Parse(stream))
            {
                JsonElement root = document.RootElement;
                DriveDirectory directory = new DriveDirectory {
                    DescriptorCount = ModelCatalog.GetInt(root, "descriptorCount"),
                    LabelCount = ModelCatalog.GetInt(root, "modelLabelCount"),
                    RetrievedAt = ModelCatalog.GetString(root, "retrievedAtUtc")
                };
                JsonElement sourceBundle = ModelCatalog.GetValue(root, "sourceBundle");
                directory.BundleUrl = ModelCatalog.GetString(sourceBundle, "url");
                directory.BundleHash = ModelCatalog.GetString(sourceBundle, "sha256");

                foreach (JsonElement array in ModelCatalog.AsArray(ModelCatalog.GetValue(root, "keyLayoutArrays")))
                {
                    string id = ModelCatalog.GetString(array, "id");
                    if (String.IsNullOrWhiteSpace(id)) continue;
                    List<DriveKeySlot> slots = new List<DriveKeySlot>();
                    foreach (JsonElement slot in ModelCatalog.AsArray(ModelCatalog.GetValue(array, "key_slots")))
                    {
                        slots.Add(new DriveKeySlot {
                            SlotIndex = ModelCatalog.GetInt(slot, "slot_index"),
                            KeySymbol = ModelCatalog.GetString(slot, "key_symbol"),
                            EnumSymbol = ModelCatalog.GetString(slot, "enum_symbol"),
                            KeyCode = GetNullableInt(slot, "key_code"),
                            Label = ModelCatalog.GetString(slot, "label")
                        });
                    }
                    directory.KeyLayoutArrays[id] = slots;
                }

                foreach (JsonElement item in ModelCatalog.AsArray(ModelCatalog.GetValue(root, "models")))
                {
                    string name = ModelCatalog.GetString(item, "name");
                    DriveModel model = FindOrAdd(directory, name);
                    if (String.IsNullOrEmpty(model.ImageUrl)) model.ImageUrl = ModelCatalog.GetString(item, "image_url");
                    JsonElement web = ModelCatalog.GetValue(item, "web_configurator");
                    DriveConnection connection = new DriveConnection {
                        Connection = ModelCatalog.GetString(item, "connection"),
                        VendorId = ModelCatalog.GetString(item, "vendor_id_hex"),
                        ProductId = ModelCatalog.GetString(item, "product_id_hex"),
                        UsagePage = ModelCatalog.GetString(item, "usage_page_hex"),
                        Usage = ModelCatalog.GetString(item, "usage_hex"),
                        Protocol = ModelCatalog.GetString(item, "protocol_type")
                    };
                    if (web.ValueKind == JsonValueKind.Object)
                    {
                        connection.HasDeclaredConfiguratorData = true;
                        connection.LayoutGroupCount = ModelCatalog.GetInt(web, "layout_group_count");
                        connection.Layers = ReadStrings(ModelCatalog.GetValue(web, "key_layers"));
                        connection.LayerIds = ReadInts(ModelCatalog.GetValue(web, "key_layer_ids"));
                        connection.Tables = ReadStrings(ModelCatalog.GetValue(web, "key_tables"));
                        foreach (JsonElement groupElement in ModelCatalog.AsArray(ModelCatalog.GetValue(web, "key_layout_groups")))
                        {
                            DriveLayoutGroup group = new DriveLayoutGroup { GroupIndex = ModelCatalog.GetInt(groupElement, "group_index") };
                            foreach (JsonElement layerElement in ModelCatalog.AsArray(ModelCatalog.GetValue(groupElement, "layers")))
                            {
                                string layoutId = ModelCatalog.GetString(layerElement, "layout_id");
                                List<DriveKeySlot> slots;
                                if (!directory.KeyLayoutArrays.TryGetValue(layoutId, out slots)) slots = new List<DriveKeySlot>();
                                group.Layers.Add(new DriveLayerLayout {
                                    LayerIndex = ModelCatalog.GetInt(layerElement, "layer_index"),
                                    LayerName = ModelCatalog.GetString(layerElement, "layer_name"),
                                    SourceSymbol = ModelCatalog.GetString(layerElement, "source_symbol"),
                                    LayoutId = layoutId,
                                    KeySlots = slots
                                });
                            }
                            connection.LayoutGroups.Add(group);
                        }
                        foreach (JsonElement effect in ModelCatalog.AsArray(ModelCatalog.GetValue(web, "lighting_effects")))
                        {
                            connection.Effects.Add(new DriveEffect {
                                Name = ModelCatalog.GetString(effect, "name"),
                                Speed = ModelCatalog.GetBool(effect, "speed"),
                                Brightness = ModelCatalog.GetBool(effect, "brightness"),
                                ColorValueDefined = ModelCatalog.GetBool(effect, "colorValueDefined"),
                                MixColor = ModelCatalog.GetBool(effect, "mixColor"),
                                SleepValue = ModelCatalog.GetInt(effect, "sleepValue")
                            });
                        }
                    }
                    model.Connections.Add(connection);
                }

                foreach (JsonElement item in ModelCatalog.AsArray(ModelCatalog.GetValue(root, "specializedKeyboardProfiles")))
                {
                    string name = ModelCatalog.GetString(item, "name");
                    DriveModel model = FindOrAdd(directory, name);
                    if (String.IsNullOrEmpty(model.ImageUrl)) model.ImageUrl = ModelCatalog.GetString(item, "image_url");
                    bool hasSideLight = ModelCatalog.GetBool(item, "has_side_light");
                    model.Connections.Add(new DriveConnection {
                        Connection = ModelCatalog.GetString(item, "connection"),
                        VendorId = ModelCatalog.GetString(item, "vendor_id_hex"),
                        ProductId = ModelCatalog.GetString(item, "product_id_hex"),
                        UsagePage = ModelCatalog.GetString(item, "usage_page_hex"),
                        Usage = ModelCatalog.GetString(item, "usage_hex"),
                        Protocol = ModelCatalog.GetString(item, "protocol_type"),
                        Specialized = true,
                        Uuid = ModelCatalog.GetString(item, "uuid"),
                        FirmwareMinimum = ModelCatalog.GetString(item, "min_firmware_version"),
                        HasSideLight = hasSideLight
                    });
                }
                return directory;
            }
        }

        private static DriveModel FindOrAdd(DriveDirectory directory, string name)
        {
            DriveModel found = directory.Models.FirstOrDefault(m => String.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));
            if (found != null) return found;
            DriveModel model = new DriveModel { Name = name };
            directory.Models.Add(model);
            return model;
        }

        private static List<string> ReadStrings(JsonElement value)
        {
            return ModelCatalog.AsArray(value).Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()).ToList();
        }

        private static List<int> ReadInts(JsonElement value)
        {
            return ModelCatalog.AsArray(value).Where(v => v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out _))
                .Select(v => v.GetInt32()).ToList();
        }

        private static int? GetNullableInt(JsonElement element, string name)
        {
            JsonElement value = ModelCatalog.GetValue(element, name);
            return value.ValueKind == JsonValueKind.Number ? (int?)value.GetInt32() : null;
        }
    }

    internal sealed class ModelCatalog
    {
        public string VendorId = "";
        public List<ModelProfile> Models = new List<ModelProfile>();
        private static string NormalizeCatalogVendorId(string raw)
        {
            string value = (raw ?? "").Trim();
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) value = value.Substring(2);
            if (value.Length < 1 || value.Length > 4 || !Regex.IsMatch(value, "^[0-9a-fA-F]+$"))
                throw new InvalidDataException("The model catalog must declare a valid vendor ID.");
            return value.PadLeft(4, '0').ToUpperInvariant();
        }
        public static ModelCatalog Load()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Stream stream = assembly.GetManifestResourceStream("RkRebuild.Profiles.json");
            if (stream == null) throw new InvalidOperationException("The embedded model catalog is missing.");
            JsonDocument document = JsonDocument.Parse(stream);
            JsonElement root = document.RootElement;
            JsonElement models;
            if (!root.TryGetProperty("models", out models)) throw new InvalidDataException("The embedded model catalog has an unexpected format.");
            JsonElement layouts = GetValue(root, "layouts");
            ModelCatalog catalog = new ModelCatalog();
            catalog.VendorId = NormalizeCatalogVendorId(GetString(root, "vendorId"));
            foreach (JsonElement item in models.EnumerateArray())
            {
                ModelProfile profile = new ModelProfile();
                profile.Code = GetString(item, "code");
                profile.Name = GetString(item, "name");
                profile.Family = GetString(item, "family");
                profile.Region = GetString(item, "region");
                profile.LayoutId = GetString(item, "layoutId");
                profile.DirectPid = GetBool(item, "isDirectPid");
                profile.KeyCount = GetInt(item, "keyCount");
                JsonElement options = GetValue(GetValue(item, "profileData"), "options");
                if (options.ValueKind == JsonValueKind.Object)
                    foreach (JsonProperty option in options.EnumerateObject()) profile.Options[option.Name] = option.Value.ToString();
                JsonElement features = GetValue(item, "features");
                if (features.ValueKind == JsonValueKind.Object)
                {
                    profile.Rgb = GetBool(features, "rgb");
                    profile.MacroBuffers = GetInt(features, "macroBuffers");
                    profile.Screen = GetString(features, "screen");
                    foreach (JsonElement slot in AsArray(GetValue(features, "lightingModeSlots"))) profile.LightingSlots.Add(ToInt(slot));
                    foreach (JsonElement layer in AsArray(GetValue(features, "layers"))) profile.Layers.Add(layer.ToString());
                }
                JsonElement layout;
                if (layouts.ValueKind == JsonValueKind.Object && layouts.TryGetProperty(profile.LayoutId, out layout))
                {
                    foreach (JsonElement key in AsArray(GetValue(layout, "keys")))
                    {
                        profile.Keys.Add(new LayoutKey {
                            Id = GetString(key, "id"), Label = GetString(key, "label"),
                            X = GetDouble(key, "x"), Y = GetDouble(key, "y"),
                            W = GetDouble(key, "w"), H = GetDouble(key, "h")
                        });
                    }
                }
                catalog.Models.Add(profile);
            }
            if (catalog.Models.Count == 0) throw new InvalidDataException("The embedded model catalog contains no profiles.");
            return catalog;
        }

        public static JsonElement GetValue(JsonElement d, string key) { JsonElement value; return d.ValueKind == JsonValueKind.Object && d.TryGetProperty(key, out value) ? value : default(JsonElement); }
        public static string GetString(JsonElement d, string key) { JsonElement value = GetValue(d, key); return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ValueKind == JsonValueKind.Null ? "" : value.ToString(); }
        public static int GetInt(JsonElement d, string key) { int n; return Int32.TryParse(GetString(d, key), out n) ? n : 0; }
        public static bool GetBool(JsonElement d, string key) { return GetValue(d, key).ValueKind == JsonValueKind.True; }
        public static IEnumerable<JsonElement> AsArray(JsonElement value) { return value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().ToArray() : Enumerable.Empty<JsonElement>(); }

        private static int ToInt(JsonElement value) { int n; return Int32.TryParse(value.ToString(), out n) ? n : 0; }
        private static double GetDouble(JsonElement d, string key) { double n; return Double.TryParse(GetString(d, key), out n) ? n : 0; }
    }

    internal sealed class AppearancePhoto
    {
        public string Id;
        public string Name;
        public string Series;
        public string ImageUrl;
        public string SourceUrl;

        public static List<AppearancePhoto> Load()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Stream stream = assembly.GetManifestResourceStream("RkRebuild.S98Appearance.json");
            if (stream == null) return new List<AppearancePhoto>();
            using (stream)
            using (JsonDocument document = JsonDocument.Parse(stream))
            {
                return ModelCatalog.AsArray(ModelCatalog.GetValue(document.RootElement, "variants"))
                    .Select(item => new AppearancePhoto {
                        Id = ModelCatalog.GetString(item, "id"),
                        Name = ModelCatalog.GetString(item, "name"),
                        Series = ModelCatalog.GetString(item, "series"),
                        ImageUrl = ModelCatalog.GetString(item, "imageUrl"),
                        SourceUrl = ModelCatalog.GetString(item, "sourceUrl")
                    })
                    .Where(item => !String.IsNullOrWhiteSpace(item.Id) && !String.IsNullOrWhiteSpace(item.Name) && !String.IsNullOrWhiteSpace(item.ImageUrl))
                    .ToList();
            }
        }

        public override string ToString() { return Name; }
    }

    internal sealed partial class MainWindow : Window
    {
        private static readonly MediaColor Ink = MediaColor.FromRgb(35, 42, 53);
        private static readonly MediaColor Muted = MediaColor.FromRgb(111, 120, 133);
        private static readonly MediaColor Accent = MediaColor.FromRgb(49, 94, 181);
        private static readonly MediaColor Surface = MediaColor.FromRgb(255, 255, 255);
        private readonly ModelCatalog _catalog;
        private readonly DriveDirectory _driveDirectory;
        private readonly List<AppearancePhoto> _appearancePhotos;
        private readonly AppSettings _settings;
        private StackPanel _pageBody;
        private TextBlock _pageName;
        private TextBlock _profileHeader;
        private readonly Forms.NotifyIcon _tray;
        private Image _shellBackdrop;
        private ModelProfile _selected;
        private DriveModel _selectedDriveModel;
        private readonly HashSet<string> _knownDeviceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private List<PnpKeyboard> _pnpDevices = new List<PnpKeyboard>();
        private DispatcherTimer _pnpTimer;
        private string _pnpSnapshot = "";
        private bool _pnpScanRunning;
        private string _page = "Device";
        private bool _allowClose;

        public MainWindow(ModelCatalog catalog, DriveDirectory driveDirectory, List<AppearancePhoto> appearancePhotos, AppSettings settings)
        {
            _catalog = catalog;
            _driveDirectory = driveDirectory;
            _appearancePhotos = appearancePhotos ?? new List<AppearancePhoto>();
            _settings = settings;
            if (String.IsNullOrWhiteSpace(settings.SelectedCode)) _page = "Compatibility";
            foreach (ModelProfile profile in _catalog.Models.Where(item => item.DirectPid))
                _knownDeviceIds.Add(_catalog.VendorId + ":" + NormalizeDeviceId(profile.Code));
            foreach (DriveConnection connection in _driveDirectory.Models.SelectMany(model => model.Connections))
                _knownDeviceIds.Add(NormalizeDeviceId(connection.VendorId) + ":" + NormalizeDeviceId(connection.ProductId));
            if (String.IsNullOrWhiteSpace(_settings.ResourceRoot))
                _settings.ResourceRoot = FindInstalledResourceRoot();
            else
                _settings.ResourceRoot = NormalizeResourceRoot(_settings.ResourceRoot);
            _selected = _catalog.Models.FirstOrDefault(m => m.Code == settings.SelectedCode) ?? _catalog.Models.First();
            Title = "RK Keyboard";
            Width = 1500;
            Height = 900;
            MinWidth = 1120;
            MinHeight = 720;
            WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.CanResizeWithGrip;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = Brush(20, 20, 20);
            FontFamily = LoadRkFont();
            BuildShell();
            _tray = BuildTray();
            Closing += OnClosing;
            StateChanged += OnStateChanged;
            SelectProfile(_selected, false);
            RefreshPnpDevices(true);
            _pnpTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            _pnpTimer.Tick += delegate { RefreshPnpDevices(true); };
            _pnpTimer.Start();
            SetStartup(_settings.StartWithWindows);
        }

        private void BuildShell()
        {
            Grid window = new Grid();
            Content = window;
            _shellBackdrop = new Image { Stretch = Stretch.Fill, Source = LoadSkinBitmap("main_nr.png") };
            window.Children.Add(_shellBackdrop);

            Grid root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(72) });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            window.Children.Add(root);

            Style commonButtonStyle = new Style(typeof(Button));
            commonButtonStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brush(20, 20, 20)));
            commonButtonStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brush(220, 220, 220)));
            commonButtonStyle.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(80, 80, 80)));
            commonButtonStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));
            commonButtonStyle.Setters.Add(new Setter(Control.TemplateProperty, SkinnedButtonTemplate()));
            Resources[typeof(Button)] = commonButtonStyle;

            Style textBoxStyle = new Style(typeof(TextBox));
            textBoxStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brush(20, 20, 20)));
            textBoxStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brush(220, 220, 220)));
            textBoxStyle.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(80, 80, 80)));
            textBoxStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(7, 4, 7, 4)));
            Resources[typeof(TextBox)] = textBoxStyle;

            Style comboBoxStyle = new Style(typeof(ComboBox));
            comboBoxStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brush(20, 20, 20)));
            comboBoxStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brush(220, 220, 220)));
            comboBoxStyle.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(80, 80, 80)));
            comboBoxStyle.Setters.Add(new Setter(ComboBox.IsEditableProperty, true));
            comboBoxStyle.Setters.Add(new Setter(ComboBox.IsReadOnlyProperty, true));
            comboBoxStyle.Setters.Add(new Setter(ComboBox.IsTextSearchEnabledProperty, false));
            Resources[typeof(ComboBox)] = comboBoxStyle;

            Grid titleBar = new Grid { Margin = new Thickness(18, 0, 14, 0) };
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetColumnSpan(titleBar, 2);
            root.Children.Add(titleBar);
            StackPanel brand = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            Image logo = SkinImage("logo.png", 104, 42);
            if (logo != null) brand.Children.Add(logo);
            TextBlock productName = new TextBlock { Text = "RK Keyboard", Foreground = Brush(220, 220, 220), FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0) };
            brand.Children.Add(productName);
            titleBar.Children.Add(brand);
            titleBar.MouseLeftButtonDown += delegate(object sender, MouseButtonEventArgs e)
            {
                DependencyObject source = e.OriginalSource as DependencyObject;
                while (source != null && source != titleBar)
                {
                    if (source is Button || source is ComboBox) return;
                    source = LogicalTreeHelper.GetParent(source);
                }
                if (e.ButtonState == MouseButtonState.Pressed)
                {
                    if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
                    else DragMove();
                }
            };

            StackPanel topTools = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(topTools, 1);
            titleBar.Children.Add(topTools);
            TextBlock modelLabel = new TextBlock { Text = "DEVICE", Foreground = Brush(175, 175, 175), FontSize = 9, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 9, 0) };
            topTools.Children.Add(modelLabel);
            ComboBox selector = new ComboBox { Width = 276, Height = 32, Padding = new Thickness(8, 4, 8, 4), Background = Brush(20, 20, 20), BorderBrush = Brush(91, 91, 91), Foreground = Brush(220, 220, 220), ItemsSource = _catalog.Models.OrderBy(m => m.Name).ThenBy(m => m.Code).ToList(), DisplayMemberPath = "Name", Text = _selected.Name };
            selector.SelectionChanged += delegate { if (selector.SelectedItem is ModelProfile) SelectProfile((ModelProfile)selector.SelectedItem, true); };
            topTools.Children.Add(selector);
            _profileSelector = selector;

            StackPanel windowActions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(15, 0, 0, 0) };
            Grid.SetColumn(windowActions, 2);
            titleBar.Children.Add(windowActions);
            Button minimize = SkinWindowButton("bigmin_nr.png", "bigmin_ov.png", delegate { WindowState = WindowState.Minimized; });
            Button exit = SkinWindowButton("bigexit_nr.png", "bigexit_ov.png", delegate { ExitApplication(); });
            windowActions.Children.Add(minimize);
            windowActions.Children.Add(exit);

            Border sidebar = new Border { Background = new SolidColorBrush(MediaColor.FromArgb(220, 15, 15, 15)), Padding = new Thickness(13, 15, 13, 15) };
            Grid.SetRow(sidebar, 1);
            root.Children.Add(sidebar);
            StackPanel nav = new StackPanel();
            sidebar.Child = nav;
            nav.Children.Add(NavCaption("KEYBOARD"));
            AddNav(nav, "Device", "Device overview");
            AddNav(nav, "Key mapping", "Key mapping");
            AddNav(nav, "Lighting", "Lighting");
            AddNav(nav, "Macros", "Macro manager");
            AddNav(nav, "RK Drive editor", "RK Drive editor");
            nav.Children.Add(NavCaption("PROFILES"));
            AddNav(nav, "Models", "Model profiles");
            AddNav(nav, "RK Drive directory", "RK Drive directory");
            AddNav(nav, "Compatibility", "All-model compatibility");
            nav.Children.Add(NavCaption("SOFTWARE"));
            AddNav(nav, "Preferences", "Preferences");
            Border spacer = new Border { Height = 1, Background = Brush(70, 70, 70), Margin = new Thickness(4, 20, 4, 13) };
            nav.Children.Add(spacer);
            nav.Children.Add(new TextBlock { Text = "Local profile drafts", Foreground = Brush(220, 220, 220), FontSize = 11, Margin = new Thickness(5, 0, 5, 5) });
            nav.Children.Add(new TextBlock { Text = "No settings are applied. Experimental lighting queries require an explicit action.", Foreground = Brush(160, 160, 160), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(5, 0, 5, 0) });

            Grid main = new Grid { Margin = new Thickness(12, 0, 20, 14) };
            main.RowDefinitions.Add(new RowDefinition { Height = new GridLength(60) });
            main.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(main, 1);
            Grid.SetRow(main, 1);
            root.Children.Add(main);
            Grid pageHeader = new Grid { Margin = new Thickness(10, 0, 10, 0) };
            pageHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            pageHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetRow(pageHeader, 0);
            main.Children.Add(pageHeader);
            StackPanel heading = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            _pageName = new TextBlock { Text = _page == "Compatibility" ? "All-model compatibility" : "Device overview", Foreground = Brush(235, 235, 235), FontSize = 17, FontWeight = FontWeights.SemiBold };
            _profileHeader = new TextBlock { Text = "", Foreground = Brush(175, 175, 175), FontSize = 10, Margin = new Thickness(0, 2, 0, 0) };
            heading.Children.Add(_pageName);
            heading.Children.Add(_profileHeader);
            pageHeader.Children.Add(heading);
            TextBlock status = new TextBlock { Text = "LOCAL MODE", Foreground = Brush(255, 128, 0), FontSize = 9, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
            Grid.SetColumn(status, 1);
            pageHeader.Children.Add(status);

            ScrollViewer scroller = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Background = Brushes.Transparent };
            Grid.SetRow(scroller, 1);
            main.Children.Add(scroller);
            _pageBody = new StackPanel { Margin = new Thickness(10, 8, 10, 16) };
            scroller.Content = _pageBody;
        }

        private ComboBox _profileSelector;

        private void AddNav(StackPanel nav, string page, string label)
        {
            string icon = NavIcon(page, page == _page);
            Grid content = new Grid();
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(36) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Image navIcon = SkinImage(icon, 30, 30);
            if (navIcon != null) { navIcon.HorizontalAlignment = HorizontalAlignment.Left; content.Children.Add(navIcon); }
            TextBlock navText = new TextBlock { Text = label, Foreground = page == _page ? Brush(255, 255, 255) : Brush(210, 210, 210), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(navText, 1);
            content.Children.Add(navText);
            Button button = new Button { Content = content, Tag = page, Height = 42, Margin = new Thickness(0, 2, 0, 2), Padding = new Thickness(7, 0, 5, 0), HorizontalContentAlignment = HorizontalAlignment.Stretch, BorderThickness = new Thickness(0), FontSize = 11, Cursor = Cursors.Hand, Background = page == _page ? Brush(60, 31, 15) : Brushes.Transparent, Foreground = Brush(220, 220, 220) };
            button.Click += delegate { SetPage(page); };
            Style navStyle = new Style(typeof(Button));
            navStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            navStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brush(220, 220, 220)));
            navStyle.Setters.Add(new Setter(Control.TemplateProperty, FlatButtonTemplate()));
            button.Style = navStyle;
            button.MouseEnter += delegate
            {
                if (_page != page) button.Background = Brush(45, 35, 28);
                if (navIcon != null) navIcon.Source = LoadSkinBitmap(NavIcon(page, true));
            };
            button.MouseLeave += delegate
            {
                if (_page != page) button.Background = Brushes.Transparent;
                if (navIcon != null) navIcon.Source = LoadSkinBitmap(NavIcon(page, _page == page));
            };
            nav.Children.Add(button);
        }

        private static string NavIcon(string page, bool selected)
        {
            string name = page == "Device" || page == "Models" ? "home" : page == "Key mapping" ? "key" : page == "Lighting" ? "light" : page == "Macros" ? "macro" : page == "RK Drive editor" ? "custom" : "cfg";
            return name + (selected ? "_ov.png" : "_nr.png");
        }

        private Button SkinWindowButton(string normalName, string hoverName, Action action)
        {
            Image icon = SkinImage(normalName, 30, 30);
            Button button = new Button { Width = 34, Height = 34, Margin = new Thickness(2, 0, 2, 0), Padding = new Thickness(0), Background = Brushes.Transparent, BorderThickness = new Thickness(0), Content = icon, Cursor = Cursors.Hand, ToolTip = normalName.StartsWith("bigmin", StringComparison.OrdinalIgnoreCase) ? "Minimize" : "Close" };
            button.Click += delegate { action(); };
            button.MouseEnter += delegate { BitmapSource hover = LoadSkinBitmap(hoverName); if (hover != null && icon != null) icon.Source = hover; };
            button.MouseLeave += delegate { BitmapSource normal = LoadSkinBitmap(normalName); if (normal != null && icon != null) icon.Source = normal; };
            return button;
        }

        private ControlTemplate FlatButtonTemplate()
        {
            FrameworkElementFactory border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(7));
            border.SetBinding(Border.BackgroundProperty, new Binding("Background") { RelativeSource = RelativeSource.TemplatedParent });
            FrameworkElementFactory content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.MarginProperty, new Thickness(0));
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            border.AppendChild(content);
            return new ControlTemplate(typeof(Button)) { VisualTree = border };
        }

        private ControlTemplate SkinnedButtonTemplate()
        {
            FrameworkElementFactory border = new FrameworkElementFactory(typeof(Border));
            border.SetBinding(Border.BackgroundProperty, new Binding("Background") { RelativeSource = RelativeSource.TemplatedParent });
            border.SetBinding(Border.BorderBrushProperty, new Binding("BorderBrush") { RelativeSource = RelativeSource.TemplatedParent });
            border.SetBinding(Border.BorderThicknessProperty, new Binding("BorderThickness") { RelativeSource = RelativeSource.TemplatedParent });
            FrameworkElementFactory content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.MarginProperty, new Thickness(0));
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            border.AppendChild(content);
            return new ControlTemplate(typeof(Button)) { VisualTree = border };
        }

        private TextBlock NavCaption(string text)
        {
            return new TextBlock { Text = text, Foreground = Brush(129, 140, 155), FontSize = 9, FontWeight = FontWeights.SemiBold, Margin = new Thickness(10, 12, 0, 7) };
        }

        private void SetPage(string page)
        {
            _page = page;
            string title = page == "Device" ? "Device overview" : page == "Key mapping" ? "Key mapping" : page == "Models" ? "Model profiles" : page == "RK Drive directory" ? "RK Drive directory" : page;
            _pageName.Text = title;
            foreach (Button button in FindVisualButtons(this))
            {
                if (button.Tag is string && new[] { "Device", "Key mapping", "Lighting", "Macros", "RK Drive editor", "Models", "RK Drive directory", "Compatibility", "Preferences" }.Contains((string)button.Tag))
                {
                    bool active = (string)button.Tag == page;
                    button.Background = active ? Brush(60, 31, 15) : Brushes.Transparent;
                    button.Foreground = active ? Brushes.White : Brush(210, 210, 210);
                    Grid content = button.Content as Grid;
                    if (content != null)
                        foreach (UIElement child in content.Children)
                        {
                            TextBlock text = child as TextBlock;
                            if (text != null) text.Foreground = active ? Brushes.White : Brush(210, 210, 210);
                            Image icon = child as Image;
                            if (icon != null) icon.Source = LoadSkinBitmap(NavIcon((string)button.Tag, active));
                        }
                }
            }
            RenderPage();
        }

        private static IEnumerable<Button> FindVisualButtons(DependencyObject parent)
        {
            if (parent == null) yield break;
            int count = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < count; i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                Button button = child as Button;
                if (button != null) yield return button;
                foreach (Button nested in FindVisualButtons(child)) yield return nested;
            }
        }

        private void SelectProfile(ModelProfile profile, bool save)
        {
            _selected = profile;
            _settings.SelectedCode = profile.Code;
            if (_profileSelector != null)
            {
                if (_profileSelector.SelectedItem != profile) _profileSelector.SelectedItem = profile;
                _profileSelector.Text = profile.Name;
            }
            _profileHeader.Text = profile.Name + "  ·  reference profile " + profile.Code + "  ·  not a detected device";
            if (save) SettingsStore.Save(_settings);
            RenderPage();
        }

        private void RenderPage()
        {
            if (_pageBody == null || _selected == null) return;
            _pageBody.Children.Clear();
            if (_page == "Device") RenderDevice();
            else if (_page == "Key mapping") RenderKeymap();
            else if (_page == "Lighting") RenderLighting();
            else if (_page == "Macros") RenderMacros();
            else if (_page == "RK Drive editor") RenderDriveEditor();
            else if (_page == "Models") RenderModels();
            else if (_page == "RK Drive directory") RenderDriveDirectory();
            else if (_page == "Compatibility") RenderCompatibility();
            else RenderPreferences();
        }

        private void RenderDevice()
        {
            AddIntro("Keyboard overview", "Windows Plug and Play device records are checked for a supported RK model. Device reports are not opened by this identification pass.");
            Grid grid = new Grid { Margin = new Thickness(0, 10, 0, 0) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.25, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(16) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.85, GridUnitType.Star) });
            Border profileCard = Card();
            Grid.SetColumn(profileCard, 0);
            grid.Children.Add(profileCard);
            StackPanel summary = new StackPanel { Margin = new Thickness(22) };
            profileCard.Child = summary;
            List<PnpKeyboard> rkDevices = FindKnownRkDevices();
            PnpKeyboard connected = rkDevices.Count == 1 ? rkDevices[0] : null;
            ModelProfile detectedProfile = connected == null ? null : FindProfileForDevice(connected);
            ModelProfile overviewProfile = detectedProfile ?? _selected;
            ModelProfile photoProfile = detectedProfile ?? _selected;
            string photoPreferenceKey = PhotoPreferenceKey(connected, photoProfile ?? overviewProfile);
            List<DriveModel> photoVariants = GetPhotoVariants(connected, photoProfile);
            int connectedPhotoCandidateCount = connected == null ? 0 : GetPhotoVariants(connected, null).Count;
            DriveModel photoModel = GetPreferredPhotoModel(photoPreferenceKey, photoVariants, connected, photoProfile);
            List<AppearancePhoto> appearanceVariants = photoProfile != null
                && String.Equals(photoProfile.Family, "S98", StringComparison.OrdinalIgnoreCase)
                && String.Equals(photoProfile.Region, "ANSI", StringComparison.OrdinalIgnoreCase)
                ? _appearancePhotos
                : new List<AppearancePhoto>();
            string appearancePreferenceKey = "appearance:" + photoPreferenceKey;
            string savedAppearanceId;
            AppearancePhoto appearance = _settings.AppearanceVariantOverrides.TryGetValue(appearancePreferenceKey, out savedAppearanceId)
                ? appearanceVariants.FirstOrDefault(item => String.Equals(item.Id, savedAppearanceId, StringComparison.OrdinalIgnoreCase))
                : null;
            summary.Children.Add(Kicker(connected == null ? "SELECTED SOFTWARE PROFILE" : "CONNECTED KEYBOARD"));
            summary.Children.Add(Headline(connected == null ? _selected.Name : detectedProfile == null ? "Selected profile · " + _selected.Name : DescribeDeviceModel(connected, detectedProfile), 23));
            summary.Children.Add(Paragraph(connected == null
                ? "Catalog code " + _selected.Code + "  ·  Family " + Blank(_selected.Family) + "  ·  " + Blank(_selected.Region)
                : "Windows reports VID " + connected.VendorId + "  ·  PID " + connected.ProductId + "  ·  " + connected.Name + (detectedProfile == null ? "  ·  selected profile is not confirmed by this device ID" : ""), 13));
            summary.Children.Add(new Border { Height = 1, Background = Brush(231, 234, 238), Margin = new Thickness(0, 12, 0, 14) });
            summary.Children.Add(MetricGrid(new string[,] { { "KEYS", overviewProfile.KeyCount.ToString() }, { "LAYOUT", overviewProfile.LayoutId }, { "LAYERS", overviewProfile.Layers.Count.ToString() }, { "LIGHTING SLOTS", overviewProfile.LightingSlots.Count.ToString() } }));
            summary.Children.Add(new TextBlock {
                Text = rkDevices.Count == 0 ? "Connection status: no supported RK VID/PID found in Windows PnP records" :
                    rkDevices.Count == 1 ? "Connection status: device present  ·  model match " + (detectedProfile == null ? "not confirmed; USB ID appears in " + connectedPhotoCandidateCount + " RK Drive labels" : "matches catalog profile " + detectedProfile.Code) :
                    "Connection status: " + rkDevices.Count + " RK device records found  ·  choose a single device to confirm the model",
                Foreground = Brush(rkDevices.Count == 1 && detectedProfile != null ? (byte)35 : (byte)166, rkDevices.Count == 1 && detectedProfile != null ? (byte)118 : (byte)95, rkDevices.Count == 1 && detectedProfile != null ? (byte)75 : (byte)24),
                FontSize = 12, Margin = new Thickness(0, 18, 0, 0), TextWrapping = TextWrapping.Wrap
            });
            summary.Children.Add(new TextBlock {
                Text = connected == null ? "The selected profile is catalog data; it does not prove the model or revision currently connected." :
                    detectedProfile == null ? "The USB ID is shared by multiple RK model labels. The displayed layout and photo follow your selected profile; finish choice is manual and live RGB is not read." :
                    (detectedProfile.Rgb ? "RGB capability is declared for this catalog profile. Live lighting mode and color are not read by PnP identification." : "The matched model and revision remain subject to the catalog's profile coverage."),
                Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0)
            });

            Border artCard = Card();
            Grid.SetColumn(artCard, 2);
            grid.Children.Add(artCard);
            StackPanel artStack = new StackPanel { Margin = new Thickness(19) };
            artCard.Child = artStack;
            string photoKickerText = appearance != null
                ? "USER-SELECTED FINISH PHOTO"
                : appearanceVariants.Count > 0
                    ? detectedProfile == null ? "S98 MODEL PHOTO · FINISH UNCONFIRMED" : "CONNECTED S98 MODEL · FINISH UNCONFIRMED"
                    : connected == null ? "SELECTED PROFILE PHOTO" : detectedProfile == null ? "CONNECTED DEVICE · SELECTED PROFILE" : "CONNECTED MODEL PHOTO";
            TextBlock photoKicker = Kicker(photoKickerText);
            artStack.Children.Add(photoKicker);
            TextBlock appearanceLabel = new TextBlock {
                Text = appearance != null
                    ? "Selected finish: " + appearance.Name + "."
                    : appearanceVariants.Count > 0
                        ? "Finish not confirmed. This is a model/layout reference photo; USB identity does not report case or keycap color."
                        : photoModel == null ? "No official product image is mapped for this profile." : "Model/layout reference from RK Drive; physical finish and live RGB are not detected.",
                Foreground = Brush(175, 175, 175), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 12)
            };
            artStack.Children.Add(appearanceLabel);
            Image image = new Image { Stretch = Stretch.Uniform };
            TextBlock photoStatus = new TextBlock { Text = "Loading official model photo…", Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
            string photoUrl = appearance != null ? appearance.ImageUrl : photoModel == null ? "" : photoModel.ImageUrl;
            if (!String.IsNullOrWhiteSpace(photoUrl)) LoadDriveImage(image, photoUrl, photoStatus);
            else image = LoadProfileImage();
            if (image != null)
            {
                image.Height = 250;
                image.Stretch = Stretch.Uniform;
                artStack.Children.Add(image);
            }
            else
            {
                Border placeholder = new Border { Height = 210, Background = Brush(20, 20, 20), BorderBrush = Brush(70, 70, 70), BorderThickness = new Thickness(1), Child = new TextBlock { Text = "Model image unavailable", Foreground = Brush(175, 175, 175), FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center } };
                artStack.Children.Add(placeholder);
            }
            artStack.Children.Add(photoStatus);
            if (appearanceVariants.Count > 1)
            {
                artStack.Children.Add(new TextBlock { Text = "CHOOSE YOUR S98 FINISH", Foreground = Brush(111, 120, 133), FontSize = 9, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 5) });
                WrapPanel appearanceChoices = new WrapPanel { Margin = new Thickness(0, 0, 0, 0) };
                List<Button> appearanceCards = new List<Button>();
                foreach (AppearancePhoto option in appearanceVariants)
                {
                    bool optionIsSelected = appearance != null && String.Equals(option.Id, appearance.Id, StringComparison.OrdinalIgnoreCase);
                    Button card = new Button {
                        Width = 126,
                        Height = 92,
                        Padding = new Thickness(4),
                        Margin = new Thickness(0, 0, 6, 6),
                        Background = Brush(255, 255, 255),
                        BorderBrush = optionIsSelected ? Brush(49, 94, 181) : Brush(225, 229, 232),
                        BorderThickness = new Thickness(optionIsSelected ? 2 : 1),
                        Cursor = Cursors.Hand,
                        IsTabStop = true,
                        Tag = option,
                        ToolTip = option.Name + " · " + (String.IsNullOrWhiteSpace(option.Series) ? "RK official product photo" : option.Series)
                    };
                    StackPanel optionBody = new StackPanel();
                    Image thumbnail = new Image { Height = 54, Stretch = Stretch.Uniform };
                    TextBlock thumbnailStatus = new TextBlock { Visibility = Visibility.Collapsed };
                    LoadDriveImage(thumbnail, ThumbnailUrl(option.ImageUrl, 380), thumbnailStatus);
                    optionBody.Children.Add(thumbnail);
                    optionBody.Children.Add(new TextBlock { Text = option.Name, Foreground = Brush(48, 56, 68), FontSize = 9, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(1, 2, 1, 0) });
                    optionBody.Children.Add(new TextBlock { Text = String.Equals(option.Series, "Special edition", StringComparison.OrdinalIgnoreCase) ? "Special edition" : "Standard finish", Foreground = Brush(120, 128, 140), FontSize = 8, Margin = new Thickness(1, 1, 1, 0) });
                    card.Content = optionBody;
                    card.Click += delegate {
                        appearance = option;
                        _settings.AppearanceVariantOverrides[appearancePreferenceKey] = option.Id;
                        SettingsStore.Save(_settings);
                        photoKicker.Text = "USER-SELECTED FINISH PHOTO";
                        appearanceLabel.Text = "Selected finish: " + option.Name + ". This photo is your choice; USB identity does not report physical color.";
                        foreach (Button appearanceCard in appearanceCards)
                        {
                            AppearancePhoto cardPhoto = appearanceCard.Tag as AppearancePhoto;
                            bool selected = cardPhoto != null && String.Equals(cardPhoto.Id, option.Id, StringComparison.OrdinalIgnoreCase);
                            appearanceCard.BorderBrush = selected ? Brush(49, 94, 181) : Brush(225, 229, 232);
                            appearanceCard.BorderThickness = new Thickness(selected ? 2 : 1);
                        }
                        LoadDriveImage(image, option.ImageUrl, photoStatus);
                    };
                    appearanceCards.Add(card);
                    appearanceChoices.Children.Add(card);
                }
                artStack.Children.Add(appearanceChoices);
                artStack.Children.Add(new TextBlock { Text = "Finish photo is saved for this model. USB identity cannot detect the physical color; live RGB is not read.", Foreground = Brush(150, 150, 150), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0) });
            }
            else if (photoVariants.Count > 1)
            {
                ComboBox photoSelector = new ComboBox {
                    Height = 31,
                    Margin = new Thickness(0, 9, 0, 0),
                    Padding = new Thickness(7, 4, 7, 4),
                    ItemsSource = photoVariants,
                    DisplayMemberPath = "Name",
                    SelectedItem = photoModel,
                    ToolTip = "Select the RK product image that matches this keyboard's printed layout."
                };
                photoSelector.SelectionChanged += delegate {
                    DriveModel selectedPhoto = photoSelector.SelectedItem as DriveModel;
                    if (selectedPhoto == null) return;
                    _settings.PhotoVariantOverrides[photoPreferenceKey] = selectedPhoto.Name;
                    SettingsStore.Save(_settings);
                    LoadDriveImage(image, selectedPhoto.ImageUrl, photoStatus);
                };
                artStack.Children.Add(photoSelector);
                artStack.Children.Add(new TextBlock { Text = "The device ID does not report case finish or live RGB color.", Foreground = Brush(150, 150, 150), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });
            }
            if (appearance != null || photoModel != null)
            {
                Button openOfficial = ActionButton(appearance != null ? "Open official S98 product page" : "Open official product photo", false);
                openOfficial.Margin = new Thickness(0, 10, 0, 0);
                openOfficial.Click += delegate { OpenOfficialUrl(appearance != null ? appearance.SourceUrl : photoModel.ImageUrl); };
                artStack.Children.Add(openOfficial);
            }
            _pageBody.Children.Add(grid);

            Border info = Card();
            info.Margin = new Thickness(0, 16, 0, 0);
            StackPanel infoBody = new StackPanel { Margin = new Thickness(20) };
            info.Child = infoBody;
            infoBody.Children.Add(Kicker("REBUILD STATUS"));
            infoBody.Children.Add(new TextBlock { Text = "This is a native Windows desktop process. It runs locally and does not open a browser, start a localhost server, or include Python.", Foreground = Brush(58, 66, 78), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0) });
            infoBody.Children.Add(new TextBlock { Text = "Model identification and product photography use Windows/online metadata. The Compatibility page offers explicit experimental lighting queries on eligible endpoints. Configuration writes, macro transfer, display control, updater actions, and firmware access remain unavailable.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });
            _pageBody.Children.Add(info);
        }

        private async void RefreshPnpDevices(bool redraw)
        {
            if (_pnpScanRunning) return;
            _pnpScanRunning = true;
            try
            {
                List<PnpKeyboard> devices = await Task.Run(() => WindowsPnpDiscovery.Enumerate());
                _pnpDevices = devices;
                string snapshot = String.Join("|", FindKnownRkDevices()
                    .Select(device => device.Identity + ":" + device.Name)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase));
                if (String.Equals(snapshot, _pnpSnapshot, StringComparison.Ordinal)) return;
                _pnpSnapshot = snapshot;
                if (redraw && (_page == "Device" || _page == "Compatibility")) RenderPage();
            }
            catch { }
            finally { _pnpScanRunning = false; }
        }

        private List<PnpKeyboard> FindKnownRkDevices()
        {
            return _pnpDevices
                .Where(device => _knownDeviceIds.Contains(device.Identity))
                .GroupBy(device => device.Identity, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToList();
        }

        private ModelProfile FindProfileForDevice(PnpKeyboard device)
        {
            if (device == null || !String.Equals(device.VendorId, _catalog.VendorId, StringComparison.OrdinalIgnoreCase)) return null;
            List<ModelProfile> matches = _catalog.Models.Where(profile => profile.DirectPid && String.Equals(profile.Code, device.ProductId, StringComparison.OrdinalIgnoreCase)).ToList();
            return matches.Count == 1 ? matches[0] : null;
        }

        private List<DriveModel> GetPhotoVariants(PnpKeyboard device, ModelProfile profile)
        {
            IEnumerable<DriveModel> candidates = Enumerable.Empty<DriveModel>();
            if (profile != null)
            {
                string family = NormalizeModelName(profile.Family);
                if (!String.IsNullOrEmpty(family))
                    candidates = _driveDirectory.Models.Where(model => NormalizeModelName(model.Name).Contains(family, StringComparison.OrdinalIgnoreCase));
                if (!candidates.Any())
                    candidates = _driveDirectory.Models.Where(model => NormalizeModelName(profile.Name).Contains(NormalizeModelName(model.Name), StringComparison.OrdinalIgnoreCase));
            }
            else if (device != null)
            {
                candidates = _driveDirectory.Models.Where(model => model.Connections.Any(connection =>
                    String.Equals(device.VendorId, NormalizeDeviceId(connection.VendorId), StringComparison.OrdinalIgnoreCase) &&
                    String.Equals(device.ProductId, NormalizeDeviceId(connection.ProductId), StringComparison.OrdinalIgnoreCase)));
            }
            return candidates.Where(model => !String.IsNullOrWhiteSpace(model.ImageUrl))
                .GroupBy(model => model.Name, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private DriveModel GetPreferredPhotoModel(string preferenceKey, List<DriveModel> variants, PnpKeyboard device, ModelProfile profile)
        {
            if (variants == null || variants.Count == 0) return null;
            string preferredName;
            if (_settings.PhotoVariantOverrides.TryGetValue(preferenceKey, out preferredName))
            {
                DriveModel saved = variants.FirstOrDefault(model => String.Equals(model.Name, preferredName, StringComparison.OrdinalIgnoreCase));
                if (saved != null) return saved;
            }
            if (profile != null)
            {
                string normalizedProfile = NormalizeModelName(profile.Name);
                DriveModel profileMatch = variants
                    .Where(model => normalizedProfile.Contains(NormalizeModelName(model.Name), StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(model => NormalizeModelName(model.Name).Length)
                    .FirstOrDefault();
                if (profileMatch != null) return profileMatch;

                string region = NormalizeModelName(profile.Region);
                if (!String.IsNullOrEmpty(region) && region != "ANSI")
                {
                    DriveModel regionMatch = variants.FirstOrDefault(model => NormalizeModelName(model.Name).EndsWith(region, StringComparison.OrdinalIgnoreCase));
                    if (regionMatch != null) return regionMatch;
                }
            }
            if (device != null)
            {
                List<DriveModel> exact = variants.Where(model => model.Connections.Any(connection =>
                    String.Equals(device.VendorId, NormalizeDeviceId(connection.VendorId), StringComparison.OrdinalIgnoreCase) &&
                    String.Equals(device.ProductId, NormalizeDeviceId(connection.ProductId), StringComparison.OrdinalIgnoreCase))).ToList();
                if (exact.Count == 1) return exact[0];
            }
            return variants.FirstOrDefault(model => profile != null && NormalizeModelName(model.Name).EndsWith(NormalizeModelName(profile.Family), StringComparison.OrdinalIgnoreCase))
                ?? variants.FirstOrDefault();
        }

        private static string PhotoPreferenceKey(PnpKeyboard device, ModelProfile profile)
        {
            if (device != null && profile != null && String.Equals(device.ProductId, NormalizeDeviceId(profile.Code), StringComparison.OrdinalIgnoreCase))
                return "device:" + device.Identity;
            if (profile != null) return "profile:" + profile.Code;
            return device != null ? "device:" + device.Identity : "profile:unknown";
        }

        private string DescribeDeviceModel(PnpKeyboard device, ModelProfile profile)
        {
            if (profile != null) return profile.Name;
            List<DriveModel> candidates = GetPhotoVariants(device, null);
            return candidates.Count == 1 ? candidates[0].Name : "RK device " + device.VendorId + ":" + device.ProductId;
        }

        private static string NormalizeDeviceId(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string normalized = value.Trim();
            if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) normalized = normalized.Substring(2);
            return normalized.ToUpperInvariant().PadLeft(4, '0');
        }

        private void RenderKeymap()
        {
            AddIntro("Local key-label draft", "Click a key to change its display label for this profile on this PC. The RK keycode tuple and hardware are not changed.");
            if (_selected.Keys.Count == 0)
            {
                _pageBody.Children.Add(CardWithText("No drawable key layout is recorded for this profile."));
                return;
            }
            Image officialImage = LoadProfileImage();
            BitmapSource plate = officialImage == null ? null : officialImage.Source as BitmapSource;
            if (plate != null)
            {
                double width = plate.PixelWidth;
                double height = plate.PixelHeight;
                double artMaxX = Math.Max(width, _selected.Keys.Max(k => k.X + k.W));
                double artMaxY = Math.Max(height, _selected.Keys.Max(k => k.Y + k.H));
                double scaleX = width / artMaxX;
                double scaleY = height / artMaxY;
                Canvas artCanvas = new Canvas { Width = width, Height = height, Background = Brushes.Transparent, Margin = new Thickness(10), ClipToBounds = true };
                artCanvas.Children.Add(new Image { Source = plate, Width = width, Height = height, Stretch = Stretch.Fill });
                foreach (LayoutKey key in _selected.Keys)
                {
                    string keyId = key.Id ?? "";
                    string draftKey = _selected.Code + ":" + keyId;
                    string label = _settings.KeyLabelDrafts.ContainsKey(draftKey) ? _settings.KeyLabelDrafts[draftKey] : key.Label;
                    Button hit = new Button {
                        Content = "", Tag = key, Width = Math.Max(8, key.W * scaleX), Height = Math.Max(8, key.H * scaleY),
                        Background = Brushes.Transparent, BorderBrush = Brushes.Transparent, BorderThickness = new Thickness(1),
                        Padding = new Thickness(0), Cursor = Cursors.Hand, ToolTip = keyId + " · " + label + " · click to edit label"
                    };
                    hit.MouseEnter += delegate { hit.Background = new SolidColorBrush(MediaColor.FromArgb(70, 255, 128, 0)); hit.BorderBrush = Brush(255, 128, 0); };
                    hit.MouseLeave += delegate { hit.Background = Brushes.Transparent; hit.BorderBrush = Brushes.Transparent; };
                    hit.Click += delegate(object sender, RoutedEventArgs e) { EditKeyLabel((LayoutKey)((Button)sender).Tag); };
                    Canvas.SetLeft(hit, key.X * scaleX);
                    Canvas.SetTop(hit, key.Y * scaleY);
                    artCanvas.Children.Add(hit);
                }
                Border authenticKeyboard = Card();
                authenticKeyboard.Padding = new Thickness(8);
                authenticKeyboard.HorizontalAlignment = HorizontalAlignment.Center;
                authenticKeyboard.Child = new ScrollViewer { Content = artCanvas, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
                _pageBody.Children.Add(authenticKeyboard);
                _pageBody.Children.Add(new TextBlock { Text = "Artwork and hit areas use the installed RK profile resources. Hover a key to locate it; key label changes remain local drafts.", Foreground = Brush(175, 175, 175), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(6, 10, 6, 0) });
                return;
            }
            double maxX = _selected.Keys.Max(k => k.X + k.W) + 12;
            double maxY = _selected.Keys.Max(k => k.Y + k.H) + 12;
            double scale = Math.Min(1.25, Math.Min(1030 / maxX, 440 / maxY));
            Canvas canvas = new Canvas { Width = maxX * scale, Height = maxY * scale, Background = Brush(20, 20, 20), Margin = new Thickness(10), ClipToBounds = true };
            foreach (LayoutKey key in _selected.Keys)
            {
                string keyId = key.Id ?? "";
                string draftKey = _selected.Code + ":" + keyId;
                string label = _settings.KeyLabelDrafts.ContainsKey(draftKey) ? _settings.KeyLabelDrafts[draftKey] : key.Label;
                Button tile = new Button { Content = label, Tag = key, FontSize = 9, Padding = new Thickness(2), Width = Math.Max(28, key.W * scale - 2), Height = Math.Max(26, key.H * scale - 2), Background = Brush(30, 30, 30), Foreground = Brush(220, 220, 220), BorderBrush = Brush(105, 105, 105), BorderThickness = new Thickness(1), ToolTip = keyId + " · source label: " + key.Label, Cursor = Cursors.Hand };
                tile.Click += delegate(object sender, RoutedEventArgs e) { EditKeyLabel((LayoutKey)((Button)sender).Tag); };
                Canvas.SetLeft(tile, key.X * scale);
                Canvas.SetTop(tile, key.Y * scale);
                canvas.Children.Add(tile);
            }
            Border shell = Card();
            shell.Child = new ScrollViewer { Content = canvas, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _pageBody.Children.Add(shell);
            _pageBody.Children.Add(new TextBlock { Text = "Key geometry and source labels come from the extracted profile catalog. The draft text is stored locally and has no vendor serialization.", Foreground = Brush(111, 120, 133), FontSize = 11, Margin = new Thickness(3, 12, 0, 0) });
        }

        private void EditKeyLabel(LayoutKey key)
        {
            string draftKey = _selected.Code + ":" + key.Id;
            string oldValue = _settings.KeyLabelDrafts.ContainsKey(draftKey) ? _settings.KeyLabelDrafts[draftKey] : key.Label;
            TextEntryWindow dialog = new TextEntryWindow(key.Id + " label draft", "Displayed label", oldValue, FontFamily);
            dialog.Owner = this;
            if (dialog.ShowDialog() == true)
            {
                _settings.KeyLabelDrafts[draftKey] = dialog.Value;
                SettingsStore.Save(_settings);
                RenderKeymap();
            }
        }

        private void RenderLighting()
        {
            AddIntro("Lighting profile data", "This page shows the option slots recorded in the selected software profile. Slot availability is evidence, not proof of names, hardware support, or a working write path.");
            RenderLightingDraft();
            Border summary = Card();
            StackPanel head = new StackPanel { Margin = new Thickness(20) };
            summary.Child = head;
            head.Children.Add(Kicker("PROFILE CAPABILITIES"));
            head.Children.Add(new TextBlock { Text = (_selected.Rgb ? "RGB flag set" : "RGB flag not set") + "  ·  " + _selected.LightingSlots.Count + " lighting slots", Foreground = Brush(50, 58, 70), FontSize = 15, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 0) });
            _pageBody.Children.Add(summary);
            WrapPanel slots = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            foreach (int slot in _selected.LightingSlots)
            {
                Border card = Card();
                card.Width = 205;
                card.Margin = new Thickness(0, 0, 12, 12);
                StackPanel body = new StackPanel { Margin = new Thickness(16) };
                card.Child = body;
                body.Children.Add(new TextBlock { Text = "SLOT " + slot.ToString("00"), Foreground = Brush(49, 94, 181), FontSize = 10, FontWeight = FontWeights.Bold });
                body.Children.Add(new TextBlock { Text = "Profile option", Foreground = Brush(52, 60, 72), FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 7, 0, 0) });
                body.Children.Add(new TextBlock { Text = "Controls unavailable", Foreground = Brush(130, 138, 150), FontSize = 10, Margin = new Thickness(0, 4, 0, 0) });
                slots.Children.Add(card);
            }
            _pageBody.Children.Add(slots);
            _pageBody.Children.Add(CardWithText("Only a local profile-bound draft can be saved here. Hardware lighting changes, effect transfer, and readback remain unavailable while model-specific call paths are validated."));
        }

        private void RenderMacros()
        {
            _pageBody.Children.Clear();
            RenderMacroTimelines();
            _pageBody.Children.Add(Headline("Legacy local notes (preserved separately)", 16));
            List<string> macros;
            if (!_settings.MacroDrafts.TryGetValue(_selected.Code, out macros))
            {
                macros = new List<string>();
                _settings.MacroDrafts[_selected.Code] = macros;
            }
            StackPanel row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            Button add = ActionButton("Add local macro note", true);
            add.Click += delegate { AddMacro(); };
            row.Children.Add(add);
            _pageBody.Children.Add(row);
            if (macros.Count == 0)
            {
                _pageBody.Children.Add(CardWithText("No local macro notes for " + _selected.Name + "."));
                return;
            }
            for (int i = 0; i < macros.Count; i++)
            {
                int index = i;
                Border item = Card();
                Grid inner = new Grid { Margin = new Thickness(17) };
                inner.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                inner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                item.Child = inner;
                inner.Children.Add(new TextBlock { Text = macros[i], Foreground = Brush(220, 220, 220), FontSize = 12, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });
                Button remove = ActionButton("Remove", false);
                Grid.SetColumn(remove, 1);
                remove.Click += delegate { macros.RemoveAt(index); SettingsStore.Save(_settings); RenderMacros(); };
                inner.Children.Add(remove);
                item.Margin = new Thickness(0, 0, 0, 9);
                _pageBody.Children.Add(item);
            }
        }

        private void AddMacro()
        {
            TextEntryWindow dialog = new TextEntryWindow("New local macro note", "Name or note", "", FontFamily);
            dialog.Owner = this;
            if (dialog.ShowDialog() == true)
            {
                List<string> macros;
                if (!_settings.MacroDrafts.TryGetValue(_selected.Code, out macros)) _settings.MacroDrafts[_selected.Code] = macros = new List<string>();
                macros.Add(dialog.Value);
                SettingsStore.Save(_settings);
                RenderMacros();
            }
        }

        private void RenderModels()
        {
            AddIntro("Software profile catalog", "The catalog contains 265 entries from one RK Windows package snapshot. These are software profiles, not a census of every product or physical revision.");
            TextBox search = new TextBox { Height = 36, Padding = new Thickness(10, 7, 10, 6), FontSize = 12, BorderBrush = Brush(80, 80, 80), Background = Brush(20, 20, 20), Foreground = Brush(220, 220, 220), Margin = new Thickness(0, 0, 0, 12), ToolTip = "Search model name, family, region, or code" };
            _pageBody.Children.Add(search);
            StackPanel results = new StackPanel();
            _pageBody.Children.Add(results);
            Action redraw = delegate
            {
                results.Children.Clear();
                string query = search.Text.Trim();
                foreach (ModelProfile model in _catalog.Models.Where(m => String.IsNullOrEmpty(query) || (m.Name + " " + m.Code + " " + m.Family + " " + m.Region).IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0).OrderBy(m => m.Name).ThenBy(m => m.Code))
                {
                    Border row = Card();
                    row.Margin = new Thickness(0, 0, 0, 7);
                    Grid content = new Grid { Margin = new Thickness(15, 11, 15, 11) };
                    content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    content.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                    row.Child = content;
                    StackPanel left = new StackPanel();
                    left.Children.Add(new TextBlock { Text = model.Name, Foreground = Brush(48, 56, 68), FontSize = 13, FontWeight = FontWeights.SemiBold });
                    left.Children.Add(new TextBlock { Text = model.Code + "  ·  family " + Blank(model.Family) + "  ·  " + model.KeyCount + " keys  ·  " + Blank(model.Region), Foreground = Brush(120, 128, 140), FontSize = 10, Margin = new Thickness(0, 3, 0, 0) });
                    content.Children.Add(left);
                    Button choose = ActionButton(model.Code == _selected.Code ? "Selected" : "Use profile", model.Code != _selected.Code);
                    Grid.SetColumn(choose, 1);
                    choose.Click += delegate { SelectProfile(model, true); SetPage("Device"); };
                    content.Children.Add(choose);
                    results.Children.Add(row);
                }
            };
            search.TextChanged += delegate { redraw(); };
            redraw();
        }

        private void RenderDriveDirectory()
        {
            AddIntro("Public RK Drive keyboard directory", "This separate directory comes from the official browser app's public model registry. It lists connection descriptors and declared capabilities; it does not identify a connected keyboard or enable configuration writes.");
            Border countCard = Card();
            StackPanel countBody = new StackPanel { Margin = new Thickness(17, 13, 17, 13) };
            countCard.Child = countBody;
            countBody.Children.Add(new TextBlock {
                Text = _driveDirectory.DescriptorCount + " connection descriptors  ·  " + _driveDirectory.LabelCount + " standard labels  ·  " + _driveDirectory.Models.Count + " labels including specialized profiles",
                Foreground = Brush(54, 62, 74), FontSize = 12, FontWeight = FontWeights.SemiBold
            });
            countBody.Children.Add(new TextBlock {
                Text = "Bundle snapshot: " + Blank(_driveDirectory.RetrievedAt) + "  ·  source SHA-256 " + _driveDirectory.BundleHash,
                Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(0, 5, 0, 0), TextWrapping = TextWrapping.Wrap
            });
            _pageBody.Children.Add(countCard);

            Grid directoryGrid = new Grid { Margin = new Thickness(0, 13, 0, 0) };
            directoryGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.95, GridUnitType.Star) });
            directoryGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            directoryGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.05, GridUnitType.Star) });
            _pageBody.Children.Add(directoryGrid);

            Border listCard = Card();
            Grid.SetColumn(listCard, 0);
            directoryGrid.Children.Add(listCard);
            DockPanel listPanel = new DockPanel { Margin = new Thickness(14) };
            listCard.Child = listPanel;
            StackPanel controls = new StackPanel();
            DockPanel.SetDock(controls, Dock.Top);
            listPanel.Children.Add(controls);
            TextBox search = new TextBox { Height = 35, Padding = new Thickness(9, 6, 9, 5), FontSize = 12, BorderBrush = Brush(80, 80, 80), Background = Brush(20, 20, 20), Foreground = Brush(220, 220, 220), ToolTip = "Search model, protocol, or connection ID" };
            controls.Children.Add(search);
            ComboBox connectionFilter = new ComboBox { Height = 32, Margin = new Thickness(0, 8, 0, 8), Padding = new Thickness(6, 4, 6, 4), FontSize = 11 };
            connectionFilter.Items.Add("All connections");
            connectionFilter.Items.Add("USB");
            connectionFilter.Items.Add("2.4 GHz receiver");
            connectionFilter.SelectedIndex = 0;
            controls.Children.Add(connectionFilter);
            TextBlock resultCount = new TextBlock { Foreground = Brush(111, 120, 133), FontSize = 10, Margin = new Thickness(1, 0, 0, 8) };
            controls.Children.Add(resultCount);
            StackPanel results = new StackPanel();
            listPanel.Children.Add(new ScrollViewer { Content = results, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, MinHeight = 410 });

            Border detailsCard = Card();
            Grid.SetColumn(detailsCard, 2);
            directoryGrid.Children.Add(detailsCard);
            StackPanel details = new StackPanel { Margin = new Thickness(18) };
            detailsCard.Child = new ScrollViewer { Content = details, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };

            Action redraw = delegate
            {
                results.Children.Clear();
                string query = search.Text.Trim();
                string connection = connectionFilter.SelectedItem == null ? "All connections" : connectionFilter.SelectedItem.ToString();
                List<DriveModel> filtered = _driveDirectory.Models
                    .Where(model => model.Connections.Any(row => connection == "All connections" || row.Connection.IndexOf(connection, StringComparison.OrdinalIgnoreCase) >= 0))
                    .Where(model => String.IsNullOrEmpty(query) || (model.Name + " " + String.Join(" ", model.Connections.Select(row => row.Protocol + " " + row.VendorId + " " + row.ProductId + " " + row.UsagePage + " " + row.Usage + " " + row.Connection))).IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                    .OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                resultCount.Text = filtered.Count + " model labels";
                foreach (DriveModel model in filtered)
                {
                    Button item = new Button {
                        Tag = model,
                        Content = new StackPanel {
                            Children = {
                                new TextBlock { Text = model.Name, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Brush(48, 56, 68) },
                                new TextBlock { Text = model.Connections.Count + " descriptor(s)  ·  " + String.Join(", ", model.Connections.Select(row => row.Connection).Distinct()), FontSize = 9, Foreground = Brush(120, 128, 140), Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap }
                            }
                        },
                        HorizontalContentAlignment = HorizontalAlignment.Left,
                        Padding = new Thickness(10, 8, 10, 8),
                        Margin = new Thickness(0, 0, 0, 6),
                        Background = model == _selectedDriveModel ? Brush(60, 31, 15) : Brush(20, 20, 20),
                        BorderBrush = Brush(225, 229, 235),
                        BorderThickness = new Thickness(1),
                        Cursor = Cursors.Hand
                    };
                    item.Click += delegate { _selectedDriveModel = model; RenderDriveDetails(details, model); UpdateDirectorySelection(results); };
                    results.Children.Add(item);
                }
                if (filtered.Count == 0)
                {
                    results.Children.Add(CardWithText("No catalog rows match that search."));
                    RenderDriveDetails(details, null);
                }
                else if (_selectedDriveModel == null || !filtered.Contains(_selectedDriveModel))
                {
                    _selectedDriveModel = filtered[0];
                    RenderDriveDetails(details, _selectedDriveModel);
                }
                else
                {
                    UpdateDirectorySelection(results);
                }
            };
            search.TextChanged += delegate { redraw(); };
            connectionFilter.SelectionChanged += delegate { redraw(); };
            redraw();

            Border note = Card();
            note.Margin = new Thickness(0, 12, 0, 0);
            StackPanel noteBody = new StackPanel { Margin = new Thickness(17, 13, 17, 13) };
            note.Child = noteBody;
            noteBody.Children.Add(new TextBlock { Text = "Feature inventory from the same site", FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Brush(54, 62, 74) });
            noteBody.Children.Add(new TextBlock { Text = "The public app bundle also contains mapping, lighting, macro, TFT/media, performance, advanced-key, device settings, and mouse pages. This native release uses the model-specific layer/table/effect declarations shown above; it does not yet reproduce those complete workflows or transfer settings to a keyboard.", FontSize = 10, Foreground = Brush(111, 120, 133), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });
            _pageBody.Children.Add(note);
        }

        private void RenderDriveEditor()
        {
            AddIntro("RK Drive local configuration drafts", "This page uses the public site’s model, connection, layer, table, and lighting declarations to prepare settings on this PC. Saving changes this app’s local draft only; it does not open HID or send anything to a keyboard.");
            if (_driveDirectory.Models.Count == 0)
            {
                _pageBody.Children.Add(CardWithText("The RK Drive model registry is empty."));
                return;
            }

            StackPanel selectors = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            ComboBox modelSelector = new ComboBox {
                Width = 300, Height = 34, Padding = new Thickness(8, 4, 8, 4),
                Background = Brush(20, 20, 20), BorderBrush = Brush(80, 80, 80),
                ItemsSource = _driveDirectory.Models.OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase).ToList(),
                DisplayMemberPath = "Name"
            };
            ComboBox connectionSelector = new ComboBox {
                Width = 430, Height = 34, Margin = new Thickness(10, 0, 0, 0), Padding = new Thickness(8, 4, 8, 4),
                Background = Brush(20, 20, 20), BorderBrush = Brush(80, 80, 80)
            };
            selectors.Children.Add(modelSelector);
            selectors.Children.Add(connectionSelector);
            _pageBody.Children.Add(selectors);

            StackPanel draftFiles = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            Button exportDraft = ActionButton("Export saved draft", false);
            Button importDraft = ActionButton("Import draft", false);
            TextBlock draftFileStatus = new TextBlock { Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
            exportDraft.ToolTip = "Export this model and connection's saved local draft as a portable JSON file.";
            importDraft.ToolTip = "Validate and import a portable local draft for this exact model and connection descriptor.";
            draftFiles.Children.Add(exportDraft);
            importDraft.Margin = new Thickness(8, 0, 0, 0);
            draftFiles.Children.Add(importDraft);
            draftFiles.Children.Add(draftFileStatus);
            _pageBody.Children.Add(draftFiles);
            StackPanel editor = new StackPanel();
            _pageBody.Children.Add(editor);

            Action redraw = delegate
            {
                editor.Children.Clear();
                DriveModel model = modelSelector.SelectedItem as DriveModel;
                DriveConnection connection = connectionSelector.SelectedItem as DriveConnection;
                exportDraft.IsEnabled = model != null && connection != null;
                importDraft.IsEnabled = model != null && connection != null;
                if (model == null || connection == null)
                {
                    editor.Children.Add(CardWithText("Choose a model and a connection descriptor."));
                    return;
                }

                string draftKey = GetDriveDraftKey(model, connection);
                DriveDraft saved;
                if (!_settings.DriveDrafts.TryGetValue(draftKey, out saved) || saved == null) saved = new DriveDraft();
                DriveDraft working = new DriveDraft {
                    Layer = saved.Layer, Table = saved.Table, Effect = saved.Effect,
                    Brightness = saved.Brightness, Speed = saved.Speed, Color = saved.Color, MixColor = saved.MixColor,
                    LayoutGroup = saved.LayoutGroup,
                    KeyMappings = saved.KeyMappings == null
                        ? new Dictionary<string, string>()
                        : new Dictionary<string, string>(saved.KeyMappings, StringComparer.Ordinal)
                };

                Border identity = Card();
                StackPanel identityBody = new StackPanel { Margin = new Thickness(17) };
                identity.Child = identityBody;
                identityBody.Children.Add(Kicker("SELECTED PUBLIC DESCRIPTOR"));
                identityBody.Children.Add(Headline(model.Name, 19));
                identityBody.Children.Add(Paragraph(connection.ToString() + "  ·  usage " + Blank(connection.UsagePage) + ":" + Blank(connection.Usage), 10));
                identityBody.Children.Add(new TextBlock {
                    Text = "This registry match is a candidate description, not proof that the connected device is this model or revision.",
                    Foreground = Brush(133, 90, 28), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0)
                });
                if (connection.Specialized)
                {
                    identityBody.Children.Add(new TextBlock {
                        Text = "Specialized profile metadata: UUID " + Blank(connection.Uuid) + "  ·  minimum firmware " + Blank(connection.FirmwareMinimum) + "  ·  side light " + (connection.HasSideLight == true ? "declared" : "not declared"),
                        Foreground = Brush(70, 78, 90), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0)
                    });
                }
                editor.Children.Add(identity);

                if (connection.HasDeclaredConfiguratorData)
                {
                    Border keyCard = Card();
                    keyCard.Margin = new Thickness(0, 12, 0, 0);
                    StackPanel keyBody = new StackPanel { Margin = new Thickness(17) };
                    keyCard.Child = keyBody;
                    keyBody.Children.Add(Kicker("KEYMAP DECLARATIONS"));
                    keyBody.Children.Add(Paragraph(connection.LayoutGroupCount + " layout group(s) declared with ordered key slots", 11));
                    ComboBox layoutGroupSelector = new ComboBox {
                        Width = 290, Height = 30, Padding = new Thickness(7, 3, 7, 3),
                        Background = Brush(20, 20, 20), BorderBrush = Brush(80, 80, 80), Foreground = Brush(220, 220, 220),
                        IsEnabled = connection.LayoutGroups.Count > 0
                    };
                    foreach (DriveLayoutGroup group in connection.LayoutGroups) layoutGroupSelector.Items.Add(group);
                    DriveLayoutGroup savedGroup = connection.LayoutGroups.FirstOrDefault(group => group.GroupIndex == working.LayoutGroup);
                    if (savedGroup != null) layoutGroupSelector.SelectedItem = savedGroup;
                    else if (layoutGroupSelector.Items.Count > 0) layoutGroupSelector.SelectedIndex = 0;
                    ComboBox layerSelector = DraftCombo("Key layer", connection.Layers, working.Layer);
                    ComboBox tableSelector = DraftCombo("OS table", connection.Tables, working.Table);
                    AddLabeledControl(keyBody, "Layout", layoutGroupSelector);
                    AddLabeledControl(keyBody, "Layer", layerSelector);
                    AddLabeledControl(keyBody, "OS table", tableSelector);
                    if (connection.Tables.Count == 0)
                    {
                        keyBody.Children.Add(new TextBlock {
                            Text = "No OS table is declared for this connection. Key drafts use an explicit no-table context.",
                            Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(130, 5, 0, 0)
                        });
                    }
                    keyBody.Children.Add(new TextBlock {
                        Text = "Slot order and symbolic labels come from the public RK Drive bundle. Physical x/y geometry is not declared here. These are local remap drafts only; no device apply path is implemented.",
                        Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0)
                    });
                    TextBlock keymapCount = new TextBlock {
                        Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(0, 9, 0, 2)
                    };
                    keyBody.Children.Add(keymapCount);
                    StackPanel slotRows = new StackPanel();
                    ScrollViewer slotScroller = new ScrollViewer {
                        Content = slotRows, MaxHeight = 310, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                        BorderBrush = Brush(230, 233, 238), BorderThickness = new Thickness(1), Padding = new Thickness(5)
                    };
                    keyBody.Children.Add(slotScroller);
                    List<KeyValuePair<string, ComboBox>> slotSelectors = new List<KeyValuePair<string, ComboBox>>();
                    Func<DriveLayerLayout> selectedLayerLayout = delegate
                    {
                        DriveLayoutGroup selectedGroup = layoutGroupSelector.SelectedItem as DriveLayoutGroup;
                        string selectedLayerName = layerSelector.SelectedItem as string;
                        if (selectedGroup == null) return null;
                        int layerPosition = connection.Layers.IndexOf(selectedLayerName ?? "");
                        int layerIndex = layerPosition >= 0 && layerPosition < connection.LayerIds.Count
                            ? connection.LayerIds[layerPosition]
                            : layerPosition;
                        return selectedGroup.Layers.FirstOrDefault(layer => layer.LayerIndex == layerIndex)
                            ?? selectedGroup.Layers.FirstOrDefault(layer => String.Equals(layer.LayerName, selectedLayerName, StringComparison.OrdinalIgnoreCase));
                    };
                    Action renderSlotRows = delegate
                    {
                        slotRows.Children.Clear();
                        slotSelectors.Clear();
                        DriveLayoutGroup selectedGroup = layoutGroupSelector.SelectedItem as DriveLayoutGroup;
                        DriveLayerLayout selectedLayout = selectedLayerLayout();
                        if (selectedGroup == null || selectedLayout == null || selectedLayout.KeySlots.Count == 0)
                        {
                            keymapCount.Text = "No ordered slot data is declared for this group and layer.";
                            return;
                        }
                        int tableIndex = connection.Tables.IndexOf(tableSelector.SelectedItem as string);
                        string tableToken = connection.Tables.Count == 0 ? "tNone" : "t" + Math.Max(0, tableIndex);
                        string contextPrefix = "g" + selectedGroup.GroupIndex + "|l" + selectedLayout.LayerIndex + "|" + tableToken + "|s";
                        List<DriveKeyChoice> choices = new List<DriveKeyChoice> {
                            new DriveKeyChoice { IsNoOverride = true, Display = "No override" }
                        };
                        foreach (DriveKeySlot candidate in selectedGroup.Layers.SelectMany(layer => layer.KeySlots))
                        {
                            if (!candidate.KeyCode.HasValue || choices.Any(choice => choice.KeyCode == candidate.KeyCode)) continue;
                            string candidateLabel = String.IsNullOrWhiteSpace(candidate.Label) ? candidate.KeySymbol : candidate.Label;
                            choices.Add(new DriveKeyChoice {
                                KeyCode = candidate.KeyCode,
                                Label = candidateLabel,
                                Symbol = candidate.EnumSymbol + "." + candidate.KeySymbol,
                                Display = candidateLabel + "  ·  0x" + candidate.KeyCode.Value.ToString("X2")
                            });
                        }
                        foreach (DriveKeySlot slot in selectedLayout.KeySlots)
                        {
                            Grid row = new Grid { Margin = new Thickness(0, 1, 0, 1), MinHeight = 29 };
                            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(190) });
                            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                            string slotLabelText = String.IsNullOrWhiteSpace(slot.Label) ? slot.KeySymbol : slot.Label;
                            TextBlock slotLabel = new TextBlock {
                                Text = "Slot " + slot.SlotIndex.ToString("D2") + "  ·  " + slotLabelText,
                                Foreground = Brush(70, 78, 90), FontSize = 9, VerticalAlignment = VerticalAlignment.Center,
                                TextTrimming = TextTrimming.CharacterEllipsis,
                                ToolTip = slot.EnumSymbol + "." + slot.KeySymbol + (slot.KeyCode.HasValue ? "  ·  code " + slot.KeyCode.Value : "  ·  no numeric code resolved")
                            };
                            ComboBox choiceSelector = new ComboBox {
                                Height = 26, Padding = new Thickness(5, 2, 5, 2),
                                Background = Brush(20, 20, 20), BorderBrush = Brush(80, 80, 80), Foreground = Brush(220, 220, 220), ItemsSource = choices
                            };
                            string mappingKey = contextPrefix + slot.SlotIndex;
                            string savedCode;
                            if (working.KeyMappings.TryGetValue(mappingKey, out savedCode))
                                choiceSelector.SelectedItem = choices.FirstOrDefault(choice => choice.KeyCode.HasValue
                                    && String.Equals(choice.KeyCode.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), savedCode, StringComparison.Ordinal));
                            if (choiceSelector.SelectedItem == null) choiceSelector.SelectedIndex = 0;
                            Grid.SetColumn(choiceSelector, 1);
                            row.Children.Add(slotLabel);
                            row.Children.Add(choiceSelector);
                            slotRows.Children.Add(row);
                            slotSelectors.Add(new KeyValuePair<string, ComboBox>(mappingKey, choiceSelector));
                        }
                        keymapCount.Text = selectedLayout.KeySlots.Count + " ordered slots · " + choices.Count + " choices (including no override) · layout " + selectedLayout.LayoutId.Substring(0, Math.Min(8, selectedLayout.LayoutId.Length));
                    };
                    layoutGroupSelector.SelectionChanged += delegate { renderSlotRows(); };
                    layerSelector.SelectionChanged += delegate { renderSlotRows(); };
                    tableSelector.SelectionChanged += delegate { renderSlotRows(); };
                    renderSlotRows();
                    Button saveKeymap = ActionButton("Save keymap draft", true);
                    saveKeymap.Margin = new Thickness(0, 9, 0, 0);
                    TextBlock keymapStatus = new TextBlock { Foreground = Brush(64, 120, 82), FontSize = 9, Margin = new Thickness(9, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                    StackPanel keymapSaveRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 7, 0, 0) };
                    saveKeymap.Click += delegate
                    {
                        DriveLayoutGroup selectedGroup = layoutGroupSelector.SelectedItem as DriveLayoutGroup;
                        working.LayoutGroup = selectedGroup == null ? 0 : selectedGroup.GroupIndex;
                        working.Layer = layerSelector.SelectedItem as string ?? "";
                        working.Table = tableSelector.SelectedItem as string ?? "";
                        foreach (KeyValuePair<string, ComboBox> slotSelector in slotSelectors)
                        {
                            DriveKeyChoice selectedChoice = slotSelector.Value.SelectedItem as DriveKeyChoice;
                            if (selectedChoice == null || selectedChoice.IsNoOverride || !selectedChoice.KeyCode.HasValue)
                                working.KeyMappings.Remove(slotSelector.Key);
                            else
                                working.KeyMappings[slotSelector.Key] = selectedChoice.KeyCode.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        }
                        _settings.DriveDrafts[draftKey] = working;
                        SettingsStore.Save(_settings);
                        keymapStatus.Text = "Saved to this PC only.";
                    };
                    keymapSaveRow.Children.Add(saveKeymap);
                    keymapSaveRow.Children.Add(keymapStatus);
                    keyBody.Children.Add(keymapSaveRow);
                    editor.Children.Add(keyCard);

                    Border lightingCard = Card();
                    lightingCard.Margin = new Thickness(0, 12, 0, 0);
                    StackPanel lightingBody = new StackPanel { Margin = new Thickness(17) };
                    lightingCard.Child = lightingBody;
                    lightingBody.Children.Add(Kicker("LIGHTING DRAFT"));
                    if (connection.Effects.Count == 0)
                    {
                        lightingBody.Children.Add(Paragraph("No lighting effects are declared for this registry row.", 10));
                    }
                    else
                    {
                        ComboBox effectSelector = DraftCombo("Effect", connection.Effects.Select(effect => effect.Name).ToList(), working.Effect);
                        AddLabeledControl(lightingBody, "Declared effect", effectSelector);
                        Slider brightness = new Slider { Minimum = 0, Maximum = 100, Value = Math.Max(0, Math.Min(100, working.Brightness)), Width = 220, IsEnabled = false };
                        TextBox color = new TextBox { Width = 100, Height = 28, Padding = new Thickness(6, 4, 6, 3), Text = String.IsNullOrWhiteSpace(working.Color) ? "#FFFFFF" : working.Color, IsEnabled = false };
                        Slider speed = new Slider { Minimum = 0, Maximum = 100, Value = Math.Max(0, Math.Min(100, working.Speed)), Width = 220, IsEnabled = false };
                        CheckBox mixColor = new CheckBox { Content = "Mix colors", IsChecked = working.MixColor, IsEnabled = false, VerticalAlignment = VerticalAlignment.Center };
                        TextBlock brightnessValue = new TextBlock { Width = 38, Foreground = Brush(111, 120, 133), VerticalAlignment = VerticalAlignment.Center };
                        TextBlock speedValue = new TextBlock { Width = 38, Foreground = Brush(111, 120, 133), VerticalAlignment = VerticalAlignment.Center };
                        brightness.ValueChanged += delegate { brightnessValue.Text = ((int)brightness.Value).ToString(); };
                        speed.ValueChanged += delegate { speedValue.Text = ((int)speed.Value).ToString(); };
                        brightnessValue.Text = ((int)brightness.Value).ToString();
                        speedValue.Text = ((int)speed.Value).ToString();
                        AddLabeledControl(lightingBody, "Brightness", PairControl(brightness, brightnessValue));
                        AddLabeledControl(lightingBody, "Speed", PairControl(speed, speedValue));
                        AddLabeledControl(lightingBody, "Color", color);
                        AddLabeledControl(lightingBody, "Color blend", mixColor);
                        Action updateControls = delegate
                        {
                            DriveEffect effect = connection.Effects.FirstOrDefault(item => String.Equals(item.Name, effectSelector.SelectedItem as string, StringComparison.OrdinalIgnoreCase));
                            brightness.IsEnabled = effect != null && effect.Brightness;
                            speed.IsEnabled = effect != null && effect.Speed;
                            color.IsEnabled = effect != null && effect.ColorValueDefined;
                            mixColor.IsEnabled = effect != null && effect.MixColor;
                        };
                        effectSelector.SelectionChanged += delegate { updateControls(); };
                        updateControls();

                        Button save = ActionButton("Save local draft", true);
                        save.Margin = new Thickness(0, 10, 0, 0);
                        TextBlock saveStatus = new TextBlock { Foreground = Brush(64, 120, 82), FontSize = 9, Margin = new Thickness(9, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                        StackPanel saveRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
                        save.Click += delegate
                        {
                            working.Layer = layerSelector.SelectedItem as string ?? "";
                            working.Table = tableSelector.SelectedItem as string ?? "";
                            working.Effect = effectSelector.SelectedItem as string ?? "";
                            working.Brightness = (int)brightness.Value;
                            working.Speed = (int)speed.Value;
                            working.Color = color.Text.Trim();
                            working.MixColor = mixColor.IsChecked == true;
                            _settings.DriveDrafts[draftKey] = working;
                            SettingsStore.Save(_settings);
                            saveStatus.Text = "Saved to this PC only.";
                        };
                        saveRow.Children.Add(save);
                        saveRow.Children.Add(saveStatus);
                        lightingBody.Children.Add(saveRow);
                        lightingBody.Children.Add(new TextBlock {
                            Text = "Only controls declared for the selected effect are enabled. Values remain local draft data; names and flags do not establish firmware support or a compatible packet.",
                            Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0)
                        });
                    }
                    editor.Children.Add(lightingCard);
                }
                else
                {
                    editor.Children.Add(CardWithText("This registry row has no general key-layer, OS-table, or effect declaration. The specialized profile data stays separate and is not inferred from another model."));
                }

                Border otherFeatures = Card();
                otherFeatures.Margin = new Thickness(0, 12, 0, 0);
                StackPanel featureBody = new StackPanel { Margin = new Thickness(17) };
                otherFeatures.Child = featureBody;
                featureBody.Children.Add(Kicker("OTHER RK DRIVE WORKFLOWS"));
                featureBody.Children.Add(FeatureLine("Macros", "The native app has a local macro-note page; macro capture, event editing, profile serialization, and device transfer are not implemented."));
                featureBody.Children.Add(FeatureLine("TFT and media", "The public bundle has a screen/media workflow. Per-model gates and the full handler path are still under audit."));
                featureBody.Children.Add(FeatureLine("Performance and advanced keys", connection.Specialized
                    ? "RK68 HE has a separate magnetic-switch workflow in the public app. The per-control gates and transfer path are only partly mapped."
                    : "The bundle includes performance, DKS, snap, SOCD, toggle, and mod-tap surfaces. Support is not declared for this selected row."));
                featureBody.Children.Add(FeatureLine("Device settings and firmware", "Information and update pages exist in the web app. This reconstruction does not open a device or expose update/boot actions."));
                Button macros = ActionButton("Open local macro notes", false);
                macros.Margin = new Thickness(0, 8, 0, 0);
                macros.Click += delegate { SetPage("Macros"); };
                featureBody.Children.Add(macros);
                editor.Children.Add(otherFeatures);
            };

            exportDraft.Click += delegate
            {
                DriveModel model = modelSelector.SelectedItem as DriveModel;
                DriveConnection connection = connectionSelector.SelectedItem as DriveConnection;
                if (model == null || connection == null) return;
                string draftKey = GetDriveDraftKey(model, connection);
                DriveDraft saved;
                if (!_settings.DriveDrafts.TryGetValue(draftKey, out saved) || saved == null) saved = new DriveDraft();
                string validationError;
                if (!ValidateDriveDraft(saved, connection, out validationError))
                {
                    MessageBox.Show("The saved draft cannot be exported: " + validationError, "RK Drive draft", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                SaveFileDialog dialog = new SaveFileDialog {
                    Title = "Export RK Drive local draft",
                    Filter = "RK Drive local draft (*.rkdrive.json)|*.rkdrive.json|JSON file (*.json)|*.json",
                    DefaultExt = ".rkdrive.json",
                    AddExtension = true,
                    FileName = SafeFileSegment(model.Name) + "-" + SafeFileSegment(connection.Connection) + "-draft.rkdrive.json"
                };
                if (dialog.ShowDialog(this) != true) return;
                DriveDraftPackage package = CreateDriveDraftPackage(model, connection, saved);
                try
                {
                    File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(package, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
                    draftFileStatus.Text = "Exported local draft JSON. It is not an RK device profile or firmware file.";
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Could not export the draft.\n\n" + ex.Message, "RK Drive draft", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            importDraft.Click += delegate
            {
                DriveModel model = modelSelector.SelectedItem as DriveModel;
                DriveConnection connection = connectionSelector.SelectedItem as DriveConnection;
                if (model == null || connection == null) return;
                OpenFileDialog dialog = new OpenFileDialog {
                    Title = "Import RK Drive local draft",
                    Filter = "RK Drive local draft (*.rkdrive.json)|*.rkdrive.json|JSON file (*.json)|*.json",
                    CheckFileExists = true,
                    Multiselect = false
                };
                if (dialog.ShowDialog(this) != true) return;
                try
                {
                    FileInfo info = new FileInfo(dialog.FileName);
                    if (info.Length > 1024 * 1024) throw new InvalidDataException("Draft files must be 1 MB or smaller.");
                    string json = File.ReadAllText(dialog.FileName, Encoding.UTF8);
                    using (JsonDocument document = JsonDocument.Parse(json))
                    {
                        JsonElement schemaVersion;
                        int version;
                        if (document.RootElement.ValueKind != JsonValueKind.Object
                            || !document.RootElement.TryGetProperty("SchemaVersion", out schemaVersion)
                            || schemaVersion.ValueKind != JsonValueKind.Number
                            || !schemaVersion.TryGetInt32(out version)
                            || (version != 1 && version != 2))
                            throw new InvalidDataException("The file must declare supported schema version 1 or 2.");
                    }
                    DriveDraftPackage package = JsonSerializer.Deserialize<DriveDraftPackage>(json);
                    if (package == null || !System.Text.RegularExpressions.Regex.IsMatch(package.SourceBundleSha256 ?? "", "^[0-9A-Fa-f]{64}$"))
                        throw new InvalidDataException("The source catalog SHA-256 field is missing or invalid.");
                    string identityError;
                    if (!MatchesDriveDescriptor(package, model, connection, out identityError))
                    {
                        MessageBox.Show("This file does not target the selected descriptor. " + identityError, "RK Drive draft", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    string validationError;
                    if (!ValidateDriveDraft(package.Draft, connection, out validationError))
                    {
                        MessageBox.Show("This draft contains a value not declared for the selected descriptor: " + validationError, "RK Drive draft", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    if (!String.Equals(package.SourceBundleSha256, _driveDirectory.BundleHash, StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBoxResult stale = MessageBox.Show(
                            "The draft was exported against a different RK Drive catalog bundle. Its descriptor identity and declared values match this local catalog, but the source catalog changed. Import it anyway?",
                            "RK Drive catalog version differs", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                        if (stale != MessageBoxResult.Yes) return;
                    }
                    _settings.DriveDrafts[GetDriveDraftKey(model, connection)] = CopyDriveDraft(package.Draft);
                    SettingsStore.Save(_settings);
                    draftFileStatus.Text = "Imported into this PC's local draft settings only.";
                    redraw();
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Could not import the draft. The local settings were not changed.\n\n" + ex.Message, "RK Drive draft", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            };

            modelSelector.SelectionChanged += delegate
            {
                _selectedDriveModel = modelSelector.SelectedItem as DriveModel;
                DriveModel selected = _selectedDriveModel;
                connectionSelector.ItemsSource = selected == null ? null : selected.Connections;
                connectionSelector.SelectedIndex = selected == null || selected.Connections.Count == 0 ? -1 : 0;
                redraw();
            };
            connectionSelector.SelectionChanged += delegate { redraw(); };
            modelSelector.SelectedItem = _selectedDriveModel != null && _driveDirectory.Models.Contains(_selectedDriveModel)
                ? _selectedDriveModel
                : _driveDirectory.Models.OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase).First();
            if (modelSelector.SelectedItem == null) modelSelector.SelectedIndex = 0;
        }

        private DriveDraftPackage CreateDriveDraftPackage(DriveModel model, DriveConnection connection, DriveDraft draft)
        {
            return new DriveDraftPackage {
                SchemaVersion = 2,
                SourceBundleSha256 = _driveDirectory.BundleHash ?? "",
                Model = model.Name ?? "",
                Connection = connection.Connection ?? "",
                VendorId = connection.VendorId ?? "",
                ProductId = connection.ProductId ?? "",
                UsagePage = connection.UsagePage ?? "",
                Usage = connection.Usage ?? "",
                Protocol = connection.Protocol ?? "",
                Specialized = connection.Specialized,
                Uuid = connection.Uuid ?? "",
                Draft = CopyDriveDraft(draft)
            };
        }

        private static string GetDriveDraftKey(DriveModel model, DriveConnection connection)
        {
            return String.Join("|", model.Name, connection.Connection, connection.VendorId, connection.ProductId, connection.UsagePage, connection.Usage);
        }

        private static DriveDraft CopyDriveDraft(DriveDraft source)
        {
            if (source == null) return null;
            return new DriveDraft {
                Layer = source.Layer ?? "",
                Table = source.Table ?? "",
                Effect = source.Effect ?? "",
                Brightness = source.Brightness,
                Speed = source.Speed,
                Color = source.Color ?? "",
                MixColor = source.MixColor,
                LayoutGroup = source.LayoutGroup,
                KeyMappings = source.KeyMappings == null
                    ? new Dictionary<string, string>()
                    : new Dictionary<string, string>(source.KeyMappings, StringComparer.Ordinal)
            };
        }

        private static bool MatchesDriveDescriptor(DriveDraftPackage package, DriveModel model, DriveConnection connection, out string error)
        {
            error = "The model label, connection, VID/PID, usage, protocol, specialized-profile flag, and UUID must match.";
            return package != null && (package.SchemaVersion == 1 || package.SchemaVersion == 2) && package.Draft != null
                && String.Equals(package.Model ?? "", model.Name ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.Connection ?? "", connection.Connection ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.VendorId ?? "", connection.VendorId ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.ProductId ?? "", connection.ProductId ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.UsagePage ?? "", connection.UsagePage ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.Usage ?? "", connection.Usage ?? "", StringComparison.OrdinalIgnoreCase)
                && String.Equals(package.Protocol ?? "", connection.Protocol ?? "", StringComparison.OrdinalIgnoreCase)
                && package.Specialized == connection.Specialized
                && String.Equals(package.Uuid ?? "", connection.Uuid ?? "", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ValidateDriveDraft(DriveDraft draft, DriveConnection connection, out string error)
        {
            error = "";
            if (draft == null) { error = "the draft data is missing."; return false; }
            if (draft.Brightness < 0 || draft.Brightness > 100) { error = "brightness must be between 0 and 100."; return false; }
            if (draft.Speed < 0 || draft.Speed > 100) { error = "speed must be between 0 and 100."; return false; }
            string color = draft.Color ?? "";
            if (!System.Text.RegularExpressions.Regex.IsMatch(color, "^#[0-9A-Fa-f]{6}$")) { error = "color must use #RRGGBB format."; return false; }
            if (!String.IsNullOrEmpty(draft.Layer) && !connection.Layers.Contains(draft.Layer)) { error = "the layer is not declared in this descriptor."; return false; }
            if (!String.IsNullOrEmpty(draft.Table) && !connection.Tables.Contains(draft.Table)) { error = "the OS table is not declared in this descriptor."; return false; }
            if (draft.KeyMappings == null) { error = "the key mapping dictionary is missing."; return false; }
            if (draft.KeyMappings.Count > 2048) { error = "the draft contains too many key mapping entries."; return false; }
            if (draft.KeyMappings.Count > 0 && connection.LayoutGroups.All(group => group.GroupIndex != draft.LayoutGroup))
            {
                error = "the selected layout group is not declared in this descriptor.";
                return false;
            }
            foreach (KeyValuePair<string, string> mapping in draft.KeyMappings)
            {
                string[] parts = (mapping.Key ?? "").Split('|');
                int groupIndex, layerIndex, tableIndex = -1, slotIndex, keyCode;
                bool tableContextValid = connection.Tables.Count == 0
                    ? String.Equals(parts.Length > 2 ? parts[2] : "", "tNone", StringComparison.Ordinal)
                    : parts.Length > 2 && TryIndexedPart(parts[2], "t", out tableIndex)
                        && tableIndex < connection.Tables.Count;
                if (parts.Length != 4
                    || !TryIndexedPart(parts[0], "g", out groupIndex)
                    || !TryIndexedPart(parts[1], "l", out layerIndex)
                    || !TryIndexedPart(parts[3], "s", out slotIndex)
                    || !Int32.TryParse(mapping.Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out keyCode)
                    || !String.Equals(mapping.Value, keyCode.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal)
                    || !tableContextValid)
                {
                    error = "a key mapping has an invalid group/layer/table/slot identifier or key code.";
                    return false;
                }
                DriveLayoutGroup group = connection.LayoutGroups.FirstOrDefault(item => item.GroupIndex == groupIndex);
                DriveLayerLayout layer = group == null ? null : group.Layers.FirstOrDefault(item => item.LayerIndex == layerIndex);
                if (group == null || layer == null || slotIndex < 0 || slotIndex >= layer.KeySlots.Count
                    || !group.Layers.SelectMany(item => item.KeySlots).Any(slot => slot.KeyCode == keyCode))
                {
                    error = "a key mapping refers to a slot, table, or key code not declared for this descriptor.";
                    return false;
                }
            }
            DriveEffect effect = String.IsNullOrEmpty(draft.Effect) ? null : connection.Effects.FirstOrDefault(item => String.Equals(item.Name, draft.Effect, StringComparison.OrdinalIgnoreCase));
            if (!String.IsNullOrEmpty(draft.Effect) && effect == null) { error = "the lighting effect is not declared in this descriptor."; return false; }
            if (draft.MixColor && (effect == null || !effect.MixColor)) { error = "color mixing is not declared for the selected effect."; return false; }
            return true;
        }

        private static bool TryIndexedPart(string value, string prefix, out int index)
        {
            index = -1;
            if (value == null || !value.StartsWith(prefix, StringComparison.Ordinal)
                || !Int32.TryParse(value.Substring(prefix.Length), System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out index) || index < 0)
            {
                index = -1;
                return false;
            }
            return String.Equals(value, prefix + index.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);
        }

        private static string SafeFileSegment(string value)
        {
            string safe = value ?? "model";
            foreach (char invalid in Path.GetInvalidFileNameChars()) safe = safe.Replace(invalid, '-');
            safe = safe.Trim().Trim('.');
            return String.IsNullOrEmpty(safe) ? "model" : safe;
        }

        private ComboBox DraftCombo(string label, List<string> values, string savedValue)
        {
            ComboBox selector = new ComboBox { Width = 250, Height = 30, Padding = new Thickness(7, 3, 7, 3), Background = Brush(20, 20, 20), BorderBrush = Brush(80, 80, 80), Foreground = Brush(220, 220, 220), IsEnabled = values.Count > 0 };
            foreach (string value in values) selector.Items.Add(value);
            if (values.Contains(savedValue)) selector.SelectedItem = savedValue;
            else if (values.Count > 0) selector.SelectedIndex = 0;
            selector.ToolTip = label + " declared by the RK Drive registry";
            return selector;
        }

        private void AddLabeledControl(Panel parent, string label, UIElement control)
        {
            Grid row = new Grid { Margin = new Thickness(0, 5, 0, 0) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(130) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            TextBlock caption = new TextBlock { Text = label, Foreground = Brush(70, 78, 90), FontSize = 10, VerticalAlignment = VerticalAlignment.Center };
            row.Children.Add(caption);
            Grid.SetColumn(control, 1);
            row.Children.Add(control);
            parent.Children.Add(row);
        }

        private StackPanel PairControl(UIElement first, UIElement second)
        {
            StackPanel pair = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            pair.Children.Add(first);
            pair.Children.Add(second);
            return pair;
        }

        private TextBlock FeatureLine(string title, string description)
        {
            return new TextBlock { Text = title + "  ·  " + description, Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
        }

        private void RenderDriveDetails(StackPanel details, DriveModel model)
        {
            details.Children.Clear();
            if (model == null)
            {
                details.Children.Add(Kicker("MODEL DETAILS"));
                details.Children.Add(Paragraph("Select a directory entry to inspect its public metadata.", 11));
                return;
            }
            details.Children.Add(Kicker("PUBLIC MODEL RECORD"));
            details.Children.Add(Headline(model.Name, 20));
            Border imageFrame = new Border { Height = 205, Background = Brush(246, 247, 249), CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 10, 0, 10), Padding = new Thickness(8) };
            Image productImage = new Image { Stretch = Stretch.Uniform, ToolTip = "Loaded from RK's public site when this model is selected" };
            imageFrame.Child = productImage;
            details.Children.Add(imageFrame);
            TextBlock imageStatus = new TextBlock { Text = "Product photo is requested from the official host when selected.", Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap };
            details.Children.Add(imageStatus);
            LoadDriveImage(productImage, model.ImageUrl, imageStatus);
            Button openImage = ActionButton("Open official product image", false);
            openImage.Margin = new Thickness(0, 8, 0, 12);
            openImage.Click += delegate { OpenOfficialUrl(model.ImageUrl); };
            details.Children.Add(openImage);

            foreach (DriveConnection row in model.Connections)
            {
                Border card = Card();
                card.Margin = new Thickness(0, 0, 0, 9);
                StackPanel body = new StackPanel { Margin = new Thickness(13) };
                card.Child = body;
                body.Children.Add(new TextBlock { Text = row.Connection + (row.Specialized ? "  ·  specialized profile" : ""), Foreground = Brush(49, 94, 181), FontSize = 10, FontWeight = FontWeights.Bold });
                body.Children.Add(new TextBlock { Text = "VID " + Blank(row.VendorId) + "  ·  PID " + Blank(row.ProductId) + "  ·  " + Blank(row.Protocol), Foreground = Brush(52, 60, 72), FontSize = 11, Margin = new Thickness(0, 5, 0, 0), TextWrapping = TextWrapping.Wrap });
                body.Children.Add(new TextBlock { Text = "Usage " + Blank(row.UsagePage) + ":" + Blank(row.Usage), Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(0, 3, 0, 0) });
                if (row.Specialized)
                {
                    body.Children.Add(new TextBlock { Text = "UUID " + Blank(row.Uuid) + "  ·  minimum firmware " + Blank(row.FirmwareMinimum) + "  ·  side light " + (row.HasSideLight == true ? "declared" : "not declared"), Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap });
                }
                if (row.HasDeclaredConfiguratorData)
                {
                    body.Children.Add(new TextBlock { Text = "Key layers: " + (row.Layers.Count == 0 ? "none declared" : String.Join(" / ", row.Layers)) + "  ·  OS tables: " + (row.Tables.Count == 0 ? "none declared" : String.Join(" / ", row.Tables)) + "  ·  layout groups: " + row.LayoutGroupCount, Foreground = Brush(70, 78, 90), FontSize = 9, Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap });
                    if (row.Effects.Count > 0)
                    {
                        body.Children.Add(new TextBlock { Text = "Declared lighting effects: " + String.Join(", ", row.Effects.Select(effect => effect.Name)), Foreground = Brush(70, 78, 90), FontSize = 9, Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap });
                        body.Children.Add(new TextBlock { Text = "Effect controls are recorded per mode (speed, brightness, color, mix color); their presence is not proof of firmware support.", Foreground = Brush(111, 120, 133), FontSize = 8, Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap });
                    }
                }
                else
                {
                    body.Children.Add(new TextBlock { Text = "This row has no layer/table/effect declaration in the extracted entry registry. Specialized profile data is recorded separately.", Foreground = Brush(111, 120, 133), FontSize = 9, Margin = new Thickness(0, 7, 0, 0), TextWrapping = TextWrapping.Wrap });
                }
                details.Children.Add(card);
            }

            Button openSite = ActionButton("Open RK Drive", false);
            openSite.Click += delegate { OpenOfficialUrl("https://drive.rkgaming.com/"); };
            details.Children.Add(openSite);
            details.Children.Add(new TextBlock { Text = "Static registry metadata only. Shared receiver IDs and model labels can be ambiguous; the directory does not confirm hardware identity.", Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 9, 0, 0) });
        }

        private static string ThumbnailUrl(string imageUrl, int width)
        {
            Uri uri;
            if (!Uri.TryCreate(imageUrl, UriKind.Absolute, out uri)) return imageUrl;
            string query = uri.Query.TrimStart('?');
            if (Regex.IsMatch(query, "(^|&)width=\\d+", RegexOptions.IgnoreCase))
                query = Regex.Replace(query, "(^|&)width=\\d+", "$1width=" + width, RegexOptions.IgnoreCase);
            else
                query = String.IsNullOrEmpty(query) ? "width=" + width : query + "&width=" + width;
            UriBuilder builder = new UriBuilder(uri) { Query = query };
            return builder.Uri.ToString();
        }

        private async void LoadDriveImage(Image target, string imageUrl, TextBlock status)
        {
            target.Source = null;
            Uri uri;
            if (!Uri.TryCreate(imageUrl, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps
                || !(String.Equals(uri.Host, "drive.rkgaming.com", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(uri.Host, "rkgamingstore.com", StringComparison.OrdinalIgnoreCase)))
            {
                status.Text = "No valid RK-hosted product image reference is recorded.";
                return;
            }
            try
            {
                using (HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) })
                using (Stream imageStream = await client.GetStreamAsync(uri))
                using (MemoryStream buffer = new MemoryStream())
                {
                    await imageStream.CopyToAsync(buffer);
                    buffer.Position = 0;
                    BitmapImage bitmap = new BitmapImage();
                    bitmap.BeginInit();
                    bitmap.CacheOption = BitmapCacheOption.OnLoad;
                    bitmap.StreamSource = buffer;
                    bitmap.EndInit();
                    bitmap.Freeze();
                    target.Source = bitmap;
                    status.Text = "Photo loaded on demand from " + uri.Host + ". The image is not included in this application.";
                }
            }
            catch
            {
                target.Source = null;
                status.Text = "RK's image host could not be reached. Use the link below to open the product image.";
            }
        }

        private static void OpenOfficialUrl(string url)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps
                || !(String.Equals(uri.Host, "drive.rkgaming.com", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(uri.Host, "rkgamingstore.com", StringComparison.OrdinalIgnoreCase))) return;
            try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
            catch { }
        }

        private void UpdateDirectorySelection(StackPanel results)
        {
            foreach (Button button in results.Children.OfType<Button>())
            {
                button.Background = Object.ReferenceEquals(button.Tag, _selectedDriveModel) ? Brush(60, 31, 15) : Brush(20, 20, 20);
            }
        }

        private void RenderPreferences()
        {
            AddIntro("Application preferences", "The native app can remain in the notification area. Start with Windows is a new opt-in setting for this community rebuild.");
            Border card = Card();
            StackPanel body = new StackPanel { Margin = new Thickness(21) };
            card.Child = body;
            body.Children.Add(Kicker("WINDOWS INTEGRATION"));
            CheckBox startup = new CheckBox { Content = "Start RK Rebuild when I sign in", IsChecked = _settings.StartWithWindows, Foreground = Brush(54, 62, 74), FontSize = 13, Margin = new Thickness(0, 16, 0, 0) };
            startup.Checked += delegate { SetStartupPreference(true); };
            startup.Unchecked += delegate { SetStartupPreference(false); };
            body.Children.Add(startup);
            body.Children.Add(new TextBlock { Text = "The preference writes a per-user Run entry. It can be turned off here or from the tray menu; no administrator access is needed.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0) });
            body.Children.Add(new Border { Height = 1, Background = Brush(231, 234, 238), Margin = new Thickness(0, 18, 0, 16) });
            body.Children.Add(Kicker("LOCAL RESOURCE FOLDER"));
            body.Children.Add(new TextBlock { Text = String.IsNullOrEmpty(_settings.ResourceRoot) ? "No folder selected" : _settings.ResourceRoot, Foreground = Brush(80, 88, 101), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 10) });
            Button choose = ActionButton("Choose extracted RK app folder", false);
            choose.HorizontalAlignment = HorizontalAlignment.Left;
            choose.Click += delegate { ChooseResourceRoot(); };
            body.Children.Add(choose);
            body.Children.Add(new TextBlock { Text = "The app reads optional local images from Dev/<profile code>. Vendor files are not bundled with the public source or executable.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
            _pageBody.Children.Add(card);

            Border local = Card();
            local.Margin = new Thickness(0, 14, 0, 0);
            StackPanel localBody = new StackPanel { Margin = new Thickness(21) };
            local.Child = localBody;
            localBody.Children.Add(Kicker("PROFILE STORAGE"));
            localBody.Children.Add(new TextBlock { Text = SettingsStore.FilePath, Foreground = Brush(100, 108, 120), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
            _pageBody.Children.Add(local);
        }

        private void SetStartupPreference(bool enabled)
        {
            _settings.StartWithWindows = enabled;
            SetStartup(enabled);
            SettingsStore.Save(_settings);
            UpdateTrayStartupText();
        }

        private void SetStartup(bool enabled)
        {
            const string keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyPath, true) ?? Registry.CurrentUser.CreateSubKey(keyPath))
                {
                    if (enabled)
                    {
                        string exe = Assembly.GetExecutingAssembly().Location;
                        key.SetValue("RK Rebuild", "\"" + exe + "\" --background");
                    }
                    else key.DeleteValue("RK Rebuild", false);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Windows startup preference could not be updated.\n\n" + ex.Message, "RK Rebuild", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private Forms.NotifyIcon BuildTray()
        {
            Forms.NotifyIcon tray = new Forms.NotifyIcon();
            string iconPath = Path.Combine(_settings.ResourceRoot ?? "", "appico.ico");
            try { tray.Icon = File.Exists(iconPath) ? new System.Drawing.Icon(iconPath) : SystemIcons.Application; }
            catch { tray.Icon = SystemIcons.Application; }
            tray.Text = "RK Keyboard";
            Forms.ContextMenuStrip menu = new Forms.ContextMenuStrip();
            Forms.ToolStripMenuItem configure = new Forms.ToolStripMenuItem("Configuration");
            configure.Click += delegate { ShowFromTray(); };
            menu.Items.Add(configure);
            Forms.ToolStripMenuItem startup = new Forms.ToolStripMenuItem("Start with Windows") { CheckOnClick = true, Checked = _settings.StartWithWindows };
            startup.CheckedChanged += delegate { SetStartupPreference(startup.Checked); };
            menu.Items.Add(startup);
            menu.Items.Add(new Forms.ToolStripSeparator());
            Forms.ToolStripMenuItem exit = new Forms.ToolStripMenuItem("Exit");
            exit.Click += delegate { ExitApplication(); };
            menu.Items.Add(exit);
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { ShowFromTray(); };
            tray.Visible = true;
            return tray;
        }

        private void UpdateTrayStartupText()
        {
            if (_tray == null || _tray.ContextMenuStrip == null) return;
            foreach (Forms.ToolStripItem item in _tray.ContextMenuStrip.Items)
            {
                Forms.ToolStripMenuItem menu = item as Forms.ToolStripMenuItem;
                if (menu != null && menu.Text == "Start with Windows") menu.Checked = _settings.StartWithWindows;
            }
        }

        private void ShowFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        private void OnClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                Hide();
            }
        }

        private void OnStateChanged(object sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                WindowState = WindowState.Normal;
            }
        }

        private void ExitApplication()
        {
            _allowClose = true;
            if (_tray != null) { _tray.Visible = false; _tray.Dispose(); }
            Close();
            Application.Current.Shutdown();
        }

        private void ChooseResourceRoot()
        {
            using (Forms.FolderBrowserDialog dialog = new Forms.FolderBrowserDialog())
            {
                dialog.Description = "Select the app folder containing Dev, or the Dev folder itself. The rebuild reads local artwork only.";
                dialog.SelectedPath = _settings.ResourceRoot;
                if (dialog.ShowDialog() == Forms.DialogResult.OK)
                {
                    _settings.ResourceRoot = NormalizeResourceRoot(dialog.SelectedPath);
                    SettingsStore.Save(_settings);
                    FontFamily = LoadRkFont();
                    BuildShell();
                    SelectProfile(_selected, false);
                    SetPage(_page);
                }
            }
        }

        private static string FindInstalledResourceRoot()
        {
            List<string> candidates = new List<string>();
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!String.IsNullOrWhiteSpace(programFilesX86)) candidates.Add(Path.Combine(programFilesX86, "RK Keyboard Software"));
            if (!String.IsNullOrWhiteSpace(programFiles)) candidates.Add(Path.Combine(programFiles, "RK Keyboard Software"));
            candidates.Add(@"C:\Program Files (x86)\RK Keyboard Software");
            return candidates.FirstOrDefault(path => File.Exists(Path.Combine(path, "Cfg.ini")) && Directory.Exists(Path.Combine(path, "skins"))) ?? "";
        }

        private static string NormalizeResourceRoot(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            string fullPath = Path.GetFullPath(path);
            if (Directory.Exists(Path.Combine(fullPath, "skins"))) return fullPath;
            if (String.Equals(Path.GetFileName(fullPath), "Dev", StringComparison.OrdinalIgnoreCase))
            {
                DirectoryInfo parent = Directory.GetParent(fullPath);
                if (parent != null && Directory.Exists(Path.Combine(parent.FullName, "skins"))) return parent.FullName;
            }
            return fullPath;
        }

        private FontFamily LoadRkFont()
        {
            try
            {
                string folder = Path.Combine(_settings.ResourceRoot ?? "", "font");
                if (Directory.Exists(folder) && Directory.GetFiles(folder, "Open Sans*.ttf").Length > 0)
                    return new FontFamily(new Uri(folder.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, UriKind.Absolute), "./#Open Sans");
            }
            catch { }
            return new FontFamily("Arial");
        }

        private BitmapSource LoadSkinBitmap(string fileName)
        {
            try
            {
                string path = Path.Combine(_settings.ResourceRoot ?? "", "skins", fileName);
                if (!File.Exists(path)) return null;
                BitmapImage bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.UriSource = new Uri(path, UriKind.Absolute);
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.EndInit();
                bitmap.Freeze();
                return bitmap;
            }
            catch { return null; }
        }

        private Image SkinImage(string fileName, double width, double height)
        {
            BitmapSource bitmap = LoadSkinBitmap(fileName);
            return bitmap == null ? null : new Image { Source = bitmap, Width = width, Height = height, Stretch = Stretch.Uniform, VerticalAlignment = VerticalAlignment.Center };
        }

        private Image LoadProfileImage()
        {
            try
            {
                string folder = ProfileFolder();
                if (String.IsNullOrEmpty(folder)) return null;
                string[] names = { "kbled.png", "keyimg.png", "sideled.png" };
                string path = names.Select(n => Path.Combine(folder, n)).FirstOrDefault(File.Exists);
                if (String.IsNullOrEmpty(path)) return null;
                BitmapImage bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.UriSource = new Uri(path, UriKind.Absolute);
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.EndInit();
                return new Image { Source = bitmap };
            }
            catch { return null; }
        }

        private string ProfileFolder()
        {
            if (String.IsNullOrEmpty(_settings.ResourceRoot)) return "";
            string root = NormalizeResourceRoot(_settings.ResourceRoot);
            string[] candidates = {
                Path.Combine(root, "Dev", _selected.Code),
                Path.Combine(root, _selected.Code)
            };
            string exact = candidates.FirstOrDefault(HasProfileArtwork);
            if (!String.IsNullOrEmpty(exact)) return exact;

            string configPath = Path.Combine(root, "Cfg.ini");
            if (!File.Exists(configPath)) return "";
            string family = NormalizeModelName(_selected.Family);
            string modelName = NormalizeModelName(_selected.Name);
            List<Tuple<int, string>> matches = new List<Tuple<int, string>>();
            try
            {
                foreach (string line in File.ReadLines(configPath))
                {
                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("DevName", StringComparison.OrdinalIgnoreCase)) continue;
                    int equals = trimmed.IndexOf('=');
                    if (equals < 0) continue;
                    string[] values = trimmed.Substring(equals + 1).Split(new[] { ',' }, 2);
                    if (values.Length != 2) continue;
                    string code = values[0].Trim();
                    string label = values[1].Trim();
                    string candidate = Path.Combine(root, "Dev", code);
                    if (!HasProfileArtwork(candidate)) continue;
                    string normalizedLabel = NormalizeModelName(label);
                    int score = !String.IsNullOrEmpty(modelName) && normalizedLabel.Contains(modelName, StringComparison.OrdinalIgnoreCase) ? 0 :
                        !String.IsNullOrEmpty(family) && normalizedLabel.Contains(family, StringComparison.OrdinalIgnoreCase) ? 1 : 2;
                    if (score < 2) matches.Add(Tuple.Create(score, candidate));
                }
            }
            catch { return ""; }
            return matches.OrderBy(item => item.Item1).Select(item => item.Item2).FirstOrDefault() ?? "";
        }

        private static bool HasProfileArtwork(string folder)
        {
            return Directory.Exists(folder) && new[] { "kbled.png", "keyimg.png", "sideled.png" }.Any(name => File.Exists(Path.Combine(folder, name)));
        }

        private static string NormalizeModelName(string value)
        {
            return new String((value ?? "").Where(Char.IsLetterOrDigit).ToArray());
        }

        private void AddIntro(string title, string detail)
        {
            _pageBody.Children.Add(Headline(title, 24));
            _pageBody.Children.Add(new TextBlock { Text = detail, Foreground = Brush(111, 120, 133), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 16), MaxWidth = 940 });
        }

        private Border Card()
        {
            return new Border { Background = new SolidColorBrush(MediaColor.FromArgb(215, 14, 17, 22)), BorderBrush = Brush(92, 92, 92), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(2) };
        }

        private Border CardWithText(string text)
        {
            Border card = Card();
            card.Padding = new Thickness(18);
            card.Child = new TextBlock { Text = text, Foreground = Brush(111, 120, 133), FontSize = 12, TextWrapping = TextWrapping.Wrap };
            return card;
        }

        private TextBlock Kicker(string text)
        {
            return new TextBlock { Text = text, Foreground = Brush(180, 180, 180), FontSize = 9, FontWeight = FontWeights.Bold };
        }

        private TextBlock Headline(string text, double size)
        {
            return new TextBlock { Text = text, Foreground = Brush(235, 235, 235), FontSize = size, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 7, 0, 0), TextWrapping = TextWrapping.Wrap };
        }

        private TextBlock Paragraph(string text, double size)
        {
            return new TextBlock { Text = text, Foreground = Brush(175, 175, 175), FontSize = size, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) };
        }

        private Grid MetricGrid(string[,] rows)
        {
            Grid grid = new Grid { Margin = new Thickness(0, 10, 0, 0) };
            for (int c = 0; c < rows.GetLength(0); c++) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            for (int c = 0; c < rows.GetLength(0); c++)
            {
                StackPanel metric = new StackPanel { Margin = new Thickness(0, 2, 14, 2) };
                metric.Children.Add(new TextBlock { Text = rows[c, 0], Foreground = Brush(165, 165, 165), FontSize = 9, FontWeight = FontWeights.Bold });
                metric.Children.Add(new TextBlock { Text = rows[c, 1], Foreground = Brush(220, 220, 220), FontSize = 14, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 5, 0, 0) });
                Grid.SetColumn(metric, c);
                grid.Children.Add(metric);
            }
            return grid;
        }

        private Border StatusPill(string label, Brush background, Brush foreground)
        {
            return new Border { Background = background, Padding = new Thickness(10, 6, 10, 6), Child = new TextBlock { Text = label, Foreground = foreground, FontSize = 9, FontWeight = FontWeights.Bold } };
        }

        private Button ActionButton(string label, bool primary)
        {
            BitmapSource normal = LoadSkinBitmap("btn_nr.png");
            BitmapSource hover = LoadSkinBitmap("btn_ov.png");
            Button button = new Button {
                Content = label, Height = 38, MinWidth = 150, Padding = new Thickness(13, 0, 13, 0), FontSize = 11,
                Foreground = Brush(220, 220, 220), Background = normal == null ? (primary ? Brush(201, 81, 0) : Brush(20, 20, 20)) : new ImageBrush(normal) { Stretch = Stretch.Fill },
                BorderBrush = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, HorizontalAlignment = HorizontalAlignment.Left
            };
            button.MouseEnter += delegate { if (hover != null) button.Background = new ImageBrush(hover) { Stretch = Stretch.Fill }; };
            button.MouseLeave += delegate { if (normal != null) button.Background = new ImageBrush(normal) { Stretch = Stretch.Fill }; else button.Background = primary ? Brush(201, 81, 0) : Brush(20, 20, 20); };
            return button;
        }

        private static string Blank(string value) { return String.IsNullOrEmpty(value) ? "not recorded" : value; }
        private static SolidColorBrush Brush(byte r, byte g, byte b)
        {
            if (r == 49 && g == 94 && b == 181) { r = 201; g = 81; b = 0; }
            else if ((r == 232 && g == 240 && b == 252) || (r == 235 && g == 241 && b == 251)) { r = 56; g = 31; b = 18; }
            else if (r == 246 && g == 247 && b == 249) { r = 20; g = 20; b = 20; }
            else if ((r == 216 && g == 221 && b == 228) || (r == 218 && g == 223 && b == 230) || (r == 214 && g == 219 && b == 226) || (r == 229 && g == 232 && b == 237) || (r == 231 && g == 234 && b == 238)) { r = 78; g = 78; b = 78; }
            else if (r == 29 && g == 35 && b == 45) { r = 20; g = 20; b = 20; }
            else if (r == 43 && g == 51 && b == 64) { r = 39; g = 39; b = 39; }
            else if (r == 63 && g == 71 && b == 84) { r = 66; g = 66; b = 66; }
            else if (r == 60 && g == 31 && b == 15) { r = 54; g = 28; b = 15; }
            else if (r == 45 && g == 35 && b == 28) { r = 46; g = 35; b = 28; }
            else if (r == 64 && g == 120 && b == 82) { r = 95; g = 177; b = 104; }
            else if (r == 133 && g == 90 && b == 28) { r = 255; g = 128; b = 0; }
            else if ((r == 50 && g == 58 && b == 70) || (r == 47 && g == 55 && b == 67) || (r == 48 && g == 56 && b == 68) || (r == 52 && g == 60 && b == 72) || (r == 54 && g == 62 && b == 74) || (r == 55 && g == 63 && b == 75) || (r == 56 && g == 64 && b == 76) || (r == 58 && g == 66 && b == 78) || (r == 70 && g == 78 && b == 90) || (r == 80 && g == 88 && b == 101) || (r == 35 && g == 42 && b == 53) || (r == 36 && g == 43 && b == 54)) { r = 220; g = 220; b = 220; }
            else if ((r == 100 && g == 108 && b == 120) || (r == 111 && g == 120 && b == 133) || (r == 120 && g == 128 && b == 140) || (r == 124 && g == 133 && b == 145) || (r == 126 && g == 134 && b == 147) || (r == 129 && g == 140 && b == 155) || (r == 130 && g == 138 && b == 150) || (r == 145 && g == 153 && b == 164)) { r = 175; g = 175; b = 175; }
            else if (r == 165 && g == 174 && b == 189) { r = 175; g = 175; b = 175; }
            else if (r == 199 && g == 205 && b == 214) { r = 205; g = 205; b = 205; }
            else if (r == 206 && g == 212 && b == 221) { r = 220; g = 220; b = 220; }
            else if (r < 90 && !(r == g && g == b)) { r = 220; g = 220; b = 220; }
            return new SolidColorBrush(MediaColor.FromRgb(r, g, b));
        }
    }

    internal sealed class TextEntryWindow : Window
    {
        private readonly TextBox _entry;
        public string Value { get { return _entry.Text.Trim(); } }

        public TextEntryWindow(string title, string label, string value, FontFamily appFont)
        {
            Title = title;
            Width = 430;
            Height = 205;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(MediaColor.FromRgb(20, 20, 20));
            Foreground = new SolidColorBrush(MediaColor.FromRgb(220, 220, 220));
            FontFamily = appFont ?? new FontFamily("Arial");
            Grid grid = new Grid { Margin = new Thickness(22) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Content = grid;
            grid.Children.Add(new TextBlock { Text = label, Foreground = new SolidColorBrush(MediaColor.FromRgb(220, 220, 220)), FontSize = 12, Margin = new Thickness(0, 0, 0, 8) });
            _entry = new TextBox { Text = value, FontSize = 13, Padding = new Thickness(9, 7, 9, 7), BorderBrush = new SolidColorBrush(MediaColor.FromRgb(78, 78, 78)), Background = new SolidColorBrush(MediaColor.FromRgb(20, 20, 20)), Foreground = new SolidColorBrush(MediaColor.FromRgb(220, 220, 220)) };
            Grid.SetRow(_entry, 1);
            grid.Children.Add(_entry);
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
            Grid.SetRow(buttons, 3);
            grid.Children.Add(buttons);
            Button cancel = new Button { Content = "Cancel", Width = 76, Height = 32, Margin = new Thickness(0, 0, 8, 0), Background = new SolidColorBrush(MediaColor.FromRgb(20, 20, 20)), Foreground = new SolidColorBrush(MediaColor.FromRgb(220, 220, 220)), BorderBrush = new SolidColorBrush(MediaColor.FromRgb(85, 85, 85)) };
            cancel.Click += delegate { DialogResult = false; };
            buttons.Children.Add(cancel);
            Button save = new Button { Content = "Save draft", Width = 94, Height = 32, IsDefault = true, Background = new SolidColorBrush(MediaColor.FromRgb(201, 81, 0)), Foreground = Brushes.White, BorderBrush = new SolidColorBrush(MediaColor.FromRgb(201, 81, 0)) };
            save.Click += delegate { DialogResult = true; };
            buttons.Children.Add(save);
        }
    }
}
