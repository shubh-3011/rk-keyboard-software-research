using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Data;
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
                AppSettings settings = SettingsStore.Load();
                ModelCatalog catalog = ModelCatalog.Load();
                DriveDirectory driveDirectory = DriveDirectory.Load();
                Application app = new Application();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                MainWindow window = new MainWindow(catalog, driveDirectory, settings);
                if (args.Any(a => String.Equals(a, "--background", StringComparison.OrdinalIgnoreCase)))
                    app.Run();
                else
                    app.Run(window);
            }
            catch (Exception ex)
            {
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
        public Dictionary<string, DriveDraft> DriveDrafts { get; set; }

        public AppSettings()
        {
            SelectedCode = "021E";
            ResourceRoot = "";
            StartWithWindows = false;
            KeyLabelDrafts = new Dictionary<string, string>();
            MacroDrafts = new Dictionary<string, List<string>>();
            DriveDrafts = new Dictionary<string, DriveDraft>();
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

        public DriveDraft()
        {
            Layer = "";
            Table = "";
            Effect = "";
            Brightness = 100;
            Speed = 50;
            Color = "#FFFFFF";
            MixColor = false;
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
                        if (saved.DriveDrafts == null) saved.DriveDrafts = new Dictionary<string, DriveDraft>();
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
        public int KeyCount;
        public bool Rgb;
        public int MacroBuffers;
        public string Screen;
        public List<int> LightingSlots = new List<int>();
        public List<string> Layers = new List<string>();
        public List<LayoutKey> Keys = new List<LayoutKey>();
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
        public List<string> Layers = new List<string>();
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
                        connection.Tables = ReadStrings(ModelCatalog.GetValue(web, "key_tables"));
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
    }

    internal sealed class ModelCatalog
    {
        public List<ModelProfile> Models = new List<ModelProfile>();
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
            foreach (JsonElement item in models.EnumerateArray())
            {
                ModelProfile profile = new ModelProfile();
                profile.Code = GetString(item, "code");
                profile.Name = GetString(item, "name");
                profile.Family = GetString(item, "family");
                profile.Region = GetString(item, "region");
                profile.LayoutId = GetString(item, "layoutId");
                profile.KeyCount = GetInt(item, "keyCount");
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

    internal sealed class MainWindow : Window
    {
        private static readonly MediaColor Ink = MediaColor.FromRgb(35, 42, 53);
        private static readonly MediaColor Muted = MediaColor.FromRgb(111, 120, 133);
        private static readonly MediaColor Accent = MediaColor.FromRgb(49, 94, 181);
        private static readonly MediaColor Surface = MediaColor.FromRgb(255, 255, 255);
        private readonly ModelCatalog _catalog;
        private readonly DriveDirectory _driveDirectory;
        private readonly AppSettings _settings;
        private StackPanel _pageBody;
        private TextBlock _pageName;
        private TextBlock _profileHeader;
        private readonly Forms.NotifyIcon _tray;
        private ModelProfile _selected;
        private DriveModel _selectedDriveModel;
        private string _page = "Device";
        private bool _allowClose;

        public MainWindow(ModelCatalog catalog, DriveDirectory driveDirectory, AppSettings settings)
        {
            _catalog = catalog;
            _driveDirectory = driveDirectory;
            _settings = settings;
            _selected = _catalog.Models.FirstOrDefault(m => m.Code == settings.SelectedCode) ?? _catalog.Models.First();
            Title = "RK Rebuild — Community Edition";
            Width = 1440;
            Height = 900;
            MinWidth = 1120;
            MinHeight = 720;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = Brush(246, 247, 249);
            FontFamily = new FontFamily("Segoe UI");
            BuildShell();
            _tray = BuildTray();
            Closing += OnClosing;
            StateChanged += OnStateChanged;
            SelectProfile(_selected, false);
            SetStartup(_settings.StartWithWindows);
        }

        private void BuildShell()
        {
            Grid root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(238) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Content = root;

            Border sidebar = new Border { Background = Brush(29, 35, 45) };
            Grid.SetColumn(sidebar, 0);
            root.Children.Add(sidebar);
            StackPanel nav = new StackPanel { Margin = new Thickness(16, 20, 16, 14) };
            sidebar.Child = nav;
            StackPanel brand = new StackPanel { Margin = new Thickness(12, 2, 8, 24) };
            brand.Children.Add(new TextBlock { Text = "RK REBUILD", Foreground = Brushes.White, FontSize = 18, FontWeight = FontWeights.Bold });
            brand.Children.Add(new TextBlock { Text = "COMMUNITY WINDOWS EDITION", Foreground = Brush(165, 174, 189), FontSize = 9, Margin = new Thickness(0, 4, 0, 0) });
            nav.Children.Add(brand);
            nav.Children.Add(NavCaption("WORKSPACE"));
            AddNav(nav, "Device", "Device overview");
            AddNav(nav, "Key mapping", "Key mapping");
            AddNav(nav, "Lighting", "Lighting");
            AddNav(nav, "Macros", "Macros");
            AddNav(nav, "RK Drive editor", "RK Drive editor");
            nav.Children.Add(NavCaption("LIBRARY"));
            AddNav(nav, "Models", "Model profiles");
            AddNav(nav, "RK Drive directory", "RK Drive directory");
            nav.Children.Add(NavCaption("APPLICATION"));
            AddNav(nav, "Preferences", "Preferences");
            Border spacer = new Border { Height = 1, Background = Brush(63, 71, 84), Margin = new Thickness(7, 20, 7, 15) };
            nav.Children.Add(spacer);
            nav.Children.Add(new TextBlock { Text = "OFFLINE PROFILE WORKSPACE", Foreground = Brush(165, 174, 189), FontSize = 9, Margin = new Thickness(8, 0, 0, 8) });
            nav.Children.Add(new TextBlock { Text = "Hardware transport is unavailable", Foreground = Brush(199, 205, 214), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(8, 0, 8, 0) });

            Grid main = new Grid();
            main.RowDefinitions.Add(new RowDefinition { Height = new GridLength(72) });
            main.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(main, 1);
            root.Children.Add(main);
            Border top = new Border { Background = Brushes.White, BorderBrush = Brush(231, 234, 238), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(28, 0, 28, 0) };
            Grid.SetRow(top, 0);
            main.Children.Add(top);
            Grid head = new Grid();
            head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            top.Child = head;
            StackPanel heading = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            _pageName = new TextBlock { Text = "Device overview", Foreground = Brush(35, 42, 53), FontSize = 19, FontWeight = FontWeights.SemiBold };
            _profileHeader = new TextBlock { Text = "", Foreground = Brush(111, 120, 133), FontSize = 11, Margin = new Thickness(0, 3, 0, 0) };
            heading.Children.Add(_pageName);
            heading.Children.Add(_profileHeader);
            head.Children.Add(heading);
            StackPanel topTools = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(topTools, 1);
            head.Children.Add(topTools);
            topTools.Children.Add(StatusPill("LOCAL PROFILE", Brush(232, 240, 252), Brush(49, 94, 181)));
            ComboBox selector = new ComboBox { Width = 255, Height = 34, Margin = new Thickness(14, 0, 0, 0), Padding = new Thickness(8, 4, 8, 4), Background = Brushes.White, BorderBrush = Brush(218, 223, 230), Foreground = Brush(44, 51, 62), ItemsSource = _catalog.Models.OrderBy(m => m.Name).ThenBy(m => m.Code).ToList(), DisplayMemberPath = "Name" };
            selector.SelectionChanged += delegate { if (selector.SelectedItem is ModelProfile) SelectProfile((ModelProfile)selector.SelectedItem, true); };
            topTools.Children.Add(selector);
            _profileSelector = selector;

            ScrollViewer scroller = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
            Grid.SetRow(scroller, 1);
            main.Children.Add(scroller);
            _pageBody = new StackPanel { Margin = new Thickness(28, 26, 28, 30) };
            scroller.Content = _pageBody;
        }

        private ComboBox _profileSelector;

        private void AddNav(StackPanel nav, string page, string label)
        {
            Button button = new Button { Content = label, Tag = page, Height = 42, Margin = new Thickness(0, 2, 0, 2), Padding = new Thickness(13, 0, 10, 0), HorizontalContentAlignment = HorizontalAlignment.Left, BorderThickness = new Thickness(0), FontSize = 12, Cursor = Cursors.Hand, Background = page == "Device" ? Brush(49, 94, 181) : Brush(29, 35, 45), Foreground = page == "Device" ? Brushes.White : Brush(206, 212, 222) };
            button.Click += delegate { SetPage(page); };
            button.Style = new Style(typeof(Button));
            button.Style.Setters.Add(new Setter(Control.BackgroundProperty, Brush(29, 35, 45)));
            button.Style.Setters.Add(new Setter(Control.ForegroundProperty, Brush(206, 212, 222)));
            button.Style.Setters.Add(new Setter(Control.TemplateProperty, FlatButtonTemplate()));
            button.MouseEnter += delegate { if (_page != page) button.Background = Brush(43, 51, 64); };
            button.MouseLeave += delegate { if (_page != page) button.Background = Brush(29, 35, 45); };
            nav.Children.Add(button);
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
                if (button.Tag is string && new[] { "Device", "Key mapping", "Lighting", "Macros", "RK Drive editor", "Models", "RK Drive directory", "Preferences" }.Contains((string)button.Tag))
                {
                    bool active = (string)button.Tag == page;
                    button.Background = active ? Brush(49, 94, 181) : Brush(29, 35, 45);
                    button.Foreground = active ? Brushes.White : Brush(206, 212, 222);
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
            if (_profileSelector != null && _profileSelector.SelectedItem != profile) _profileSelector.SelectedItem = profile;
            _profileHeader.Text = profile.Name + "  ·  profile " + profile.Code;
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
            else RenderPreferences();
        }

        private void RenderDevice()
        {
            AddIntro("Selected software profile", "The selected profile is a local catalog entry. This build does not scan USB, open a HID collection, or identify a connected keyboard.");
            Grid grid = new Grid { Margin = new Thickness(0, 10, 0, 0) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.25, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(16) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.85, GridUnitType.Star) });
            Border profileCard = Card();
            Grid.SetColumn(profileCard, 0);
            grid.Children.Add(profileCard);
            StackPanel summary = new StackPanel { Margin = new Thickness(22) };
            profileCard.Child = summary;
            summary.Children.Add(Kicker("PROFILE DETAILS"));
            summary.Children.Add(Headline(_selected.Name, 23));
            summary.Children.Add(Paragraph("Catalog code " + _selected.Code + "  ·  Family " + Blank(_selected.Family) + "  ·  " + Blank(_selected.Region), 13));
            summary.Children.Add(new Border { Height = 1, Background = Brush(231, 234, 238), Margin = new Thickness(0, 12, 0, 14) });
            summary.Children.Add(MetricGrid(new string[,] { { "KEYS", _selected.KeyCount.ToString() }, { "LAYOUT", _selected.LayoutId }, { "LAYERS", _selected.Layers.Count.ToString() }, { "LIGHTING SLOTS", _selected.LightingSlots.Count.ToString() } }));
            summary.Children.Add(new TextBlock { Text = "Connection status: unavailable in this build", Foreground = Brush(133, 90, 28), FontSize = 12, Margin = new Thickness(0, 18, 0, 0) });
            summary.Children.Add(new TextBlock { Text = "The profile catalog cannot confirm your physical keyboard revision. Device support and report behavior remain under research.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });

            Border artCard = Card();
            Grid.SetColumn(artCard, 2);
            grid.Children.Add(artCard);
            StackPanel artStack = new StackPanel { Margin = new Thickness(19) };
            artCard.Child = artStack;
            artStack.Children.Add(Kicker("LOCAL PROFILE ART"));
            artStack.Children.Add(new TextBlock { Text = "Artwork is loaded only from an RK package folder you choose on this PC.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 12) });
            Image image = LoadProfileImage();
            if (image != null)
            {
                image.Height = 210;
                image.Stretch = Stretch.Uniform;
                artStack.Children.Add(image);
            }
            else
            {
                Border placeholder = new Border { Height = 210, Background = Brush(246, 247, 249), CornerRadius = new CornerRadius(8), Child = new TextBlock { Text = "No local image found", Foreground = Brush(145, 153, 164), FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center } };
                artStack.Children.Add(placeholder);
            }
            Button browse = ActionButton(String.IsNullOrEmpty(_settings.ResourceRoot) ? "Choose local resource folder" : "Change resource folder", false);
            browse.Margin = new Thickness(0, 12, 0, 0);
            browse.Click += delegate { ChooseResourceRoot(); };
            artStack.Children.Add(browse);
            _pageBody.Children.Add(grid);

            Border info = Card();
            info.Margin = new Thickness(0, 16, 0, 0);
            StackPanel infoBody = new StackPanel { Margin = new Thickness(20) };
            info.Child = infoBody;
            infoBody.Children.Add(Kicker("REBUILD STATUS"));
            infoBody.Children.Add(new TextBlock { Text = "This is a native Windows desktop process. It runs locally and does not open a browser, start a localhost server, or include Python.", Foreground = Brush(58, 66, 78), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0) });
            infoBody.Children.Add(new TextBlock { Text = "This first rebuild milestone provides profile browsing, local key-label drafts, local macro notes, tray behavior, and optional startup. Hardware configuration, updates, and firmware actions are not implemented.", Foreground = Brush(111, 120, 133), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });
            _pageBody.Children.Add(info);
        }

        private void RenderKeymap()
        {
            AddIntro("Local key-label draft", "Click a key to change its display label for this profile on this PC. The RK keycode tuple and hardware are not changed.");
            if (_selected.Keys.Count == 0)
            {
                _pageBody.Children.Add(CardWithText("No drawable key layout is recorded for this profile."));
                return;
            }
            double maxX = _selected.Keys.Max(k => k.X + k.W) + 12;
            double maxY = _selected.Keys.Max(k => k.Y + k.H) + 12;
            double scale = Math.Min(1.25, Math.Min(1030 / maxX, 440 / maxY));
            Canvas canvas = new Canvas { Width = maxX * scale, Height = maxY * scale, Background = Brush(246, 247, 249), Margin = new Thickness(10), ClipToBounds = true };
            foreach (LayoutKey key in _selected.Keys)
            {
                string keyId = key.Id ?? "";
                string draftKey = _selected.Code + ":" + keyId;
                string label = _settings.KeyLabelDrafts.ContainsKey(draftKey) ? _settings.KeyLabelDrafts[draftKey] : key.Label;
                Button tile = new Button { Content = label, Tag = key, FontSize = 9, Padding = new Thickness(2), Width = Math.Max(28, key.W * scale - 2), Height = Math.Max(26, key.H * scale - 2), Background = Brushes.White, Foreground = Brush(56, 64, 76), BorderBrush = Brush(206, 212, 221), BorderThickness = new Thickness(1), ToolTip = keyId + " · source label: " + key.Label, Cursor = Cursors.Hand };
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
            TextEntryWindow dialog = new TextEntryWindow(key.Id + " label draft", "Displayed label", oldValue);
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
            _pageBody.Children.Add(CardWithText("Lighting control, brightness adjustment, effect transfer, and readback are intentionally unavailable while hardware call paths remain under static review."));
        }

        private void RenderMacros()
        {
            AddIntro("Local macro notes", "Create simple text notes in this profile library. This editor does not capture key input, encode RK macro records, or send them to a keyboard.");
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
                inner.Children.Add(new TextBlock { Text = macros[i], Foreground = Brush(52, 60, 72), FontSize = 12, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });
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
            TextEntryWindow dialog = new TextEntryWindow("New local macro note", "Name or note", "");
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
            TextBox search = new TextBox { Height = 36, Padding = new Thickness(10, 7, 10, 6), FontSize = 12, BorderBrush = Brush(216, 221, 228), Background = Brushes.White, Margin = new Thickness(0, 0, 0, 12), ToolTip = "Search model name, family, region, or code" };
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
            TextBox search = new TextBox { Height = 35, Padding = new Thickness(9, 6, 9, 5), FontSize = 12, BorderBrush = Brush(216, 221, 228), Background = Brushes.White, ToolTip = "Search model, protocol, or connection ID" };
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
                        Background = model == _selectedDriveModel ? Brush(235, 241, 251) : Brushes.White,
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
                Background = Brushes.White, BorderBrush = Brush(218, 223, 230),
                ItemsSource = _driveDirectory.Models.OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase).ToList(),
                DisplayMemberPath = "Name"
            };
            ComboBox connectionSelector = new ComboBox {
                Width = 430, Height = 34, Margin = new Thickness(10, 0, 0, 0), Padding = new Thickness(8, 4, 8, 4),
                Background = Brushes.White, BorderBrush = Brush(218, 223, 230)
            };
            selectors.Children.Add(modelSelector);
            selectors.Children.Add(connectionSelector);
            _pageBody.Children.Add(selectors);
            StackPanel editor = new StackPanel();
            _pageBody.Children.Add(editor);

            Action redraw = delegate
            {
                editor.Children.Clear();
                DriveModel model = modelSelector.SelectedItem as DriveModel;
                DriveConnection connection = connectionSelector.SelectedItem as DriveConnection;
                if (model == null || connection == null)
                {
                    editor.Children.Add(CardWithText("Choose a model and a connection descriptor."));
                    return;
                }

                string draftKey = String.Join("|", model.Name, connection.Connection, connection.VendorId, connection.ProductId, connection.UsagePage, connection.Usage);
                DriveDraft saved;
                if (!_settings.DriveDrafts.TryGetValue(draftKey, out saved) || saved == null) saved = new DriveDraft();
                DriveDraft working = new DriveDraft {
                    Layer = saved.Layer, Table = saved.Table, Effect = saved.Effect,
                    Brightness = saved.Brightness, Speed = saved.Speed, Color = saved.Color, MixColor = saved.MixColor
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
                    keyBody.Children.Add(Paragraph(connection.LayoutGroupCount + " layout group(s) declared", 11));
                    ComboBox layerSelector = DraftCombo("Key layer", connection.Layers, working.Layer);
                    ComboBox tableSelector = DraftCombo("OS table", connection.Tables, working.Table);
                    AddLabeledControl(keyBody, "Layer", layerSelector);
                    AddLabeledControl(keyBody, "OS table", tableSelector);
                    keyBody.Children.Add(new TextBlock {
                        Text = "The public registry declares these choices, but this project has not recovered the matching web-layout data or a safe device apply path for this descriptor.",
                        Foreground = Brush(111, 120, 133), FontSize = 9, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0)
                    });
                    Button saveKeymap = ActionButton("Save keymap draft", true);
                    saveKeymap.Margin = new Thickness(0, 9, 0, 0);
                    TextBlock keymapStatus = new TextBlock { Foreground = Brush(64, 120, 82), FontSize = 9, Margin = new Thickness(9, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                    StackPanel keymapSaveRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 7, 0, 0) };
                    saveKeymap.Click += delegate
                    {
                        working.Layer = layerSelector.SelectedItem as string ?? "";
                        working.Table = tableSelector.SelectedItem as string ?? "";
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

        private ComboBox DraftCombo(string label, List<string> values, string savedValue)
        {
            ComboBox selector = new ComboBox { Width = 250, Height = 30, Padding = new Thickness(7, 3, 7, 3), Background = Brushes.White, BorderBrush = Brush(218, 223, 230), IsEnabled = values.Count > 0 };
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

        private async void LoadDriveImage(Image target, string imageUrl, TextBlock status)
        {
            Uri uri;
            if (!Uri.TryCreate(imageUrl, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || !String.Equals(uri.Host, "drive.rkgaming.com", StringComparison.OrdinalIgnoreCase))
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
                status.Text = "RK's image host could not be reached. Use the link below to open the product image.";
            }
        }

        private static void OpenOfficialUrl(string url)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || !String.Equals(uri.Host, "drive.rkgaming.com", StringComparison.OrdinalIgnoreCase)) return;
            try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
            catch { }
        }

        private void UpdateDirectorySelection(StackPanel results)
        {
            foreach (Button button in results.Children.OfType<Button>())
            {
                button.Background = Object.ReferenceEquals(button.Tag, _selectedDriveModel) ? Brush(235, 241, 251) : Brushes.White;
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
            tray.Icon = SystemIcons.Application;
            tray.Text = "RK Rebuild — Community Edition";
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
                    _settings.ResourceRoot = dialog.SelectedPath;
                    SettingsStore.Save(_settings);
                    RenderPage();
                }
            }
        }

        private Image LoadProfileImage()
        {
            try
            {
                string folder = ProfileFolder();
                if (String.IsNullOrEmpty(folder)) return null;
                string[] names = { "keyimg.png", "kbled.png", "sideled.png" };
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
            string first = Path.Combine(_settings.ResourceRoot, "Dev", _selected.Code);
            if (Directory.Exists(first)) return first;
            string second = Path.Combine(_settings.ResourceRoot, _selected.Code);
            return Directory.Exists(second) ? second : "";
        }

        private void AddIntro(string title, string detail)
        {
            _pageBody.Children.Add(Headline(title, 24));
            _pageBody.Children.Add(new TextBlock { Text = detail, Foreground = Brush(111, 120, 133), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 16), MaxWidth = 940 });
        }

        private Border Card()
        {
            return new Border { Background = Brushes.White, BorderBrush = Brush(229, 232, 237), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(9) };
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
            return new TextBlock { Text = text, Foreground = Brush(124, 133, 145), FontSize = 9, FontWeight = FontWeights.Bold };
        }

        private TextBlock Headline(string text, double size)
        {
            return new TextBlock { Text = text, Foreground = Brush(36, 43, 54), FontSize = size, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 7, 0, 0), TextWrapping = TextWrapping.Wrap };
        }

        private TextBlock Paragraph(string text, double size)
        {
            return new TextBlock { Text = text, Foreground = Brush(111, 120, 133), FontSize = size, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) };
        }

        private Grid MetricGrid(string[,] rows)
        {
            Grid grid = new Grid { Margin = new Thickness(0, 10, 0, 0) };
            for (int c = 0; c < rows.GetLength(0); c++) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            for (int c = 0; c < rows.GetLength(0); c++)
            {
                StackPanel metric = new StackPanel { Margin = new Thickness(0, 2, 14, 2) };
                metric.Children.Add(new TextBlock { Text = rows[c, 0], Foreground = Brush(126, 134, 147), FontSize = 9, FontWeight = FontWeights.Bold });
                metric.Children.Add(new TextBlock { Text = rows[c, 1], Foreground = Brush(47, 55, 67), FontSize = 14, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 5, 0, 0) });
                Grid.SetColumn(metric, c);
                grid.Children.Add(metric);
            }
            return grid;
        }

        private Border StatusPill(string label, Brush background, Brush foreground)
        {
            return new Border { Background = background, CornerRadius = new CornerRadius(12), Padding = new Thickness(10, 6, 10, 6), Child = new TextBlock { Text = label, Foreground = foreground, FontSize = 9, FontWeight = FontWeights.Bold } };
        }

        private Button ActionButton(string label, bool primary)
        {
            return new Button { Content = label, Height = 34, Padding = new Thickness(13, 0, 13, 0), FontSize = 11, Foreground = primary ? Brushes.White : Brush(55, 63, 75), Background = primary ? Brush(49, 94, 181) : Brushes.White, BorderBrush = primary ? Brush(49, 94, 181) : Brush(214, 219, 226), BorderThickness = new Thickness(1), Cursor = Cursors.Hand, HorizontalAlignment = HorizontalAlignment.Left };
        }

        private static string Blank(string value) { return String.IsNullOrEmpty(value) ? "not recorded" : value; }
        private static SolidColorBrush Brush(byte r, byte g, byte b) { return new SolidColorBrush(MediaColor.FromRgb(r, g, b)); }
    }

    internal sealed class TextEntryWindow : Window
    {
        private readonly TextBox _entry;
        public string Value { get { return _entry.Text.Trim(); } }

        public TextEntryWindow(string title, string label, string value)
        {
            Title = title;
            Width = 430;
            Height = 205;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(MediaColor.FromRgb(246, 247, 249));
            FontFamily = new FontFamily("Segoe UI");
            Grid grid = new Grid { Margin = new Thickness(22) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Content = grid;
            grid.Children.Add(new TextBlock { Text = label, Foreground = new SolidColorBrush(MediaColor.FromRgb(55, 63, 75)), FontSize = 12, Margin = new Thickness(0, 0, 0, 8) });
            _entry = new TextBox { Text = value, FontSize = 13, Padding = new Thickness(9, 7, 9, 7), BorderBrush = new SolidColorBrush(MediaColor.FromRgb(214, 219, 226)) };
            Grid.SetRow(_entry, 1);
            grid.Children.Add(_entry);
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
            Grid.SetRow(buttons, 3);
            grid.Children.Add(buttons);
            Button cancel = new Button { Content = "Cancel", Width = 76, Height = 32, Margin = new Thickness(0, 0, 8, 0) };
            cancel.Click += delegate { DialogResult = false; };
            buttons.Children.Add(cancel);
            Button save = new Button { Content = "Save draft", Width = 94, Height = 32, IsDefault = true, Background = new SolidColorBrush(MediaColor.FromRgb(49, 94, 181)), Foreground = Brushes.White };
            save.Click += delegate { DialogResult = true; };
            buttons.Children.Add(save);
        }
    }
}
