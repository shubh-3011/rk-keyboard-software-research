using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

internal static class InstallerManifestTests
{
    private static int checks;
    private static readonly XNamespace W = "http://wixtoolset.org/schemas/v4/wxs";

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private static string Attr(XElement element, string name) => (string)element.Attribute(name);

    private static string FindInstaller(string[] args)
    {
        if (args.Length == 1) return Path.GetFullPath(args[0]);
        foreach (string start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
        {
            for (DirectoryInfo dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
            {
                foreach (string suffix in new[] { "installer", Path.Combine("rebuild", "windows", "installer") })
                {
                    string candidate = Path.Combine(dir.FullName, suffix);
                    if (File.Exists(Path.Combine(candidate, "Package.wxs"))) return candidate;
                }
            }
        }
        throw new InvalidOperationException("Pass the installer directory as the sole argument.");
    }

    private static int Main(string[] args)
    {
        try
        {
            string root = FindInstaller(args);
            XDocument manifest = XDocument.Load(Path.Combine(root, "Package.wxs"));
            XElement package = manifest.Root.Element(W + "Package");
            Check(package != null, "Exactly one WiX package is required.");
            Check(manifest.Descendants(W + "Package").Count() == 1, "No extra packages.");
            Check(Attr(package, "Scope") == "perUser", "Must be truly per-user, not per-machine/dual-purpose.");
            Check(Attr(package, "UpgradeCode") == "12D50DE5-7286-4B6E-99D9-B4F9FC1F7996", "Stable UpgradeCode changed.");
            Check(Attr(package, "Version") == "$(PackageVersion)", "Version must come from the app project.");
            Check(Attr(package, "ProductCode") == "$(ProductCode)", "Same-version maintenance identity must be supplied.");
            XElement upgrade = package.Element(W + "MajorUpgrade");
            Check(Attr(upgrade, "AllowDowngrades") == "no", "Downgrades must be blocked.");
            Check(Attr(upgrade, "AllowSameVersionUpgrades") == "no", "No same-version replacement/downgrade loophole.");
            Check(Attr(upgrade, "Schedule") == "afterInstallInitialize", "Major upgrade must be transactional.");
            Check(package.Elements(W + "Launch").Any(x => Attr(x, "Condition") == "NOT ALLUSERS"), "Reject command-line per-machine override.");
            Check(Attr(package.Element(W + "MediaTemplate"), "EmbedCab") == "yes", "MSI must be self-contained.");

            Dictionary<string, XElement> dirs = manifest.Descendants().Where(x => x.Name == W + "Directory" || x.Name == W + "StandardDirectory").ToDictionary(x => Attr(x, "Id"));
            Check(Attr(dirs["INSTALLFOLDER"], "Name") == "RK Rebuild", "Installation folder name.");
            Check(Attr(dirs["INSTALLFOLDER"].Parent, "Id") == "UserProgramsFolder", "Installation folder parent.");
            Check(Attr(dirs["UserProgramsFolder"], "Name") == "Programs", "Programs folder name.");
            Check(Attr(dirs["UserProgramsFolder"].Parent, "Id") == "LocalAppDataFolder", "Must install under LocalAppData\\Programs.");
            Check(Attr(dirs["ApplicationMenuFolder"].Parent, "Id") == "ProgramMenuFolder", "Current user's Start Menu only.");
            Check(!dirs.Keys.Any(x => x.Contains("Desktop", StringComparison.OrdinalIgnoreCase) || x.Contains("Startup", StringComparison.OrdinalIgnoreCase) || x.Contains("ProgramFiles", StringComparison.OrdinalIgnoreCase) || x.Contains("Common", StringComparison.OrdinalIgnoreCase)), "No desktop/startup/shared/system directories.");

            XElement[] files = manifest.Descendants(W + "File").ToArray();
            Check(files.Length == 2, "Strict two-file payload allowlist.");
            Check(files.Any(x => Attr(x, "Id") == "AppExecutable" && Attr(x, "Source") == "$(SourceExe)" && Attr(x, "Name") == "RK-Rebuild.exe"), "Only validated source-built EXE.");
            Check(files.Any(x => Attr(x, "Id") == "ProjectLicense" && Attr(x, "Source") == "$(LicenseFile)" && Attr(x, "Name") == "LICENSE.txt"), "Project MIT license required.");
            Check(files.All(x => !Attr(x, "Source").Contains('*')), "Never harvest directories/vendor assets.");
            XElement shortcut = manifest.Descendants(W + "Shortcut").Single();
            Check(Attr(shortcut, "Advertise") == "no", "Shortcut must be non-advertised.");
            Check(Attr(shortcut, "Target") == "[INSTALLFOLDER]RK-Rebuild.exe", "Shortcut must point only to app.");
            Check(Attr(shortcut, "WorkingDirectory") == "INSTALLFOLDER" && shortcut.Attribute("Arguments") == null, "No hardware/startup command arguments.");
            Check(Attr(shortcut.Parent.Parent, "Id") == "ApplicationMenuFolder", "No extra shortcut locations.");

            XElement[] components = manifest.Descendants(W + "Component").ToArray();
            Check(components.Length == 2, "Only application and Start Menu components.");
            Dictionary<string, string> expectedGuids = new Dictionary<string, string>
            {
                ["ApplicationFiles"] = "6A9694FA-23E2-49E1-9D3A-38602B15AC56",
                ["StartMenuShortcut"] = "2FE6B5AE-A1B9-42AA-A2C1-325A59FB1B16"
            };
            foreach (XElement component in components)
            {
                Check(expectedGuids[Attr(component, "Id")] == Attr(component, "Guid"), "Component identity must remain stable.");
                XElement registry = component.Element(W + "RegistryValue");
                Check(registry != null && Attr(registry, "Root") == "HKCU" && Attr(registry, "Key") == "Software\\RK Rebuild\\Installer" && Attr(registry, "KeyPath") == "yes", "Each per-user component needs own HKCU key path.");
                Check(component.Elements(W + "RemoveFolder").Any(x => Attr(x, "On") == "uninstall" && x.Attribute("Directory") == null), "Remove own empty app/menu folders on uninstall.");
            }
            Check(manifest.Descendants(W + "RegistryValue").Count() == 2, "No extra registry writes.");
            string[] forbidden = { "CustomAction", "Custom", "SetProperty", "SetDirectory", "ServiceInstall", "ServiceControl", "Environment", "Files", "Icon", "Binary", "RegistryKey", "RemoveFile", "LaunchApplication" };
            Check(!manifest.Descendants().Any(x => forbidden.Contains(x.Name.LocalName)), "No custom actions, services, vendor icons, harvesting or launch actions.");
            Check(!manifest.Descendants(W + "Property").Any(x => new[] { "ALLUSERS", "MSIINSTALLPERUSER", "ARPSYSTEMCOMPONENT", "ARPNOREMOVE", "DISABLEADVTSHORTCUTS" }.Contains(Attr(x, "Id"))), "Do not hide uninstall or enable dual-purpose scope.");
            Check(manifest.Descendants(W + "ComponentRef").Select(x => Attr(x, "Id")).OrderBy(x => x).SequenceEqual(expectedGuids.Keys.OrderBy(x => x)), "Both components included in feature.");

            XDocument project = XDocument.Load(Path.Combine(root, "RKRebuild.Installer.wixproj"));
            Check((string)project.Root.Attribute("Sdk") == "WixToolset.Sdk/5.0.2", "WiX SDK must be exactly pinned.");
            Check(!project.Descendants("PackageReference").Any(), "No optional/custom-action extension dependencies.");
            Check(project.Descendants("InstallerPlatform").Single().Value == "x64", "Match existing win-x64 self-contained app.");
            Check(project.Descendants("SuppressIces").Single().Value == "ICE91", "Only intentional per-user ICE91 may be suppressed.");
            Check(project.Descendants("TreatWarningsAsErrors").Single().Value == "true", "Other WiX validation warnings fail the build.");

            string script = File.ReadAllText(Path.Combine(root, "build-installer.ps1"));
            foreach (string required in new[] { ".dotnet\\dotnet.exe", "Get-Command dotnet", "-PathType Leaf", "-getProperty:Version", "FileVersionInfo", "ProductVersion", "FileMajorPart", "255", "65535", "SHA256", "dist\\installer", "test-installer.ps1", ".sha256", "$LASTEXITCODE", "NUGET_PACKAGES", "DOTNET_CLI_HOME", "DOTNET_GENERATE_ASPNET_CERTIFICATE = \"false\"", "DOTNET_NOLOGO = \"true\"", "finally" })
                Check(script.Contains(required, StringComparison.Ordinal), "Missing build guard: " + required);
            foreach (string forbiddenCommand in new[] { "Start-Process", "InstallProduct(", "OpenPackage(", "dotnet tool install", "Invoke-WebRequest", "Set-ItemProperty", "New-ItemProperty", "Register-ScheduledTask" })
                Check(!script.Contains(forbiddenCommand, StringComparison.OrdinalIgnoreCase), "Build must never install/launch/configure: " + forbiddenCommand);
            string inspection = File.ReadAllText(Path.Combine(root, "test-installer.ps1"));
            foreach (string required in new[] { "WindowsInstaller.Installer", "OpenDatabase($MsiPath, 0)", "SummaryInformation(0)", "ReadStream(1, 65536, 1)", "expand.exe", "SHA256", "CustomAction", "WIX_DOWNGRADE_DETECTED", "RegisterProduct", "PublishProduct" })
                Check(inspection.Contains(required, StringComparison.Ordinal), "Missing read-only MSI validation: " + required);
            Console.WriteLine("PASS: " + checks + " installer manifest/script checks (no MSI execution).");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("FAIL: " + exception.Message);
            return 1;
        }
    }
}
