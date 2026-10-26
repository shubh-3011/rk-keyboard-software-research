using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Xml.Linq;

internal static class InstallerLifecycleTests
{
    private static int checks;
    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private static string FindInstaller(string[] args)
    {
        if (args.Length == 1) return Path.GetFullPath(args[0]);
        foreach (string start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
            for (DirectoryInfo dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
                foreach (string suffix in new[] { "installer", Path.Combine("rebuild", "windows", "installer") })
                {
                    string candidate = Path.Combine(dir.FullName, suffix);
                    if (File.Exists(Path.Combine(candidate, "test-installer-lifecycle.ps1"))) return candidate;
                }
        throw new InvalidOperationException("Pass the installer directory as the sole argument.");
    }

    private static (int ExitCode, string Output) RunPowerShell(string command, Action<ProcessStartInfo> configure = null)
    {
        // Windows PowerShell ships with Windows: no PowerShell SDK/NuGet dependency.
        string host = OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe") : "pwsh";
        ProcessStartInfo info = new ProcessStartInfo(host) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", command }) info.ArgumentList.Add(arg);
        configure?.Invoke(info);
        using Process process = Process.Start(info);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000))
        {
            process.Kill(); // Only this test's parser/guard child, never any MSI service/process.
            throw new InvalidOperationException("PowerShell parser/negative-guard test timed out.");
        }
        return (process.ExitCode, stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
    }

    private static string Quote(string value) => "'" + value.Replace("'", "''") + "'";

    private static int Main(string[] args)
    {
        try
        {
            string root = FindInstaller(args);
            string path = Path.Combine(root, "test-installer-lifecycle.ps1");
            string script = File.ReadAllText(path);
            foreach (string guard in new[] { "$env:GITHUB_ACTIONS -cne 'true'", "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$env:RUNNER_OS -cne 'Windows'", "-not $ConfirmDisposableVm", "Assert-DisposableRunner", "OpenDatabase($Path, 0)", "Assert-ProductCode", "$previous.Version -lt $current.Version", "$current.ProductCode -ne $previous.ProductCode", "12D50DE5-7286-4B6E-99D9-B4F9FC1F7996", "Pre-existing path", "Pre-existing product registration", "RelatedProducts", "Registry32", "Registry64", "LocalMachine", "CurrentUser", "WaitForExit(120000)", "$script:MsiUncertain = $true", "$code -eq 1618", "if ($script:MsiUncertain)", "System32\\msiexec.exe", "/qn /norestart /L*v", "Get-FileHash -LiteralPath $installedExe -Algorithm SHA256", "Get-FileHash -LiteralPath $installedLicense -Algorithm SHA256", "Repair deletion ownership/hash guard", "Invoke-Msi '/fa'", "Invoke-Msi '/x' $current.ProductCode", "-ExpectFailure", "Downgrade changed uninstall registration", "--compatibility-report", "DOTNET_BUNDLE_EXTRACT_BASE_DIR", "444", "CataloguedOnly", "$attemptedProducts.Add", "$completed = $true" })
                Check(script.Contains(guard, StringComparison.Ordinal), "Missing lifecycle safeguard: " + guard);
            foreach (string forbidden in new[] { "Win32_Product", "Stop-Process", "taskkill", "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "Remove-Item -Recurse", "--hid-diagnostics", "--read-wireless", "--read-g5", "--apply-", "InstallProduct(" })
                Check(!script.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "Forbidden lifecycle behavior: " + forbidden);

            // Parse with the real PowerShell AST; never dot-source or execute an allowed invocation.
            string parse = "$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; " +
                "$ast=[System.Management.Automation.Language.Parser]::ParseFile(" + Quote(path) + ",[ref]$tokens,[ref]$errors); " +
                "if($errors.Count){throw ($errors | Out-String)}; " +
                "$commands=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)); " +
                "$remove=@($commands | Where-Object {$_.GetCommandName() -eq 'Remove-Item'}); " +
                "if($remove.Count -ne 1 -or $remove[0].Extent.Text -cne 'Remove-Item -LiteralPath $installedExe'){throw 'Unsafe deletion AST'}; " +
                "$launch=@($commands | Where-Object {$_.GetCommandName() -eq 'Start-Process'}); " +
                "if($launch.Count -ne 2){throw 'Unexpected process launch AST'}; " +
                "$top=@($ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.PipelineAst] -and $_.Extent.Text -notlike 'Set-StrictMode *'}); " +
                "if($top[0].Extent.Text -cne 'Assert-DisposableRunner'){throw 'Guard must be first top-level command'}; " +
                "Write-Output 'PASS: syntax and ownership AST'";
            var parsed = RunPowerShell(parse);
            Check(parsed.ExitCode == 0, "PowerShell AST validation: " + parsed.Output);
            var parsedBuild = RunPowerShell("$errors=$null; $tokens=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile(" + Quote(Path.Combine(root, "build-installer.ps1")) + ",[ref]$tokens,[ref]$errors); if($errors.Count){throw ($errors | Out-String)}");
            Check(parsedBuild.ExitCode == 0, "Build PowerShell syntax: " + parsedBuild.Output);

            // Each invocation has at least one deliberately failed guard, even in real CI.
            // Nonexistent dummy inputs prove refusal precedes Resolve-Path/file/registry IO.
            string dummy = Path.Combine(Path.GetTempPath(), "rk-lifecycle-negative-" + Guid.NewGuid().ToString("N"));
            for (int failingGuard = 0; failingGuard < 4; failingGuard++)
            {
                string invocation = "$ErrorActionPreference='Stop'; try { & " + Quote(path) +
                    " -CurrentMsiPath " + Quote(Path.Combine(dummy, "current.msi")) +
                    " -PreviousMsiPath " + Quote(Path.Combine(dummy, "previous.msi")) +
                    " -SourceExe " + Quote(Path.Combine(dummy, "RK-Rebuild.exe")) +
                    (failingGuard == 0 ? "" : " -ConfirmDisposableVm") +
                    "; throw 'Unexpected guard acceptance' } catch { if($_.Exception.Message -notlike 'REFUSED:*'){throw}; Write-Output $_.Exception.Message; exit 17 }";
                int failure = failingGuard;
                var result = RunPowerShell(invocation, info =>
                {
                    info.Environment["GITHUB_ACTIONS"] = failure == 1 ? "false" : "true";
                    info.Environment["RUNNER_ENVIRONMENT"] = failure == 2 ? "self-hosted" : "github-hosted";
                    info.Environment["RUNNER_OS"] = failure == 3 ? "Linux" : "Windows";
                    info.Environment["RUNNER_TEMP"] = dummy;
                });
                Check(result.ExitCode == 17 && result.Output.Contains("REFUSED:", StringComparison.Ordinal), "Negative guard " + failingGuard + ": " + result.Output);
                Check(!Directory.Exists(dummy) && !File.Exists(dummy), "Negative guard created scratch/input data");
            }

            XNamespace wix = "http://wixtoolset.org/schemas/v4/wxs";
            XDocument manifest = XDocument.Load(Path.Combine(root, "Package.wxs"));
            XElement package = manifest.Root.Element(wix + "Package");
            Check((string)package.Attribute("Scope") == "perUser", "Lifecycle requires per-user manifest");
            Check((string)package.Attribute("UpgradeCode") == "12D50DE5-7286-4B6E-99D9-B4F9FC1F7996", "Lifecycle family must match manifest");
            Check(manifest.Descendants(wix + "File").Count() == 2, "Lifecycle payload must remain EXE + LICENSE");
            string build = File.ReadAllText(Path.Combine(root, "build-installer.ps1"));
            foreach (string token in new[] { "[string]$VersionProject", "[string]$OutputDirectory", "msbuild $VersionProject", "ProductVersion", "FileMajorPart", "Get-FileHash", "test-installer.ps1" })
                Check(build.Contains(token, StringComparison.Ordinal), "Build version/payload guard missing: " + token);
            Console.WriteLine("PASS: " + checks + " lifecycle manifest/code/AST and negative-guard checks; no installation or registry writes.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("FAIL: " + exception.Message);
            return 1;
        }
    }
}
