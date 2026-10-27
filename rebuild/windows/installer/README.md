# Experimental per-user MSI

This is an **unsigned, experimental Windows x64 MSI**, built only from the
existing source-built `../dist/RK-Rebuild.exe` and this repository's root MIT
`LICENSE`. It is not the vendor's installer and contains no separately packaged
vendor art, icons, firmware, drivers, research captures, or `.research` tree.
There is no directory harvesting. The existing EXE is treated as an immutable
input: packaging does not rebuild, launch, or change it. Build that EXE from
trusted project source before packaging; version metadata alone does not prove
its provenance.

## Build

From the repository root in Windows PowerShell 5.1 or PowerShell 7:

```powershell
# If needed, first build the source-only app using the existing build script.
# .\rebuild\windows\build.ps1
.\rebuild\windows\installer\build-installer.ps1

# An alternate existing source-built executable can be explicitly supplied:
.\rebuild\windows\installer\build-installer.ps1 -SourceExe 'C:\build\RK-Rebuild.exe'

# Package a real previous build, using its immutable checkout's evaluated version.
# Keep its artifact separate; do not relabel the current EXE as an older release.
.\rebuild\windows\installer\build-installer.ps1 `
  -SourceExe 'C:\previous-checkout\rebuild\windows\dist\RK-Rebuild.exe' `
  -VersionProject 'C:\previous-checkout\rebuild\windows\RKRebuild.csproj' `
  -OutputDirectory 'C:\ci-artifacts\previous-installer'
```

The script prefers `../.dotnet/dotnet.exe`, falling back to `dotnet` on PATH.
It needs a .NET 8 SDK and Windows Installer COM. It restores the exactly pinned
`WixToolset.Sdk/5.0.2` through ordinary project-local NuGet restore, using only
the source in `NuGet.Config`. It does **not** install a global tool, SDK, runtime,
application, or driver. SDK CLI state, package cache and HTTP cache are isolated
inside this ignored installer subtree; environment variables and working
directory are restored in `finally`. First-run ASP.NET certificate generation
is explicitly disabled. First restore needs access to nuget.org; honor network
approval policy rather than working around denied access.

The app's evaluated `Version` is read with `dotnet msbuild -getProperty:Version`.
It must have three numeric components within MSI's `255.255.65535` limits.
The input EXE must exist, and its ProductVersion and first three FileVersion
components must match. The app's experimental InformationalVersion suffix and
an optional zero fourth component are accepted. Missing/mismatched inputs fail
before WiX build.

`VersionProject` defaults to `../RKRebuild.csproj`; `OutputDirectory` defaults to
`../dist/installer`. Overriding them does not bypass EXE/version/hash guards. For
the two-version CI test, build actual `0.5.0` source in an immutable previous
checkout and package its real EXE with that checkout's project, then separately
package the current `0.6.0` EXE. The current installer authoring is used for both.

WiX intermediates are isolated under `obj/<version>/Release/`. Packaging the
current and previous versions sequentially must not reuse the other version's
incremental outputs; selecting a different final output directory alone is not
sufficient to isolate WiX's cache.

Output, for app version `0.5.0`:

```text
rebuild/windows/dist/installer/RK-Rebuild-0.5.0-win-x64-experimental.msi
rebuild/windows/dist/installer/RK-Rebuild-0.5.0-win-x64-experimental.msi.sha256
```

MSI and cache outputs are not source artifacts; do not commit them. The SHA-256
sidecar is written only after read-only database and exact payload validation
succeeds. No signing or bootstrapper is performed. Windows may display an
unknown publisher warning. Source inputs and tool version make the build process
repeatable; **byte-for-byte MSI reproducibility is not promised**: WiX/Windows
Installer generates package identity and summary timestamps per build. The
sidecar records the actual artifact, not an expected constant hash.

## Installation contract (not executed by the build/read-only tests)

- Scope is `perUser`, with the MSI summary's non-elevated bit set. `ALLUSERS`
  is absent; a launch condition rejects an attempt to set it. No admin rights,
  UAC elevation request, all-users folders, or HKLM writes are authored.
- Files go to `%LOCALAPPDATA%\Programs\RK Rebuild`: `RK-Rebuild.exe` and
  `LICENSE.txt`. This is deliberately local/non-roaming.
- One **non-advertised** shortcut goes to the current user's Start Menu under
  `RK Rebuild`. No desktop shortcut is authored, so there is no default desktop
  clutter or extra optional UI. Users may create one manually if desired.
- No startup entry, scheduled task, service, environment mutation, hardware
  command, application auto-launch, or custom action is authored.
- Two HKCU values under `Software\RK Rebuild\Installer` are Windows Installer
  component key paths, not application preferences or startup entries. Standard
  MSI actions register the per-user uninstaller in Windows installed-apps UI.
  The uninstaller is not hidden or disabled. Removal deletes the owned files,
  shortcut and component values and removes the app/menu folders only if empty;
  the intermediate `Programs` folder is also removed only if empty (ICE64).
  Existing application data and unrelated files are not recursively removed.
- UpgradeCode stays **`12D50DE5-7286-4B6E-99D9-B4F9FC1F7996`**. Component GUIDs
  also stay fixed. ProductCode is deterministically derived from this product
  family, version and architecture, so re-running the same immutable version
  enters MSI maintenance rather than creating duplicate registrations. MSI
  package codes remain generated per build.
- A strictly higher three-part version major-upgrades the same user's older
  installation, removing it after `InstallInitialize` inside rollback protection.
  A lower version detects a newer version and is blocked. Same-version major
  upgrades are disabled; publish changed payloads only with an increased app
  version. **Do not redistribute different EXEs under the same version.**
  For an intentional rollback, the user must explicitly uninstall the newer
  version first. Other users' installations are outside this package's scope.

WiX ICE validation remains enabled, with warnings as errors. Only **ICE91** is
suppressed: that check warns that LocalAppData files cannot serve a hypothetical
per-machine installation. This is intentional and enforced by `Scope=perUser`
and the `NOT ALLUSERS` launch condition. Other validation is not disabled.

## Validate without installing

Dependency-free console checks (manifest and script guard regressions):

```powershell
.\rebuild\windows\.dotnet\dotnet.exe run --project .\rebuild\windows\tests\InstallerManifest.Tests.csproj --configuration Release
.\rebuild\windows\.dotnet\dotnet.exe run --project .\rebuild\windows\tests\InstallerLifecycle.Tests.csproj --configuration Release
```

Read-only inspection of an already built package (also run by the build):

```powershell
.\rebuild\windows\installer\test-installer.ps1 `
  -MsiPath .\rebuild\windows\dist\installer\RK-Rebuild-0.5.0-win-x64-experimental.msi `
  -ExpectedVersion 0.5.0
```

The inspection opens `WindowsInstaller.Installer.OpenDatabase(path, 0)` and
reads summary information and MSI tables. It verifies scope, directory ancestry,
exact file allowlist, HKCU-only component keys, non-advertised shortcut, visible
standard uninstaller registration actions, absence of custom actions/services/
startup entries/vendor icons, and upgrade/downgrade conditions. It exports the
embedded cabinet via `Record.ReadStream`, extracts **data only** with Windows'
`expand.exe`, and verifies the EXE and MIT license SHA-256 against source inputs.
Only a newly created GUID-named directory under ignored `.validation/` is used
and cleaned up. It never calls `msiexec`, `InstallProduct`, `OpenPackage`, or the
application. There is no `Win32_Product` query (which can trigger repair).

The lifecycle console tests are also safe locally: they inspect the manifest and
script, parse the real PowerShell AST, and invoke only deliberately failing
runner/confirmation guards with nonexistent inputs. They never install anything
or write the registry. They require Windows PowerShell (or `pwsh` on other OSes).

## Real lifecycle validation: disposable GitHub-hosted Windows runner ONLY

**Never run installation locally, on a user VM, or on a self-hosted runner. Do not
spoof the environment checks to bypass this restriction.** Only an ephemeral
GitHub-hosted Windows job, after building both real versions and passing the
read-only package checks, may explicitly invoke:

```powershell
.\rebuild\windows\installer\test-installer-lifecycle.ps1 `
  -CurrentMsiPath '.\rebuild\windows\dist\installer\RK-Rebuild-0.6.0-win-x64-experimental.msi' `
  -PreviousMsiPath 'C:\ci-artifacts\previous-installer\RK-Rebuild-0.5.0-win-x64-experimental.msi' `
  -SourceExe '.\rebuild\windows\dist\RK-Rebuild.exe' `
  -ConfirmDisposableVm
```

Before input IO or COM activation, the script requires all of
`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, `RUNNER_OS=Windows`,
and the explicit confirmation switch. It opens both MSI databases read-only,
checks stable family identity, distinct GUID ProductCodes, strictly increasing
versions and per-user destinations, and refuses existing target/menu paths,
family registrations, installer component keys, processes, or startup entries.

The actual sequence is previous install → current major upgrade → rejected old
package downgrade → repair after deleting only the verified owned EXE → installed
`--compatibility-report` smoke (exactly 444 `CataloguedOnly` entries) → uninstall.
Checks cover current EXE/license SHA-256, previous registration removal, current
HKCU registration, no HKLM registration, exact current-user shortcut target,
no shared/desktop/startup shortcut and no auto-launch. Downgrade must leave
payload, shortcut and uninstall registration unchanged. Smoke uses no HID command;
its output, shadow writable app/runtime directories, stdout and stderr stay in a
new GUID-named directory under `RUNNER_TEMP`, alongside verbose MSI logs.

Every `msiexec` client has a 120-second timeout. On timeout only this script's
client is terminated: the Windows Installer service is never killed. Because its
transaction might continue, further MSI operations (including cleanup) are
refused. Exit 1618 similarly blocks concurrent cleanup. Other failures trigger
bounded uninstall attempts only for this invocation's attempted ProductCodes
that are registered in HKCU; no generic file/registry deletion is performed.
Keep logs and discard the ephemeral runner, especially after a timeout. This
does not test reboot recovery, locked-file rollback, other users, or hardware.

Workflow wiring is separate. Upload current `dist/installer/*.msi` and
`*.msi.sha256` only as unsigned experimental artifacts; keep previous-version
fixtures isolated from the distributable upload. CI can retain the invocation's
`RUNNER_TEMP/rk-installer-lifecycle-*` logs/report for diagnostics. A local
parser/guard test pass is **not** evidence that the real lifecycle passed.
