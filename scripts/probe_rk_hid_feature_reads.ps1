param(
    [ValidateRange(1, 10)]
    [int]$RepeatCount = 3,
    [ValidatePattern('^[0-9A-Fa-f]{4}$')]
    [string]$VendorId = '258A',
    [ValidatePattern('^[0-9A-Fa-f]{4}$')]
    [string]$ProductId = '0150'
)

$ErrorActionPreference = 'Stop'

# This probe opens only the explicitly selected vendor-defined feature
# collections with GENERIC_READ. It calls HidD_GetFeature for descriptor-
# documented report IDs 0x05 and 0x0A; it contains no report/device write API.
$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

public static class RkReadOnlyFeatureProbe
{
    private const int DIGCF_PRESENT = 0x00000002;
    private const int DIGCF_DEVICEINTERFACE = 0x00000010;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private static readonly Regex CollectionPattern = new Regex(
        @"(?<mi>MI_[0-9A-F]{2})(?:&(?<col>COL[0-9A-F]{2}))?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public UIntPtr Reserved;
    }

    [DllImport("hid.dll")]
    private static extern void HidD_GetHidGuid(out Guid hidGuid);

    [DllImport("hid.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HidD_GetFeature(
        SafeFileHandle handle, byte[] reportBuffer, int reportBufferLength);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevsW(
        ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, int flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr deviceInfoSet, IntPtr deviceInfoData, ref Guid interfaceClassGuid,
        uint memberIndex, ref SP_DEVICE_INTERFACE_DATA interfaceData);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceInterfaceDetailW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet, ref SP_DEVICE_INTERFACE_DATA interfaceData,
        IntPtr detailData, int detailDataSize, ref int requiredSize, IntPtr deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    public sealed class Row
    {
        public string Interface { get; set; }
        public string ReportId { get; set; }
        public int Attempt { get; set; }
        public string Result { get; set; }
        public string DataHex { get; set; }
        public string Sha256 { get; set; }
    }

    private static string Hash(byte[] bytes)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(bytes);
            var text = new StringBuilder(hash.Length * 2);
            foreach (byte value in hash) text.Append(value.ToString("x2"));
            return text.ToString();
        }
    }

    private static void AddReads(List<Row> rows, string label, SafeFileHandle handle,
        byte reportId, int reportBytes, int repeatCount)
    {
        for (int attempt = 1; attempt <= repeatCount; attempt++)
        {
            var report = new byte[reportBytes];
            report[0] = reportId;
            bool ok = HidD_GetFeature(handle, report, report.Length);
            int error = Marshal.GetLastWin32Error();
            rows.Add(new Row {
                Interface = label,
                ReportId = "0x" + reportId.ToString("X2"),
                Attempt = attempt,
                Result = ok ? "success" : "Win32 " + error,
                DataHex = ok ? BitConverter.ToString(report).Replace("-", " ") : "",
                Sha256 = ok ? Hash(report) : ""
            });
        }
    }

    public static Row[] Enumerate(string vendorId, string productId, int repeatCount)
    {
        Guid hidGuid;
        HidD_GetHidGuid(out hidGuid);
        IntPtr set = SetupDiGetClassDevsW(ref hidGuid, IntPtr.Zero, IntPtr.Zero,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == new IntPtr(-1))
            throw new InvalidOperationException("SetupDiGetClassDevs failed: " + Marshal.GetLastWin32Error());

        var rows = new List<Row>();
        try
        {
            for (uint index = 0; ; index++)
            {
                var interfaceData = new SP_DEVICE_INTERFACE_DATA();
                interfaceData.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref hidGuid, index, ref interfaceData))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 259) break;
                    throw new InvalidOperationException("SetupDiEnumDeviceInterfaces failed: " + error);
                }

                int required = 0;
                SetupDiGetDeviceInterfaceDetail(set, ref interfaceData, IntPtr.Zero, 0, ref required, IntPtr.Zero);
                if (required <= 0) continue;
                IntPtr detail = Marshal.AllocHGlobal(required);
                try
                {
                    Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref interfaceData, detail,
                        required, ref required, IntPtr.Zero)) continue;

                    string path = Marshal.PtrToStringUni(IntPtr.Add(detail, 4));
                    if (path == null || path.IndexOf("VID_" + vendorId + "&PID_" + productId,
                        StringComparison.OrdinalIgnoreCase) < 0) continue;
                    Match match = CollectionPattern.Match(path);
                    string collection = match.Success && match.Groups["col"].Success
                        ? match.Groups["col"].Value.ToUpperInvariant() : "";

                    byte reportId;
                    int reportBytes;
                    if (collection == "COL06") { reportId = 0x05; reportBytes = 6; }
                    else if (collection == "COL08") { reportId = 0x0A; reportBytes = 8; }
                    else continue;

                    string label = match.Success
                        ? match.Groups["mi"].Value.ToUpperInvariant() + "/" + collection
                        : collection;
                    using (SafeFileHandle handle = CreateFile(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                        OPEN_EXISTING, 0, IntPtr.Zero))
                    {
                        if (handle == null || handle.IsInvalid)
                        {
                            rows.Add(new Row { Interface = label,
                                ReportId = "0x" + reportId.ToString("X2"),
                                Result = "open failed Win32 " + Marshal.GetLastWin32Error() });
                        }
                        else AddReads(rows, label, handle, reportId, reportBytes, repeatCount);
                    }
                }
                finally { Marshal.FreeHGlobal(detail); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return rows.ToArray();
    }
}
'@

if (-not ('RkReadOnlyFeatureProbe' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

[RkReadOnlyFeatureProbe]::Enumerate($VendorId, $ProductId, $RepeatCount) |
    Sort-Object Interface, Attempt |
    Format-List Interface, ReportId, Attempt, Result, DataHex, Sha256
