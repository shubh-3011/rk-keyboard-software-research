param(
    [ValidatePattern('^[0-9A-Fa-f]{4}$')]
    [string]$VendorId = '258A',
    [ValidatePattern('^[0-9A-Fa-f]{4}$')]
    [string]$ProductId = '0150'
)

$ErrorActionPreference = 'Stop'

$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

public static class RkReadOnlyHidMetadata
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

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDD_ATTRIBUTES
    {
        public int Size;
        public ushort VendorID;
        public ushort ProductID;
        public ushort VersionNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDP_CAPS
    {
        public ushort Usage;
        public ushort UsagePage;
        public ushort InputReportByteLength;
        public ushort OutputReportByteLength;
        public ushort FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
        public ushort[] Reserved;
        public ushort NumberLinkCollectionNodes;
        public ushort NumberInputButtonCaps;
        public ushort NumberInputValueCaps;
        public ushort NumberInputDataIndices;
        public ushort NumberOutputButtonCaps;
        public ushort NumberOutputValueCaps;
        public ushort NumberOutputDataIndices;
        public ushort NumberFeatureButtonCaps;
        public ushort NumberFeatureValueCaps;
        public ushort NumberFeatureDataIndices;
    }

    [DllImport("hid.dll")]
    private static extern void HidD_GetHidGuid(out Guid hidGuid);

    [DllImport("hid.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HidD_GetAttributes(SafeFileHandle handle, ref HIDD_ATTRIBUTES attributes);

    [DllImport("hid.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HidD_GetPreparsedData(SafeFileHandle handle, out IntPtr preparsedData);

    [DllImport("hid.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HidD_FreePreparsedData(IntPtr preparsedData);

    [DllImport("hid.dll")]
    private static extern int HidP_GetCaps(IntPtr preparsedData, ref HIDP_CAPS caps);

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
        public string Open { get; set; }
        public string Detail { get; set; }
        public string UsagePage { get; set; }
        public string Usage { get; set; }
        public int InputBytes { get; set; }
        public int OutputBytes { get; set; }
        public int FeatureBytes { get; set; }
        public int FeatureButtonCaps { get; set; }
        public int FeatureValueCaps { get; set; }
        public int FeatureDataIndices { get; set; }
        public string Attributes { get; set; }
    }

    public static Row[] Enumerate(string vendorId, string productId)
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
            for (uint i = 0; ; i++)
            {
                var interfaceData = new SP_DEVICE_INTERFACE_DATA();
                interfaceData.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref hidGuid, i, ref interfaceData))
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
                    string label = match.Success ? match.Groups["mi"].Value.ToUpperInvariant() : "MI_?";
                    if (match.Success && match.Groups["col"].Success)
                        label += "/" + match.Groups["col"].Value.ToUpperInvariant();

                    var row = new Row { Interface = label };
                    using (SafeFileHandle handle = CreateFile(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
                    {
                        if (handle == null || handle.IsInvalid)
                        {
                            row.Open = "denied/error";
                            row.Detail = "Win32 " + Marshal.GetLastWin32Error();
                            rows.Add(row);
                            continue;
                        }

                        row.Open = "read-only handle opened";
                        var attributes = new HIDD_ATTRIBUTES();
                        attributes.Size = Marshal.SizeOf(typeof(HIDD_ATTRIBUTES));
                        if (HidD_GetAttributes(handle, ref attributes))
                            row.Attributes = attributes.VendorID.ToString("X4") + ":" +
                                attributes.ProductID.ToString("X4") + " rev " + attributes.VersionNumber.ToString("X4");

                        IntPtr preparsed;
                        if (!HidD_GetPreparsedData(handle, out preparsed))
                        {
                            row.Detail = "HidD_GetPreparsedData Win32 " + Marshal.GetLastWin32Error();
                            rows.Add(row);
                            continue;
                        }

                        try
                        {
                            var caps = new HIDP_CAPS();
                            int status = HidP_GetCaps(preparsed, ref caps);
                            if (status != 0x00110000)
                            {
                                row.Detail = "HidP_GetCaps status 0x" + status.ToString("X8");
                            }
                            else
                            {
                                row.UsagePage = caps.UsagePage.ToString("X4");
                                row.Usage = caps.Usage.ToString("X4");
                                row.InputBytes = caps.InputReportByteLength;
                                row.OutputBytes = caps.OutputReportByteLength;
                                row.FeatureBytes = caps.FeatureReportByteLength;
                                row.FeatureButtonCaps = caps.NumberFeatureButtonCaps;
                                row.FeatureValueCaps = caps.NumberFeatureValueCaps;
                                row.FeatureDataIndices = caps.NumberFeatureDataIndices;
                            }
                        }
                        finally
                        {
                            HidD_FreePreparsedData(preparsed);
                        }
                    }
                    rows.Add(row);
                }
                finally
                {
                    Marshal.FreeHGlobal(detail);
                }
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }
        return rows.ToArray();
    }
}
'@

if (-not ('RkReadOnlyHidMetadata' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

[RkReadOnlyHidMetadata]::Enumerate($VendorId, $ProductId) |
    Sort-Object Interface |
    Format-Table Interface, Open, Detail, Attributes, UsagePage, Usage,
        InputBytes, OutputBytes, FeatureBytes, FeatureButtonCaps,
        FeatureValueCaps, FeatureDataIndices -AutoSize
