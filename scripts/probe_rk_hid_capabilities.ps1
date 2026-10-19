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

public static class RkReadOnlyHidCapabilities
{
    private const int DIGCF_PRESENT = 0x00000002;
    private const int DIGCF_DEVICEINTERFACE = 0x00000010;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const int HIDP_STATUS_SUCCESS = 0x00110000;
    private const int HIDP_INPUT = 0;
    private const int HIDP_OUTPUT = 1;
    private const int HIDP_FEATURE = 2;
    private const int HIDP_CAP_RECORD_SIZE = 72;
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
    private static extern bool HidD_GetPreparsedData(SafeFileHandle handle, out IntPtr preparsedData);

    [DllImport("hid.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HidD_FreePreparsedData(IntPtr preparsedData);

    [DllImport("hid.dll")]
    private static extern int HidP_GetCaps(IntPtr preparsedData, ref HIDP_CAPS caps);

    [DllImport("hid.dll")]
    private static extern int HidP_GetButtonCaps(int reportType, IntPtr buttonCaps,
        ref ushort buttonCapsLength, IntPtr preparsedData);

    [DllImport("hid.dll")]
    private static extern int HidP_GetValueCaps(int reportType, IntPtr valueCaps,
        ref ushort valueCapsLength, IntPtr preparsedData);

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

    public sealed class Capability
    {
        public string Interface { get; set; }
        public string ReportType { get; set; }
        public string Kind { get; set; }
        public string ReportId { get; set; }
        public string UsagePage { get; set; }
        public string Usage { get; set; }
        public string LinkCollection { get; set; }
        public string LinkUsage { get; set; }
        public string LinkUsagePage { get; set; }
        public string ReportCount { get; set; }
        public string BitSize { get; set; }
        public string LogicalRange { get; set; }
        public string Status { get; set; }
    }

    private static ushort ReadU16(IntPtr p, int offset)
    {
        return unchecked((ushort)Marshal.ReadInt16(p, offset));
    }

    private static string Hex(ushort value)
    {
        return value.ToString("X4");
    }

    private static void AddCaps(List<Capability> rows, string collection, string reportName,
        int reportType, ushort count, bool button, IntPtr preparsed)
    {
        if (count == 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(count * HIDP_CAP_RECORD_SIZE);
        try
        {
            ushort returned = count;
            int status = button
                ? HidP_GetButtonCaps(reportType, buffer, ref returned, preparsed)
                : HidP_GetValueCaps(reportType, buffer, ref returned, preparsed);

            if (status != HIDP_STATUS_SUCCESS)
            {
                rows.Add(new Capability {
                    Interface = collection,
                    ReportType = reportName,
                    Kind = button ? "button" : "value",
                    Status = "HIDP status 0x" + status.ToString("X8")
                });
                return;
            }

            for (int i = 0; i < returned; i++)
            {
                IntPtr cap = IntPtr.Add(buffer, i * HIDP_CAP_RECORD_SIZE);
                bool isRange = Marshal.ReadByte(cap, 12) != 0;
                ushort usageStart = ReadU16(cap, 56);
                ushort usageEnd = isRange ? ReadU16(cap, 58) : usageStart;
                ushort reportCount = ReadU16(cap, button ? 16 : 20);
                string logicalRange = button ? "n/a" :
                    Marshal.ReadInt32(cap, 40).ToString() + ".." + Marshal.ReadInt32(cap, 44).ToString();

                rows.Add(new Capability {
                    Interface = collection,
                    ReportType = reportName,
                    Kind = button ? "button" : "value",
                    ReportId = Marshal.ReadByte(cap, 2).ToString("X2"),
                    UsagePage = Hex(ReadU16(cap, 0)),
                    Usage = isRange ? Hex(usageStart) + "-" + Hex(usageEnd) : Hex(usageStart),
                    LinkCollection = ReadU16(cap, 6).ToString(),
                    LinkUsage = Hex(ReadU16(cap, 8)),
                    LinkUsagePage = Hex(ReadU16(cap, 10)),
                    ReportCount = reportCount.ToString(),
                    BitSize = button ? "n/a" : ReadU16(cap, 18).ToString(),
                    LogicalRange = logicalRange,
                    Status = "ok"
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static Capability[] Enumerate(string vendorId, string productId)
    {
        Guid hidGuid;
        HidD_GetHidGuid(out hidGuid);
        IntPtr set = SetupDiGetClassDevsW(ref hidGuid, IntPtr.Zero, IntPtr.Zero,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == new IntPtr(-1))
            throw new InvalidOperationException("SetupDiGetClassDevs failed: " + Marshal.GetLastWin32Error());

        var rows = new List<Capability>();
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

                    using (SafeFileHandle handle = CreateFile(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
                    {
                        if (handle == null || handle.IsInvalid)
                        {
                            rows.Add(new Capability { Interface = label, Status = "open failed Win32 " + Marshal.GetLastWin32Error() });
                            continue;
                        }

                        IntPtr preparsed;
                        if (!HidD_GetPreparsedData(handle, out preparsed))
                        {
                            rows.Add(new Capability { Interface = label, Status = "HidD_GetPreparsedData Win32 " + Marshal.GetLastWin32Error() });
                            continue;
                        }

                        try
                        {
                            var caps = new HIDP_CAPS();
                            int status = HidP_GetCaps(preparsed, ref caps);
                            if (status != HIDP_STATUS_SUCCESS)
                            {
                                rows.Add(new Capability { Interface = label, Status = "HidP_GetCaps status 0x" + status.ToString("X8") });
                                continue;
                            }

                            AddCaps(rows, label, "input", HIDP_INPUT, caps.NumberInputButtonCaps, true, preparsed);
                            AddCaps(rows, label, "input", HIDP_INPUT, caps.NumberInputValueCaps, false, preparsed);
                            AddCaps(rows, label, "output", HIDP_OUTPUT, caps.NumberOutputButtonCaps, true, preparsed);
                            AddCaps(rows, label, "output", HIDP_OUTPUT, caps.NumberOutputValueCaps, false, preparsed);
                            AddCaps(rows, label, "feature", HIDP_FEATURE, caps.NumberFeatureButtonCaps, true, preparsed);
                            AddCaps(rows, label, "feature", HIDP_FEATURE, caps.NumberFeatureValueCaps, false, preparsed);
                        }
                        finally
                        {
                            HidD_FreePreparsedData(preparsed);
                        }
                    }
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

if (-not ('RkReadOnlyHidCapabilities' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

[RkReadOnlyHidCapabilities]::Enumerate($VendorId, $ProductId) |
    Sort-Object Interface, ReportType, Kind, ReportId, UsagePage, Usage |
    Format-List Interface, ReportType, Kind, ReportId, UsagePage, Usage,
        LinkCollection, LinkUsagePage, LinkUsage, ReportCount, BitSize, LogicalRange, Status
