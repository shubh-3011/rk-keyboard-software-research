using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RkRebuild
{
    internal static class G5FeatureMetadata
    {
        private const int HidpSuccess = 0x00110000;
        private const int MaximumCaps = 1024;

        public static void ValidateEndpoint(HidEndpoint endpoint)
        {
            if (endpoint == null || !String.IsNullOrEmpty(endpoint.Error) || endpoint.FeatureReportBytes != 520 ||
                endpoint.UsagePage != "FF02" || endpoint.Usage != "0002" || endpoint.OutputReportBytes != 0 ||
                endpoint.InputReportBytes > 20 || String.IsNullOrWhiteSpace(endpoint.DevicePath) || endpoint.DevicePath.Contains('\0'))
                throw new ArgumentException("Endpoint is not an eligible 520-byte G5 vendor feature interface.");
        }

        // Descriptor metadata only. Report IDs are declared by the device,
        // never probed by sending arbitrary report-ID values to the hardware.
        public static byte[] FeatureReportIds(HidEndpoint endpoint)
        {
            ValidateEndpoint(endpoint);
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("HID metadata requires Windows.");
            using SafeFileHandle handle = CreateFileW(endpoint.DevicePath, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (handle.IsInvalid) throw Error("Opening feature metadata");
            if (!HidD_GetPreparsedData(handle, out IntPtr preparsed)) throw Error("Getting preparsed feature metadata");
            try
            {
                if (HidP_GetCaps(preparsed, out WindowsHidDiscovery.HidpCaps caps) != HidpSuccess)
                    throw new IOException("HID feature capability metadata is unavailable.");
                if (caps.FeatureReportByteLength != 520 || caps.UsagePage != 0xff02 || caps.Usage != 2)
                    throw new IOException("Feature endpoint capabilities changed during discovery.");
                var ids = new HashSet<byte>();
                ReadIds(preparsed, caps.NumberFeatureValueCaps, false, ids);
                ReadIds(preparsed, caps.NumberFeatureButtonCaps, true, ids);
                if (ids.Count == 0) throw new IOException("No feature report IDs were declared; no query was sent.");
                return ids.OrderBy(value => value).ToArray();
            }
            finally { HidD_FreePreparsedData(preparsed); }
        }

        private static void ReadIds(IntPtr preparsed, ushort count, bool buttons, HashSet<byte> ids)
        {
            if (count == 0) return;
            if (count > MaximumCaps) throw new IOException("Feature capability count exceeds the metadata bound.");
            var records = new NativeCapability[count];
            ushort actual = count;
            int status = buttons ? HidP_GetButtonCaps(2, records, ref actual, preparsed) : HidP_GetValueCaps(2, records, ref actual, preparsed);
            if (status != HidpSuccess || actual > count) throw new IOException("Feature report-ID metadata could not be read completely.");
            for (int index = 0; index < actual; index++) ids.Add(records[index].ReportId);
        }

        // HIDP_BUTTON_CAPS and HIDP_VALUE_CAPS are both 72 bytes. Only their
        // shared first three bytes are interpreted; union contents are opaque.
        [StructLayout(LayoutKind.Explicit, Size = 72)]
        internal struct NativeCapability
        {
            [FieldOffset(0)] internal ushort UsagePage;
            [FieldOffset(2)] internal byte ReportId;
        }

        private static IOException Error(string operation) => new IOException(operation + " failed (Win32 " + Marshal.GetLastWin32Error() + ").");
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("hid.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_GetPreparsedData(SafeFileHandle handle, out IntPtr data);
        [DllImport("hid.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_FreePreparsedData(IntPtr data);
        [DllImport("hid.dll")]
        private static extern int HidP_GetCaps(IntPtr data, out WindowsHidDiscovery.HidpCaps caps);
        [DllImport("hid.dll")]
        private static extern int HidP_GetValueCaps(int type, [Out] NativeCapability[] caps, ref ushort length, IntPtr data);
        [DllImport("hid.dll")]
        private static extern int HidP_GetButtonCaps(int type, [Out] NativeCapability[] caps, ref ushort length, IntPtr data);
    }
}
