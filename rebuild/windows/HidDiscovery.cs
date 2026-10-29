using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace RkRebuild
{
    // DevicePath is an opaque selection token. Do not display, log, export, or parse it:
    // Windows instance paths may contain device-specific identifying information.
    internal sealed class HidEndpoint
    {
        public string VendorId { get; }
        public string ProductId { get; }
        public string UsagePage { get; }
        public string Usage { get; }
        public ushort VersionNumber { get; }
        public int InputReportBytes { get; }
        public int OutputReportBytes { get; }
        public int FeatureReportBytes { get; }
        public string DevicePath { get; }
        public string Error { get; }

        internal HidEndpoint(string path, WindowsHidDiscovery.HiddAttributes? attributes,
            WindowsHidDiscovery.HidpCaps? caps, string error)
        {
            DevicePath = path;
            VendorId = attributes.HasValue ? WindowsHidDiscovery.FormatId(attributes.Value.VendorID) : "";
            ProductId = attributes.HasValue ? WindowsHidDiscovery.FormatId(attributes.Value.ProductID) : "";
            VersionNumber = attributes.HasValue ? attributes.Value.VersionNumber : (ushort)0;
            UsagePage = caps.HasValue ? WindowsHidDiscovery.FormatId(caps.Value.UsagePage) : "";
            Usage = caps.HasValue ? WindowsHidDiscovery.FormatId(caps.Value.Usage) : "";
            InputReportBytes = caps.HasValue ? caps.Value.InputReportByteLength : 0;
            OutputReportBytes = caps.HasValue ? caps.Value.OutputReportByteLength : 0;
            FeatureReportBytes = caps.HasValue ? caps.Value.FeatureReportByteLength : 0;
            Error = error ?? "";
        }
    }

    internal sealed class HidDiscoveryResult
    {
        public IReadOnlyList<HidEndpoint> Endpoints { get; }
        // True only if enumeration reached its natural end and every interface
        // path was obtained. Individual metadata failures are reported separately.
        public bool EnumerationComplete { get; }
        // Messages identify only interface indices and native error codes, never paths.
        public IReadOnlyList<string> Errors { get; }

        internal HidDiscoveryResult(List<HidEndpoint> endpoints, List<string> errors, bool enumerationComplete)
        {
            Endpoints = new List<HidEndpoint>(endpoints).AsReadOnly();
            Errors = new List<string>(errors).AsReadOnly();
            EnumerationComplete = enumerationComplete;
        }

        internal void RequireCompleteEnumerationForIdentity(string vendor, string product)
        {
            if (!EnumerationComplete)
                throw new InvalidOperationException("HID discovery is incomplete for this identity; no query was sent.");
            foreach (HidEndpoint endpoint in Endpoints)
                if (endpoint.VendorId.Equals(vendor, StringComparison.OrdinalIgnoreCase)
                    && endpoint.ProductId.Equals(product, StringComparison.OrdinalIgnoreCase)
                    && !String.IsNullOrEmpty(endpoint.Error))
                    throw new InvalidOperationException("HID metadata is incomplete for this identity; no query was sent.");
        }
    }

    internal static class WindowsHidDiscovery
    {
        internal const int MaximumInterfaces = 1024;
        private const int MaximumDetailBytes = 65536;
        private const int ErrorNoMoreItems = 259;
        private const int ErrorInsufficientBuffer = 122;
        private const int HidpStatusSuccess = 0x00110000;

        // Only SetupAPI and HID metadata calls are used. No input reports, serial
        // strings, feature reports, output reports, or protocol commands are requested.
        // Cancellation throws OperationCanceledException; finally/using release all resources.
        public static HidDiscoveryResult Enumerate(int maxInterfaces = MaximumInterfaces,
            CancellationToken cancellationToken = default)
        {
            if (maxInterfaces < 1 || maxInterfaces > MaximumInterfaces)
                throw new ArgumentOutOfRangeException(nameof(maxInterfaces), "Must be between 1 and 1024.");
            cancellationToken.ThrowIfCancellationRequested();
            var endpoints = new List<HidEndpoint>();
            var errors = new List<string>();
            bool enumerationComplete = false;
            bool allPathsRead = true;
            if (!OperatingSystem.IsWindows())
            {
                errors.Add("HID metadata discovery requires Windows.");
                return new HidDiscoveryResult(endpoints, errors, false);
            }

            try
            {
                HidD_GetHidGuid(out Guid hidGuid);
                using SafeDeviceInfoSet devices = SetupDiGetClassDevsW(ref hidGuid, IntPtr.Zero,
                    IntPtr.Zero, 0x00000002 | 0x00000010); // PRESENT | DEVICEINTERFACE
                if (devices.IsInvalid)
                {
                    errors.Add(Win32Error("SetupDiGetClassDevs", Marshal.GetLastWin32Error()));
                    return new HidDiscoveryResult(endpoints, errors, false);
                }

                // One extra enumeration probe detects truncation without opening another path.
                for (uint index = 0; index <= (uint)maxInterfaces; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var data = new SpDeviceInterfaceData { CbSize = (uint)Marshal.SizeOf<SpDeviceInterfaceData>() };
                    if (!SetupDiEnumDeviceInterfaces(devices, IntPtr.Zero, ref hidGuid, index, ref data))
                    {
                        int code = Marshal.GetLastWin32Error();
                        if (code != ErrorNoMoreItems)
                            errors.Add("Interface " + index + ": " + Win32Error("SetupDiEnumDeviceInterfaces", code));
                        else enumerationComplete = allPathsRead;
                        // A failed enum call cannot safely establish a usable interface or the next index.
                        break;
                    }
                    if (index == (uint)maxInterfaces)
                    {
                        errors.Add("HID interface limit reached (" + maxInterfaces + "); results are incomplete.");
                        break;
                    }

                    string path = ReadPath(devices, ref data, out string pathError);
                    if (path == null)
                    {
                        allPathsRead = false;
                        errors.Add("Interface " + index + ": " + pathError);
                        continue;
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    HidEndpoint endpoint = ReadEndpoint(path, cancellationToken);
                    endpoints.Add(endpoint);
                    if (endpoint.Error.Length != 0)
                        errors.Add("Interface " + index + ": " + endpoint.Error);
                }
            }
            catch (DllNotFoundException)
            {
                enumerationComplete = false;
                errors.Add("Windows HID metadata libraries are unavailable.");
            }
            catch (EntryPointNotFoundException)
            {
                enumerationComplete = false;
                errors.Add("A required Windows HID metadata entry point is unavailable.");
            }
            catch (BadImageFormatException)
            {
                enumerationComplete = false;
                errors.Add("Windows HID metadata libraries could not be loaded for this architecture.");
            }
            return new HidDiscoveryResult(endpoints, errors, enumerationComplete);
        }

        internal static string FormatId(ushort value) => value.ToString("X4", CultureInfo.InvariantCulture);

        // SP_DEVICE_INTERFACE_DETAIL_DATA_W's sizeof is 6 on x86 and 8 on x64,
        // but DevicePath ALWAYS starts at byte 4, not at cbSize.
        internal static int DetailCbSize(int pointerSize)
        {
            if (pointerSize == 4) return 6;
            if (pointerSize == 8) return 8;
            throw new ArgumentOutOfRangeException(nameof(pointerSize));
        }
        internal const int DetailPathOffset = 4;

        private static string ReadPath(SafeDeviceInfoSet devices, ref SpDeviceInterfaceData data, out string error)
        {
            error = "";
            bool sized = SetupDiGetDeviceInterfaceDetailW(devices, ref data, IntPtr.Zero, 0,
                out uint required, IntPtr.Zero);
            int code = Marshal.GetLastWin32Error();
            if (sized || code != ErrorInsufficientBuffer)
            {
                error = Win32Error("SetupDiGetDeviceInterfaceDetail(size)", code);
                return null;
            }
            if (required < DetailCbSize(IntPtr.Size) || required > MaximumDetailBytes || (required & 1) != 0)
            {
                error = "Invalid or excessive HID interface detail size.";
                return null;
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)required);
            try
            {
                // Zero the bounded buffer so malformed native results cannot expose uninitialized bytes.
                Marshal.Copy(new byte[(int)required], 0, buffer, (int)required);
                Marshal.WriteInt32(buffer, DetailCbSize(IntPtr.Size));
                if (!SetupDiGetDeviceInterfaceDetailW(devices, ref data, buffer, required,
                    out uint returned, IntPtr.Zero))
                {
                    error = Win32Error("SetupDiGetDeviceInterfaceDetail", Marshal.GetLastWin32Error());
                    return null;
                }
                if (returned > required || returned < DetailPathOffset + 2 || (returned & 1) != 0)
                {
                    error = "Invalid HID interface detail length.";
                    return null;
                }
                int characters = ((int)returned - DetailPathOffset) / 2;
                int length = 0;
                while (length < characters && Marshal.ReadInt16(buffer, DetailPathOffset + length * 2) != 0)
                    length++;
                if (length == 0 || length == characters)
                {
                    error = "Empty or unterminated HID interface path.";
                    return null;
                }
                return Marshal.PtrToStringUni(IntPtr.Add(buffer, DetailPathOffset), length);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static HidEndpoint ReadEndpoint(string path, CancellationToken cancellationToken)
        {
            // desiredAccess=0 deliberately permits metadata inspection of keyboard collections
            // that Windows reserves exclusively for the input stack.
            using SafeFileHandle handle = CreateFileW(path, 0, 0x00000001 | 0x00000002,
                IntPtr.Zero, 3, 0, IntPtr.Zero); // SHARE_READ | SHARE_WRITE, OPEN_EXISTING
            if (handle.IsInvalid)
                return new HidEndpoint(path, null, null, Win32Error("CreateFile(metadata)", Marshal.GetLastWin32Error()));

            var failures = new List<string>();
            HiddAttributes? attributes = null;
            HidpCaps? caps = null;
            var nativeAttributes = new HiddAttributes { Size = (uint)Marshal.SizeOf<HiddAttributes>() };
            if (HidD_GetAttributes(handle, ref nativeAttributes)) attributes = nativeAttributes;
            else failures.Add(Win32Error("HidD_GetAttributes", Marshal.GetLastWin32Error()));
            cancellationToken.ThrowIfCancellationRequested();

            if (HidD_GetPreparsedData(handle, out SafePreparsedData preparsed))
            {
                using (preparsed)
                {
                    if (preparsed == null || preparsed.IsInvalid)
                        failures.Add("HidD_GetPreparsedData returned an invalid metadata handle.");
                    else
                    {
                        int status = HidP_GetCaps(preparsed, out HidpCaps nativeCaps);
                        if (status == HidpStatusSuccess) caps = nativeCaps;
                        else failures.Add("HidP_GetCaps failed (NTSTATUS 0x" + status.ToString("X8", CultureInfo.InvariantCulture) + ").");
                    }
                }
            }
            else
            {
                int code = Marshal.GetLastWin32Error();
                preparsed?.Dispose();
                failures.Add(Win32Error("HidD_GetPreparsedData", code));
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new HidEndpoint(path, attributes, caps, string.Join(" ", failures));
        }

        private static string Win32Error(string operation, int code) =>
            operation + " failed (Win32 " + code.ToString(CultureInfo.InvariantCulture) + ").";

        [StructLayout(LayoutKind.Sequential)]
        internal struct SpDeviceInterfaceData
        {
            internal uint CbSize;
            internal Guid InterfaceClassGuid;
            internal uint Flags;
            internal UIntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct HiddAttributes
        {
            internal uint Size;
            internal ushort VendorID;
            internal ushort ProductID;
            internal ushort VersionNumber;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct HidpCaps
        {
            internal ushort Usage;
            internal ushort UsagePage;
            internal ushort InputReportByteLength;
            internal ushort OutputReportByteLength;
            internal ushort FeatureReportByteLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
            internal ushort[] Reserved;
            internal ushort NumberLinkCollectionNodes;
            internal ushort NumberInputButtonCaps;
            internal ushort NumberInputValueCaps;
            internal ushort NumberInputDataIndices;
            internal ushort NumberOutputButtonCaps;
            internal ushort NumberOutputValueCaps;
            internal ushort NumberOutputDataIndices;
            internal ushort NumberFeatureButtonCaps;
            internal ushort NumberFeatureValueCaps;
            internal ushort NumberFeatureDataIndices;
        }

        private sealed class SafeDeviceInfoSet : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeDeviceInfoSet() : base(true) { }
            protected override bool ReleaseHandle() => SetupDiDestroyDeviceInfoList(handle);
        }

        private sealed class SafePreparsedData : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafePreparsedData() : base(true) { }
            protected override bool ReleaseHandle() => HidD_FreePreparsedData(handle);
        }

        [DllImport("hid.dll", ExactSpelling = true)]
        private static extern void HidD_GetHidGuid(out Guid guid);
        [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
        private static extern SafeDeviceInfoSet SetupDiGetClassDevsW(ref Guid guid, IntPtr enumerator, IntPtr parent, uint flags);
        [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiEnumDeviceInterfaces(SafeDeviceInfoSet devices, IntPtr device,
            ref Guid guid, uint index, ref SpDeviceInterfaceData data);
        [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceInterfaceDetailW(SafeDeviceInfoSet devices,
            ref SpDeviceInterfaceData data, IntPtr detail, uint size, out uint required, IntPtr device);
        [DllImport("setupapi.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr devices);
        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("hid.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_GetAttributes(SafeFileHandle handle, ref HiddAttributes attributes);
        [DllImport("hid.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_GetPreparsedData(SafeFileHandle handle, out SafePreparsedData data);
        [DllImport("hid.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool HidD_FreePreparsedData(IntPtr data);
        [DllImport("hid.dll", ExactSpelling = true)]
        private static extern int HidP_GetCaps(SafePreparsedData data, out HidpCaps caps);
    }
}
