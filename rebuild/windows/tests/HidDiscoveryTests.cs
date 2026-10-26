using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using RkRebuild;

internal static class HidDiscoveryTests
{
    private static int assertions;
    private static void Check(bool value, string message)
    {
        assertions++;
        if (!value) throw new Exception(message);
    }
    private static void Offset<T>(string field, int expected) =>
        Check(Marshal.OffsetOf<T>(field).ToInt32() == expected, typeof(T).Name + "." + field);
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }

    private static int Main(string[] args)
    {
        Check(Marshal.SizeOf<WindowsHidDiscovery.SpDeviceInterfaceData>() == (IntPtr.Size == 8 ? 32 : 28), "SP_DEVICE_INTERFACE_DATA size");
        Offset<WindowsHidDiscovery.SpDeviceInterfaceData>("CbSize", 0);
        Offset<WindowsHidDiscovery.SpDeviceInterfaceData>("InterfaceClassGuid", 4);
        Offset<WindowsHidDiscovery.SpDeviceInterfaceData>("Flags", 20);
        Offset<WindowsHidDiscovery.SpDeviceInterfaceData>("Reserved", 24);
        Check(Marshal.SizeOf<WindowsHidDiscovery.HiddAttributes>() == 12, "HIDD_ATTRIBUTES size incl trailing alignment");
        Offset<WindowsHidDiscovery.HiddAttributes>("Size", 0);
        Offset<WindowsHidDiscovery.HiddAttributes>("VendorID", 4);
        Offset<WindowsHidDiscovery.HiddAttributes>("ProductID", 6);
        Offset<WindowsHidDiscovery.HiddAttributes>("VersionNumber", 8);
        Check(Marshal.SizeOf<WindowsHidDiscovery.HidpCaps>() == 64, "HIDP_CAPS size");
        string[] capFields = { "Usage", "UsagePage", "InputReportByteLength", "OutputReportByteLength", "FeatureReportByteLength", "Reserved" };
        for (int i = 0; i < capFields.Length; i++) Offset<WindowsHidDiscovery.HidpCaps>(capFields[i], i * 2);
        string[] countFields = { "NumberLinkCollectionNodes", "NumberInputButtonCaps", "NumberInputValueCaps", "NumberInputDataIndices", "NumberOutputButtonCaps", "NumberOutputValueCaps", "NumberOutputDataIndices", "NumberFeatureButtonCaps", "NumberFeatureValueCaps", "NumberFeatureDataIndices" };
        for (int i = 0; i < countFields.Length; i++) Offset<WindowsHidDiscovery.HidpCaps>(countFields[i], 44 + i * 2);
        Check(WindowsHidDiscovery.DetailCbSize(4) == 6, "x86 Unicode cbSize");
        Check(WindowsHidDiscovery.DetailCbSize(8) == 8, "x64 Unicode cbSize");
        Check(WindowsHidDiscovery.DetailPathOffset == 4, "path offset does not equal x64 cbSize");
        Throws<ArgumentOutOfRangeException>(() => WindowsHidDiscovery.DetailCbSize(16));

        CultureInfo previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            Check(WindowsHidDiscovery.FormatId(0) == "0000", "zero ID");
            Check(WindowsHidDiscovery.FormatId(0xab) == "00AB", "padded upper-case ID");
            Check(WindowsHidDiscovery.FormatId(ushort.MaxValue) == "FFFF", "maximum ID");
        }
        finally { CultureInfo.CurrentCulture = previous; }

        var attributes = new WindowsHidDiscovery.HiddAttributes { VendorID = 0x258a, ProductID = 0x00ab, VersionNumber = 0x1234 };
        var caps = new WindowsHidDiscovery.HidpCaps { UsagePage = 0xff00, Usage = 1, InputReportByteLength = 65, OutputReportByteLength = 33, FeatureReportByteLength = 257 };
        var endpoint = new HidEndpoint("opaque-token", attributes, caps, "");
        Check(endpoint.VendorId == "258A" && endpoint.ProductId == "00AB", "canonical endpoint IDs");
        Check(endpoint.UsagePage == "FF00" && endpoint.Usage == "0001", "canonical endpoint usages");
        Check(endpoint.VersionNumber == 0x1234, "version preserved");
        Check(endpoint.InputReportBytes == 65 && endpoint.OutputReportBytes == 33 && endpoint.FeatureReportBytes == 257, "report lengths preserved including report ID byte");
        Check(endpoint.DevicePath == "opaque-token" && endpoint.Error == "", "opaque token, success");
        var failed = new HidEndpoint("opaque-token", null, null, "access denied");
        Check(failed.VendorId == "" && failed.ProductId == "" && failed.UsagePage == "" && failed.Usage == "", "unknown identity never fabricated");
        Check(failed.InputReportBytes == 0 && failed.OutputReportBytes == 0 && failed.FeatureReportBytes == 0 && failed.VersionNumber == 0, "unavailable numeric metadata");
        Check(failed.Error == "access denied", "per-interface failure retained");
        var partial = new HidEndpoint("opaque-token", attributes, null, "caps failed");
        Check(partial.VendorId == "258A" && partial.UsagePage == "" && partial.Error != "", "partial metadata retained explicitly");
        foreach (PropertyInfo property in typeof(HidEndpoint).GetProperties())
            Check(property.SetMethod == null, "immutable endpoint " + property.Name);
        var endpoints = new List<HidEndpoint> { endpoint };
        var errors = new List<string> { "failure" };
        var result = new HidDiscoveryResult(endpoints, errors);
        endpoints.Clear(); errors.Clear();
        Check(result.Endpoints.Count == 1 && result.Errors.Count == 1, "result takes defensive snapshots");
        Throws<NotSupportedException>(() => ((IList<HidEndpoint>)result.Endpoints).Add(failed));
        Throws<NotSupportedException>(() => ((IList<string>)result.Errors).Add("change"));
        Throws<ArgumentOutOfRangeException>(() => WindowsHidDiscovery.Enumerate(0));
        Throws<ArgumentOutOfRangeException>(() => WindowsHidDiscovery.Enumerate(-1));
        Throws<ArgumentOutOfRangeException>(() => WindowsHidDiscovery.Enumerate(1025));
        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            Throws<OperationCanceledException>(() => WindowsHidDiscovery.Enumerate(cancellationToken: cancellation.Token));
        }

        // Ensure the native surface stays metadata-only, with no serial/string APIs or I/O.
        var allowed = new HashSet<string> { "HidD_GetHidGuid", "SetupDiGetClassDevsW", "SetupDiEnumDeviceInterfaces", "SetupDiGetDeviceInterfaceDetailW", "SetupDiDestroyDeviceInfoList", "CreateFileW", "HidD_GetAttributes", "HidD_GetPreparsedData", "HidD_FreePreparsedData", "HidP_GetCaps" };
        int imports = 0;
        foreach (MethodInfo method in typeof(WindowsHidDiscovery).GetMethods(BindingFlags.Static | BindingFlags.NonPublic))
        {
            var import = method.GetCustomAttribute<DllImportAttribute>();
            if (import == null) continue;
            imports++;
            Check(allowed.Contains(import.EntryPoint), "metadata-only native import " + import.EntryPoint);
        }
        Check(imports == allowed.Count, "expected native surface");

        if (Array.IndexOf(args, "--enumerate") >= 0)
        {
            HidDiscoveryResult live = WindowsHidDiscovery.Enumerate();
            Console.WriteLine("Metadata-only runtime enumeration: " + live.Endpoints.Count + " endpoints, " + live.Errors.Count + " errors.");
            foreach (HidEndpoint entry in live.Endpoints)
            {
                Check(!string.IsNullOrEmpty(entry.DevicePath), "discovered path exists");
                // Do not print paths, serials, or any device-specific strings.
                Console.WriteLine("VID=" + entry.VendorId + " PID=" + entry.ProductId + " UsagePage=" + entry.UsagePage + " Usage=" + entry.Usage + " Reports=" + entry.InputReportBytes + "/" + entry.OutputReportBytes + "/" + entry.FeatureReportBytes + " Error=" + entry.Error);
            }
            foreach (string error in live.Errors) Console.WriteLine(error);
        }
        Console.WriteLine("PASS HID discovery: " + assertions + " assertions (" + (IntPtr.Size * 8) + "-bit process).");
        return 0;
    }
}
