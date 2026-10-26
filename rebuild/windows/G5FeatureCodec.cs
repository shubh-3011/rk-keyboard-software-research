using System;

namespace RkRebuild
{
    // Offline reconstruction ONLY, installed DeviceDriver.exe 4.06 SHA-256
    // c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6.
    // True entry VA 0x40F700 (not the independent screen writer 0x412B10).
    // x86 entry: ECX=data; stack args handle, reportId, operation, command,
    // length, delay, option. Operation is host control flow, NOT a wire byte.
    // Static object-layout witnesses for a future process-local observer ONLY:
    // 0x40ECE3 installs vtable 0x5CBA2C; constructor 0x40ED2E/31 clears
    // DWORD handles +8/+4. Find/open entry 0x40F350 stores primary handle at
    // +4 (0x40F433), secondary at +8 (0x40F4A3), and BYTE report ID at
    // +0x2D0 (0x40F44A). +0x22 is the inline UTF-16 device path, copied with
    // capacity 0x104 wchar at 0x40F51E-0x40F52B (not a pointer field).
    // WORD +0x248/+0x24A receive selector WORDs +0/+2 (VID/PID order),
    // 0x40F530-0x40F546; compared in the same order at 0x40F680/0x40F694.
    // +0x250 is a fallback child-object pointer (0x40F9CD, 0x40FAFB).
    // These are hash-specific metadata offsets, not a process reader or a
    // guarantee that any live pointer/handle/path is valid or still current.
    internal static class G5FeatureCodec
    {
        public const string SourceSha256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6";
        public const int ReportBytes = 520;
        public const int PayloadBytes = 512;
        public const int MaxTransferBytes = 255 * PayloadBytes;

        // Every header byte is assigned after memset(520,0), 0x40F7ED-0x40F846:
        // [0] explicit report ID; [1] command; [2] option; [3] zero;
        // [4] ceil(totalLength/512); [5] ZERO-based packet index;
        // [6..7] this chunk's length, little endian; [8..519] payload/zero padding.
        // There is NO optional checksum, flags, or source seed in this helper.
        // Unlike screen framing, [4] is not a rolling index, [5] not checksum.
        // 0x40F726 rejects nonpositive length; 0x40F74C accepts only op 1 or 2.
        // 0x40F84A-0x40F865 copies data only for op 1 and non-null data pointer.
        // Deliberately safer local bounds: reject >255 packets instead of silently
        // truncating count/index to byte; reject a missing write chunk instead of
        // emulating the vendor's null-pointer zero-write. No HID/OS/delay/retry API.
        public static byte[] BuildRequestPacket(byte reportId, int operation, byte command,
            byte option, int totalLength, int packetIndex, ReadOnlySpan<byte> writeChunk)
        {
            if (operation != 1 && operation != 2)
                throw new ArgumentOutOfRangeException(nameof(operation));
            if (totalLength < 1 || totalLength > MaxTransferBytes)
                throw new ArgumentOutOfRangeException(nameof(totalLength));
            int count = (totalLength + PayloadBytes - 1) / PayloadBytes;
            if (packetIndex < 0 || packetIndex >= count)
                throw new ArgumentOutOfRangeException(nameof(packetIndex));
            int length = Math.Min(PayloadBytes, totalLength - packetIndex * PayloadBytes);
            if (operation == 1 ? writeChunk.Length != length : !writeChunk.IsEmpty)
                throw new ArgumentException("Op 1 needs exactly this chunk; op 2 needs an empty chunk.", nameof(writeChunk));

            var report = new byte[ReportBytes];
            report[0] = reportId;
            report[1] = command;
            report[2] = option;
            report[4] = (byte)count;
            report[5] = (byte)packetIndex;
            report[6] = (byte)length;
            report[7] = (byte)(length >> 8);
            if (operation == 1) writeChunk.CopyTo(report.AsSpan(8));
            return report;
        }

        // ONLY the vendor command predicate, 0x40F8FA-0x40F907 (op 2).
        // 0x40F909-0x40F916 copies requested chunk length from response+8.
        // Fixed report length and payload bounds here are local safety checks.
        // This is NOT ACK integrity/authenticity validation: no report ID,
        // option, status, index, count, declared response length, signature or
        // checksum checks exist at this entry. Caller must not infer otherwise.
        // Separate query entry 0x40FAD0 builds command 0x84, option 0, length
        // 128, count 1, index 0 (0x40FB8E-0x40FBAA), then compares only byte 1
        // at 0x40FC22-0x40FC28. A later caller's 5A A5 test is not transport ACK.
        public static bool MatchesVendorReadCommand(ReadOnlySpan<byte> response, byte command)
        {
            return response.Length == ReportBytes && response[1] == command;
        }

        public static byte[] CopyReadPayload(ReadOnlySpan<byte> response, byte command, int requestedLength)
        {
            if (requestedLength < 1 || requestedLength > PayloadBytes)
                throw new ArgumentOutOfRangeException(nameof(requestedLength));
            if (!MatchesVendorReadCommand(response, command))
                throw new ArgumentException("Expected a 520-byte response with matching command byte 1.", nameof(response));
            return response.Slice(8, requestedLength).ToArray();
        }
    }
}
