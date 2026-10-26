using System;
using System.Collections.Generic;

namespace RkRebuild
{
    // Pure, offline framing only. Deliberately has no HID/serial/OS handles or send API.
    // Installed 4.06 c03f88...: FUN_0040D7E0, FUN_0040D2E0, FUN_0040D370.
    // Physical model/revision compatibility and command payload meanings are unknown.
    internal enum Rk3632ResponseKind { Match, CommandMismatch, StatusEvent, DisconnectMarker, DeviceErrorFlag }

    internal static class Rk3632Codec
    {
        public const int FrameBytes = 20;
        public const int PayloadBytes = 14;
        public const int MaxRequestBytes = 512;

        public static byte[][] EncodeRequest(byte command, int option, ReadOnlySpan<byte> payload)
        {
            // 0x0040D80D-0x0040D816 checks unsigned (length-1) <= 0x1FF.
            if (payload.Length < 1 || payload.Length > MaxRequestBytes)
                throw new ArgumentOutOfRangeException(nameof(payload), "A native 3632 request contains 1–512 bytes.");
            // Native shifts a byte; reject truncating option values rather than silently wrapping.
            if (option < 0 || option > 15) throw new ArgumentOutOfRangeException(nameof(option));
            int count = (payload.Length + PayloadBytes - 1) / PayloadBytes;
            byte[][] frames = new byte[count][];
            for (int index = 0; index < count; index++)
            {
                int offset = index * PayloadBytes;
                int size = Math.Min(PayloadBytes, payload.Length - offset);
                byte[] frame = new byte[FrameBytes];
                frame[0] = 0x13;
                frame[1] = command;
                frame[2] = checked((byte)count);
                frame[3] = checked((byte)index);
                frame[4] = (byte)((option << 4) | size);
                payload.Slice(offset, size).CopyTo(frame.AsSpan(5, size));
                int checksum = 0;
                for (int i = 0; i < FrameBytes - 1; i++) checksum += frame[i];
                frame[19] = unchecked((byte)checksum);
                frames[index] = frame;
            }
            return frames;
        }

        public static bool RequiresResponse(byte command)
        {
            // 0x0040D970-0x0040D977 skips the queue wait for high-bit commands and 6.
            return (command & 0x80) == 0 && command != 6;
        }

        public static Rk3632ResponseKind InspectResponse(ReadOnlySpan<byte> frame, byte requestedCommand)
        {
            if (frame.Length != FrameBytes) throw new ArgumentException("Expected exactly 20 recorded bytes.", nameof(frame));
            // The dispatcher diverts status events before the ordinary response queue.
            if (frame[1] == 0x0A) return Rk3632ResponseKind.StatusEvent;
            if (frame[0] == 0xFF) return Rk3632ResponseKind.DisconnectMarker;
            if ((frame[2] & 0x80) != 0) return Rk3632ResponseKind.DeviceErrorFlag;
            return frame[1] == requestedCommand ? Rk3632ResponseKind.Match : Rk3632ResponseKind.CommandMismatch;
            // No invented response checksum, marker or packet-index validation: not present
            // in the documented ordinary consumer. A Match is not firmware acceptance.
        }

        public static int StatusMessageValue(ReadOnlySpan<byte> frame)
        {
            if (frame.Length != FrameBytes || frame[1] != 0x0A)
                throw new ArgumentException("Expected one 20-byte status-event record.", nameof(frame));
            return frame[5] | (frame[6] << 8) | (frame[7] << 16);
        }
    }
}
