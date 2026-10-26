using System;
using System.Collections.Generic;

namespace RkRebuild
{
    // Static evidence ONLY: installed DeviceDriver.exe 4.06 SHA-256
    // c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6.
    // Ordinary entry 0x411900; firmware-2 entry 0x411700. No transport/OS APIs.
    internal enum LightingPacketLayout { Ordinary, Firmware2 }

    // Canonical R(i) = config+0x2140+0x30*i; brightness is R+4 = config+0x2144.
    // Neutral offset names deliberately avoid attributing unproved UI meanings.
    internal readonly record struct LightingPacketRow(uint Field00, uint Field04, uint Field0C, uint Field2C);

    internal sealed class LightingPacketInputs
    {
        public LightingPacketLayout Layout { get; init; }
        public int RowCount { get; init; }
        public byte SelectedOrdinal { get; init; }
        public uint LedMask { get; init; }
        public uint ApplyFlags { get; init; }
        public int GaoshouIndex { get; init; } = 1;
        public int RgbOffIndex { get; init; } = -1;
        public byte Field25C0 { get; init; }
        public byte Field3E02 { get; init; }
        public uint Field3E04 { get; init; }
        public uint Field3E08 { get; init; }
        public int Field3E14 { get; init; }
        public byte Field3E20 { get; init; }
        public uint DebounceGate { get; init; }
    }

    internal readonly record struct LightingPacketWrite(int Offset, byte Before, byte After, string Source);
    internal readonly record struct LightingPacketCollision(int Offset, int PreviousWrite, int OverwritingWrite);
    internal readonly record struct LightingPacketChange(int Offset, byte Before, byte After, int FinalWrite);

    internal sealed class LightingPacketResult
    {
        public byte[] Bytes { get; }
        public IReadOnlyList<LightingPacketWrite> Writes { get; }
        public IReadOnlyList<LightingPacketCollision> Collisions { get; }
        public IReadOnlyList<LightingPacketChange> Changes { get; }

        internal LightingPacketResult(byte[] bytes, List<LightingPacketWrite> writes,
            List<LightingPacketCollision> collisions, List<LightingPacketChange> changes)
        {
            Bytes = bytes;
            Writes = writes.AsReadOnly();
            Collisions = collisions.AsReadOnly();
            Changes = changes.AsReadOnly();
        }
    }

    internal static class LightingPacketCodec
    {
        public const int PacketBytes = 128;
        public const string SourceSha256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6";

        // Explicit tables are already-parsed profile state, not raw LedOpt/INI text.
        // resetItems is exactly the THREE byte pairs consumed, not the entire parser buffer.
        // No implicit default tables, profile inference, signature generation or sending.
        public static LightingPacketResult Patch(ReadOnlySpan<byte> seed, LightingPacketInputs input,
            ReadOnlySpan<LightingPacketRow> rows, ReadOnlySpan<uint> mappings,
            ReadOnlySpan<byte> lightHw, ReadOnlySpan<byte> debounceHw, ReadOnlySpan<byte> resetItems)
        {
            if (seed.Length != PacketBytes) throw new ArgumentException("Seed must contain exactly 128 bytes.", nameof(seed));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (input.Layout != LightingPacketLayout.Ordinary && input.Layout != LightingPacketLayout.Firmware2)
                throw new ArgumentOutOfRangeException(nameof(input.Layout));
            if (input.RowCount < 0 || input.RowCount > 24 || input.RowCount > rows.Length)
                throw new ArgumentOutOfRangeException(nameof(input.RowCount));
            if (input.SelectedOrdinal >= 24) throw new ArgumentOutOfRangeException(nameof(input.SelectedOrdinal));
            if (resetItems.Length != 6) throw new ArgumentException("Supply exactly three reset pairs.", nameof(resetItems));

            var plan = new List<(int Offset, byte Value, string Source)>();
            void Put(ulong offset, byte value, string source)
            {
                if (offset >= PacketBytes) throw new ArgumentOutOfRangeException(nameof(offset), "Planned write is outside the seed: " + source);
                plan.Add(((int)offset, value, source));
            }

            // ResetItem overlay first. Gate examines only the first FOUR bytes.
            // 0x41173B-0x41178F / 0x411960-0x4119AF. Ordinary packing may overwrite it.
            if ((input.ApplyFlags & 0x10) != 0 && (resetItems[0] | resetItems[1] | resetItems[2] | resetItems[3]) != 0)
                for (int pair = 0; pair < 3; pair++)
                {
                    byte offset = resetItems[2 * pair], value = resetItems[2 * pair + 1];
                    if (offset != 0 || value != 0) Put(offset, value, "ResetItem pair " + pair + " @0x411786/0x4119A6");
                }

            int selected = input.SelectedOrdinal;
            bool ordinary = input.Layout == LightingPacketLayout.Ordinary;
            bool mapped = false;
            if (ordinary)
            {
                // 0x41191C-0x411937 sums M(0)..M(14), NOT all 24; signed JLE.
                if (mappings.Length < 15) throw new ArgumentException("Ordinary layout needs the first 15 mapping cells.", nameof(mappings));
                uint sum = 0;
                for (int i = 0; i < 15; i++) sum = unchecked(sum + mappings[i]);
                mapped = unchecked((int)sum) > 0;
                uint mode = mapped ? Mapping(mappings, selected) : (uint)(selected + 1);
                Put(9, (byte)(selected == input.GaoshouIndex ? 1 : 0), "selected==GaoshouIndex @0x4119C6");
                Put(10, unchecked((byte)mode), "selected mapping/fallback @0x4119D8");
                if (selected == input.RgbOffIndex) Put(10, 0, "RGBOFFIndex override @0x4119E3");
                Put(11, unchecked((byte)(input.Field25C0 + 0x20)), "config+0x25C0 + 0x20 @0x4119EF");
                Put(0x39, 0xFF, "pair initialization @0x4119F4");
                Put(0x38, 0xFF, "pair initialization @0x4119F7");
            }
            else
            {
                Put(0x21, unchecked((byte)Mapping(mappings, selected)), "selected mapping @0x41179B");
                if (selected == input.RgbOffIndex) Put(0x21, 0, "RGBOFFIndex override @0x4117A6");
            }

            for (int i = 0; i < input.RowCount; i++)
            {
                if ((input.LedMask & (1u << i)) != 0) continue;
                uint m = (!ordinary || mapped) ? Mapping(mappings, i) : 0;
                if (!ordinary && m == 0) continue; // 0x4117E5-0x4117E7; NOT an ordinary gate.
                LightingPacketRow row = rows[i];
                byte brightness = Lookup(lightHw, row.Field04, nameof(lightHw));
                byte q = row.Field2C != 0 ? (byte)7 : unchecked((byte)row.Field0C);
                byte high = (byte)(row.Field00 & 15);
                byte packed = (byte)((high << 4) | (q & 15));
                ulong destination = ordinary ? (mapped ? 0x38UL + 2UL * m : 0x3AUL + 2UL * (uint)i) : 0x53UL + 2UL * m;
                string source = "row " + i + (ordinary ? " @0x411A57/0x411A65" : " @0x411820/0x411818");
                if (ordinary)
                {
                    Put(destination, brightness, source + " LightHW[record+4]");
                    Put(destination + 1, packed, source + " record+0/record+0x0C/record+0x2C");
                }
                else
                {
                    // Native order: packed byte first, brightness second.
                    Put(destination + 1, packed, source + " record+0/record+0x0C/record+0x2C");
                    Put(destination, brightness, source + " LightHW[record+4]");
                    // 0x411824 compares LOOP i with M(i), NOT selected ordinal.
                    if ((uint)i == m)
                    {
                        Put(0x22, q, "row " + i + " i==M(i), low8(q) @0x41182C");
                        Put(0x23, brightness, "row " + i + " i==M(i), LightHW @0x41182F");
                        Put(0x24, high, "row " + i + " i==M(i), low nibble @0x411832");
                    }
                }
            }

            // Outside mask loop; may collide with an ordinary row byte.
            if (ordinary && selected == input.GaoshouIndex)
            {
                if (selected >= rows.Length) throw new ArgumentException("Selected special row is unavailable.", nameof(rows));
                Put(0x5E, Lookup(lightHw, rows[selected].Field04, nameof(lightHw)), "selected special LightHW @0x411AA8");
            }
            if (input.DebounceGate != 0)
            {
                byte value = Lookup(debounceHw, input.Field3E02, nameof(debounceHw));
                Put(3, value, ordinary ? "DebounceHW @0x411AC1" : "DebounceHW @0x411872");
                if (!ordinary) Put(2, value, "DebounceHW @0x411875");
            }
            Put(ordinary ? 0x16UL : 8UL, input.Field3E04 != 0 ? (byte)0 : unchecked((byte)input.Field3E08),
                "config+0x3E04/+0x3E08 @0x411AD7/0x41188B");
            if (input.Field3E14 >= 1 && input.Field3E14 <= 5)
            {
                byte[] values = { 10, 20, 40, 60, 0 };
                Put(ordinary ? 0x18UL : 9UL, values[input.Field3E14 - 1], "config+0x3E14 translation @0x411B07/0x4118BB");
            }
            if (ordinary) Put(0x1B, (byte)(input.Field3E20 == 0 ? 1 : 0), "config+0x3E20==0 @0x411B19");
            else Put(5, 0, "constant @0x4118D1");

            // ALL source lookups and destination validation have finished before clone/mutation.
            byte[] bytes = seed.ToArray();
            var writes = new List<LightingPacketWrite>();
            var collisions = new List<LightingPacketCollision>();
            int[] last = new int[PacketBytes];
            Array.Fill(last, -1);
            foreach (var write in plan)
            {
                int index = writes.Count;
                if (last[write.Offset] >= 0) collisions.Add(new LightingPacketCollision(write.Offset, last[write.Offset], index));
                writes.Add(new LightingPacketWrite(write.Offset, bytes[write.Offset], write.Value, write.Source));
                bytes[write.Offset] = write.Value;
                last[write.Offset] = index;
            }
            var changes = new List<LightingPacketChange>();
            for (int i = 0; i < PacketBytes; i++)
                if (bytes[i] != seed[i]) changes.Add(new LightingPacketChange(i, seed[i], bytes[i], last[i]));
            return new LightingPacketResult(bytes, writes, collisions, changes);
        }

        private static uint Mapping(ReadOnlySpan<uint> mappings, int index)
        {
            if ((uint)index >= (uint)mappings.Length) throw new ArgumentException("Accessed mapping cell is unavailable.", nameof(mappings));
            return mappings[index];
        }

        private static byte Lookup(ReadOnlySpan<byte> table, uint index, string name)
        {
            if (index >= (uint)table.Length) throw new ArgumentException("Accessed source-table index is unavailable.", name);
            return table[(int)index];
        }
    }
}
