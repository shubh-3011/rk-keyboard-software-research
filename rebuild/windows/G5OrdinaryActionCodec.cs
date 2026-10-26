using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace RkRebuild
{
    /// <summary>An explicitly supplied 16-byte local source record, NOT device readback.</summary>
    public sealed class SourceActionDescriptor
    {
        private readonly byte[] bytes;

        public SourceActionDescriptor(ReadOnlySpan<byte> source)
        {
            if (source.Length != 16)
                throw new ArgumentException("A source action descriptor must contain exactly 16 bytes.", nameof(source));
            bytes = source.ToArray();
        }

        public byte Tag => bytes[3];
        public byte ModifierMask => bytes[8];
        public byte PrimaryNumericValue => bytes[9];
        public byte SecondaryNumericValue => bytes[10];
        public byte[] Bytes => (byte[])bytes.Clone();
    }

    /// <summary>Only the supported ordinary subset; not a general action or macro decoder.</summary>
    public sealed class G5OrdinaryAction
    {
        internal G5OrdinaryAction(SourceActionDescriptor source, byte primaryUsage, byte secondaryUsage)
        {
            SourceDescriptor = source;
            PrimaryUsage = primaryUsage;
            SecondaryUsage = secondaryUsage;
            WireValue = ((uint)primaryUsage << 24) | ((uint)secondaryUsage << 16)
                | ((uint)source.ModifierMask << 8);
        }

        public SourceActionDescriptor SourceDescriptor { get; }
        public byte PrimaryNumericValue => SourceDescriptor.PrimaryNumericValue;
        public byte SecondaryNumericValue => SourceDescriptor.SecondaryNumericValue;
        public byte ModifierMask => SourceDescriptor.ModifierMask;
        public byte PrimaryUsage { get; }
        public byte SecondaryUsage { get; }
        public uint WireValue { get; }
        public byte[] Bytes
        {
            get
            {
                var bytes = new byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(bytes, WireValue);
                return bytes;
            }
        }
    }

    public sealed class G5OrdinaryDwordChange
    {
        internal G5OrdinaryDwordChange(int slot, uint oldValue, uint newValue)
        {
            Slot = slot;
            OldWireValue = oldValue;
            NewWireValue = newValue;
        }

        public int Slot { get; }
        public int ByteOffset => Slot * 4;
        public uint OldWireValue { get; }
        public uint NewWireValue { get; }
    }

    /// <summary>Owned offline snapshots and a zero-or-one DWORD change report.</summary>
    public sealed class G5OrdinaryPatchResult
    {
        private readonly byte[] offlineSeed;
        private readonly byte[] patchedOfflineSeed;

        internal G5OrdinaryPatchResult(ReadOnlySpan<byte> seed, int capacity, int slot,
            G5OrdinaryAction oldAction, G5OrdinaryAction newAction)
        {
            offlineSeed = seed.ToArray();
            patchedOfflineSeed = seed.ToArray();
            WireCapacity = capacity;
            SelectedSlot = slot;
            OldAction = oldAction;
            NewAction = newAction;
            BinaryPrimitives.WriteUInt32LittleEndian(patchedOfflineSeed.AsSpan(slot * 4, 4), newAction.WireValue);
            var changes = new List<G5OrdinaryDwordChange>();
            if (oldAction.WireValue != newAction.WireValue)
                changes.Add(new G5OrdinaryDwordChange(slot, oldAction.WireValue, newAction.WireValue));
            Changes = new ReadOnlyCollection<G5OrdinaryDwordChange>(changes);
        }

        public int WireCapacity { get; }
        public int SelectedSlot { get; }
        public G5OrdinaryAction OldAction { get; }
        public G5OrdinaryAction NewAction { get; }
        public byte[] OfflineSeed => (byte[])offlineSeed.Clone();
        public byte[] PatchedOfflineSeed => (byte[])patchedOfflineSeed.Clone();
        public IReadOnlyList<G5OrdinaryDwordChange> Changes { get; }
    }

    /// <summary>
    /// Partial, pure OFFLINE packing/patching foundation. No transport or Apply capability.
    /// Caller supplies seed origin, slot/layer/profile metadata and capacity; none is inferred.
    /// An OfflineSeed is not device-current settings. Command-83 readback remains unproven.
    /// No implicit seed (zero-filled or otherwise), firmware/model claim, or macro maintenance.
    /// </summary>
    public static class G5OrdinaryActionCodec
    {
        // Independently authored numeric facts, not vendor source code. Statically read from
        // DeviceDriver.exe 4.06, image base 00400000, SHA-256:
        // c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6
        // 005D2FC0..005D30A4 (file 001D23C0), 114 (usage,input) pairs, SHA-256:
        // b6f313df4299451aac121648bb8759081c141bec7bb74a399f162e95574beae1
        // 00463EE0..00463F00: first matching input wins, absent => 0; SHA-256:
        // b9b102c086b39075e7a9f67045864794b0aa7cb89f305e9ce095454f81d6fef8
        // Translator 004107A0..00410F00 (including selector tables/padding), SHA-256:
        // 013d4d5440f6f5b0e672bcb82e6b0b6315e7b0d66fb32eba01629161b5bf1f9a
        // Gate witnesses: 0041084C..004108AA; packing: 00410965..004109D8.
        // See docs/rk406-g5-keymap-next-step-2026-10-27.md. Static facts, not device tests.
        private static readonly byte[] NumericPairs =
        {
            0x64, 0xE2, 0x29, 0x1B, 0x3A, 0x70, 0x3B, 0x71, 0x3C, 0x72, 0x3D, 0x73,
            0x3E, 0x74, 0x3F, 0x75, 0x40, 0x76, 0x41, 0x77, 0x42, 0x78, 0x43, 0x79,
            0x44, 0x7A, 0x45, 0x7B, 0x04, 0x41, 0x05, 0x42, 0x06, 0x43, 0x07, 0x44,
            0x08, 0x45, 0x09, 0x46, 0x0A, 0x47, 0x0B, 0x48, 0x0C, 0x49, 0x0D, 0x4A,
            0x0E, 0x4B, 0x0F, 0x4C, 0x10, 0x4D, 0x11, 0x4E, 0x12, 0x4F, 0x13, 0x50,
            0x14, 0x51, 0x15, 0x52, 0x16, 0x53, 0x17, 0x54, 0x18, 0x55, 0x19, 0x56,
            0x1A, 0x57, 0x1B, 0x58, 0x1C, 0x59, 0x1D, 0x5A, 0x1E, 0x31, 0x1F, 0x32,
            0x20, 0x33, 0x21, 0x34, 0x22, 0x35, 0x23, 0x36, 0x24, 0x37, 0x25, 0x38,
            0x26, 0x39, 0x27, 0x30, 0x2B, 0x09, 0x39, 0x14, 0x28, 0x0D, 0x2A, 0x08,
            0x2C, 0x20, 0x2F, 0xDB, 0x30, 0xDD, 0x31, 0xDC, 0x33, 0xBA, 0x34, 0xDE,
            0x36, 0xBC, 0x37, 0xBE, 0x38, 0xBF, 0x35, 0xC0, 0x2E, 0xBB, 0x2D, 0xBD,
            0x46, 0x2C, 0x47, 0x91, 0x48, 0x13, 0x49, 0x2D, 0x4A, 0x24, 0x4B, 0x21,
            0x4C, 0x2E, 0x4D, 0x23, 0x4E, 0x22, 0x52, 0x26, 0x51, 0x28, 0x50, 0x25,
            0x4F, 0x27, 0x59, 0x61, 0x5A, 0x62, 0x5B, 0x63, 0x5C, 0x64, 0x5D, 0x65,
            0x5E, 0x66, 0x5F, 0x67, 0x60, 0x68, 0x61, 0x69, 0x62, 0x60, 0x57, 0x6B,
            0x56, 0x6D, 0x55, 0x6A, 0x54, 0x6F, 0x53, 0x90, 0x58, 0xFD, 0x63, 0x6E,
            0xE0, 0xA2, 0xE1, 0xA0, 0xE2, 0xA4, 0xE3, 0x5B, 0xE4, 0xA3, 0xE5, 0xA1,
            0xE6, 0xA5, 0xE7, 0x5C, 0x65, 0x5D, 0x85, 0xC2, 0x87, 0xC1, 0x89, 0xC3,
            0x32, 0xD8, 0x8A, 0xDA, 0x88, 0xD7, 0x8B, 0xEB, 0x90, 0xC4, 0x91, 0xC5,
        };

        // Internal seams for exhaustive numeric-fact / first-match tests, not action permission.
        internal static bool TryLookupUsage(byte input, out byte usage)
            => TryLookupUsage(NumericPairs, input, out usage);

        internal static bool TryLookupUsage(ReadOnlySpan<byte> pairs, byte input, out byte usage)
        {
            if ((pairs.Length & 1) != 0) throw new ArgumentException("Expected (usage,input) pairs.", nameof(pairs));
            for (int i = 0; i < pairs.Length; i += 2)
            {
                if (pairs[i + 1] != input) continue;
                usage = pairs[i];
                return true;
            }
            usage = 0;
            return false;
        }

        public static bool TryEncode(SourceActionDescriptor descriptor,
            out G5OrdinaryAction action, out string rejectionReason)
        {
            action = null;
            rejectionReason = null;
            if (descriptor == null) rejectionReason = "An explicit source descriptor is required.";
            else if (descriptor.Tag != 2) rejectionReason = "Only tag-2 ordinary source descriptors are supported; macros/other tags are not editable.";
            else if (descriptor.ModifierMask == 0 && (descriptor.PrimaryNumericValue == 0xFA || descriptor.PrimaryNumericValue == 0xFB))
                rejectionReason = "Modifier-zero FA/FB are special actions, not ordinary keys.";
            else if (descriptor.PrimaryNumericValue >= 1 && descriptor.PrimaryNumericValue <= 5)
                rejectionReason = "Primary 01..05 select descriptor passthrough actions, not ordinary keys.";
            else if (descriptor.PrimaryNumericValue >= 0x88 && descriptor.PrimaryNumericValue <= 0xE0)
                rejectionReason = "Primary 88..E0 selector branches are deliberately unsupported, including any unclassified defaults.";
            if (rejectionReason != null) return false;

            if (!TryLookupUsage(descriptor.PrimaryNumericValue, out byte primary))
            {
                rejectionReason = "Primary numeric value is not mapped; zero lookup fallback is not an editable action.";
                return false;
            }
            byte secondary = 0;
            if (descriptor.SecondaryNumericValue != 0 && !TryLookupUsage(descriptor.SecondaryNumericValue, out secondary))
            {
                rejectionReason = "Secondary numeric value is not mapped; refusing silent zero substitution.";
                return false;
            }
            action = new G5OrdinaryAction(descriptor, primary, secondary);
            return true;
        }

        /// <summary>
        /// Patch exactly one explicit offline slot after proving both source records ordinary
        /// and matching the old packed DWORD. Preserve every other byte, including opaque
        /// macro/unknown entries. This cannot authenticate caller metadata or seed provenance.
        /// No capacity default, layer inference, source-row/slot mapping, or device read/write.
        /// </summary>
        public static bool TryPatchOfflineSeed(ReadOnlySpan<byte> offlineSeed, int wireCapacity, int selectedSlot,
            SourceActionDescriptor oldSourceDescriptor, SourceActionDescriptor newSourceDescriptor,
            out G5OrdinaryPatchResult result, out string rejectionReason)
        {
            result = null;
            rejectionReason = null;
            if (wireCapacity < 1 || wireCapacity > 132)
                rejectionReason = "Explicit wire capacity must be in 1..132; there is no default.";
            else if (offlineSeed.Length != wireCapacity * 4)
                rejectionReason = "OfflineSeed length must equal explicit wire capacity * 4.";
            else if (selectedSlot < 0 || selectedSlot >= wireCapacity)
                rejectionReason = "Selected slot must be within the explicit wire capacity, not merely below source-row bound 132.";
            if (rejectionReason != null) return false;

            if (!TryEncode(oldSourceDescriptor, out G5OrdinaryAction oldAction, out string oldReason))
            {
                rejectionReason = "Old source is not editable ordinary: " + oldReason;
                return false;
            }
            if (!TryEncode(newSourceDescriptor, out G5OrdinaryAction newAction, out string newReason))
            {
                rejectionReason = "New source is not supported ordinary: " + newReason;
                return false;
            }
            if (BinaryPrimitives.ReadUInt32LittleEndian(offlineSeed.Slice(selectedSlot * 4, 4)) != oldAction.WireValue)
            {
                rejectionReason = "Old packed action does not match OfflineSeed at the selected slot.";
                return false;
            }
            result = new G5OrdinaryPatchResult(offlineSeed, wireCapacity, selectedSlot, oldAction, newAction);
            return true;
        }
    }
}
