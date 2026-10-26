using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using RkRebuild;

internal static class G5OrdinaryActionTests
{
    private static int checks;

    // Independent literal fixture in (usage,input) order. The whole-fixture digest is
    // checked even without the optional installed PE; all 114 pairs are exercised.
    private static readonly byte[] Pairs = Convert.FromHexString(
        "64E2291B3A703B713C723D733E743F754076417742784379447A457B" +
        "0441054206430744084509460A470B480C490D4A0E4B0F4C104D114E124F1350" +
        "1451155216531754185519561A571B581C591D5A1E311F3220332134223523362437" +
        "2538263927302B093914280D2A082C202FDB30DD31DC33BA34DE36BC37BE38BF35C0" +
        "2EBB2DBD462C47914813492D4A244B214C2E4D234E225226512850254F2759615A62" +
        "5B635C645D655E665F67606861696260576B566D556A546F539058FD636EE0A2E1A0" +
        "E2A4E35BE4A3E5A1E6A5E75C655D85C287C189C332D88ADA88D78BEB90C491C5");

    private const string SourceHash = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6";
    private const string TableHash = "b6f313df4299451aac121648bb8759081c141bec7bb74a399f162e95574beae1";

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition) throw new Exception(message);
    }

    private static void Equal(byte[] actual, byte[] expected, string message)
        => Check(actual.AsSpan().SequenceEqual(expected), message);

    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }

    private static SourceActionDescriptor Descriptor(byte primary = 0x41, byte secondary = 0, byte modifiers = 0, byte tag = 2)
    {
        // Deliberately nonzero opaque bytes: no hidden zero-record precondition.
        byte[] bytes = Enumerable.Repeat((byte)0xA7, 16).ToArray();
        bytes[3] = tag;
        bytes[8] = modifiers;
        bytes[9] = primary;
        bytes[10] = secondary;
        return new SourceActionDescriptor(bytes);
    }

    private static G5OrdinaryAction Encode(SourceActionDescriptor descriptor)
    {
        Check(G5OrdinaryActionCodec.TryEncode(descriptor, out var result, out var reason), "encode failed: " + reason);
        Check(result != null && reason == null, "success result/reason");
        return result;
    }

    private static void Reject(SourceActionDescriptor descriptor, string reasonFragment)
    {
        Check(!G5OrdinaryActionCodec.TryEncode(descriptor, out var result, out var reason), "must reject");
        Check(result == null && reason != null && reason.Contains(reasonFragment), "rejection detail: " + reason);
    }

    private static bool IsAllowedPrimary(byte key)
        => Pairs.Where((_, i) => (i & 1) == 1).Contains(key)
            && !(key >= 0x88 && key <= 0xE0) && !(key >= 1 && key <= 5);

    private static void NumericFacts()
    {
        Check(Pairs.Length == 228, "114 tuples");
        Check(Convert.ToHexString(SHA256.HashData(Pairs)).Equals(TableHash, StringComparison.OrdinalIgnoreCase), "literal fixture table digest");
        for (int i = 0; i < Pairs.Length; i += 2)
        {
            byte usage = Pairs[i], key = Pairs[i + 1];
            Check(G5OrdinaryActionCodec.TryLookupUsage(key, out byte actual) && actual == usage, "every numeric tuple");
            // Every tuple is legal as a secondary lookup on an ordinary primary.
            var secondary = Encode(Descriptor(0x41, key, 0xA5));
            Check(secondary.PrimaryUsage == 4 && secondary.SecondaryUsage == usage, "all secondary usages");
            Check(secondary.WireValue == (0x0400A500U | ((uint)usage << 16)), "all secondary packing");
            if (IsAllowedPrimary(key))
            {
                var primary = Encode(Descriptor(key));
                Check(primary.WireValue == (uint)usage << 24 && primary.PrimaryUsage == usage, "all supported primary tuples");
            }
            else Reject(Descriptor(key), "selector");
        }

        for (int key = 0; key < 256; key++)
        {
            bool known = false;
            byte expected = 0;
            for (int i = 0; i < Pairs.Length; i += 2)
                if (Pairs[i + 1] == key) { known = true; expected = Pairs[i]; break; }
            Check(G5OrdinaryActionCodec.TryLookupUsage((byte)key, out byte actual) == known && actual == expected, "exhaustive lookup domain");
            bool encoded = G5OrdinaryActionCodec.TryEncode(Descriptor((byte)key), out var action, out var reason);
            Check(encoded == IsAllowedPrimary((byte)key), "exhaustive primary policy");
            Check(encoded ? action != null && reason == null : action == null && !string.IsNullOrEmpty(reason), "exhaustive primary result");
            bool secondaryEncoded = G5OrdinaryActionCodec.TryEncode(Descriptor(0x41, (byte)key), out _, out _);
            Check(secondaryEncoded == (key == 0 || known), "unknown secondary never silently maps to zero");
        }

        // The shipped table has no duplicate inputs. A synthetic duplicate explicitly
        // witnesses first-match semantics so a future dictionary rewrite cannot select last.
        byte[] duplicates = { 0x12, 0x41, 0x34, 0x41, 0x56, 0x42 };
        Check(G5OrdinaryActionCodec.TryLookupUsage(duplicates, 0x41, out byte first) && first == 0x12, "duplicate lookup keeps first");
        Check(!G5OrdinaryActionCodec.TryLookupUsage(duplicates, 0x43, out byte absent) && absent == 0, "absent explicit false");
        Check(!G5OrdinaryActionCodec.TryLookupUsage(ReadOnlySpan<byte>.Empty, 0x41, out _), "empty lookup");
        Throws<ArgumentException>(() => G5OrdinaryActionCodec.TryLookupUsage(new byte[1], 0, out _));
    }

    private static void VectorsAndGuards()
    {
        foreach (var vector in new[] { (0x41, 0x04000000U), (0x42, 0x05000000U), (0x1B, 0x29000000U),
            (0x70, 0x3A000000U), (0x0D, 0x28000000U), (0x20, 0x2C000000U) })
            Check(Encode(Descriptor((byte)vector.Item1)).WireValue == vector.Item2, "documented vector");
        Equal(Encode(Descriptor()).Bytes, new byte[] { 0, 0, 0, 4 }, "41 => 04000000 => 00 00 00 04");
        var chord = Encode(Descriptor(0x41, 0x42, 2));
        Check(chord.WireValue == 0x04050200 && chord.PrimaryNumericValue == 0x41 && chord.SecondaryNumericValue == 0x42
            && chord.ModifierMask == 2 && chord.PrimaryUsage == 4 && chord.SecondaryUsage == 5, "typed numeric/usage metadata");
        Equal(chord.Bytes, new byte[] { 0, 2, 5, 4 }, "secondary/modifier byte order");
        for (int m = 0; m < 256; m++)
            Equal(Encode(Descriptor(0x41, 0x42, (byte)m)).Bytes, new byte[] { 0, (byte)m, 5, 4 }, "all modifier masks");
        for (int tag = 0; tag < 256; tag++)
            if (tag != 2) Reject(Descriptor(tag: (byte)tag), "tag-2");
        foreach (byte primary in new byte[] { 0xFA, 0xFB })
        {
            Reject(Descriptor(primary), "special");
            Reject(Descriptor(primary, modifiers: 1), "not mapped");
        }
        for (byte p = 1; p <= 5; p++) Reject(Descriptor(p), "passthrough");
        for (int p = 0x88; p <= 0xE0; p++)
            foreach (byte m in new byte[] { 0, 1, 0xFF }) Reject(Descriptor((byte)p, modifiers: m), "selector");
        Reject(Descriptor(0), "not mapped");
        Reject(Descriptor(0x41, 0xFF), "Secondary");
        Reject(null, "explicit");
        foreach (int n in new[] { 0, 1, 15, 17, 32 }) Throws<ArgumentException>(() => new SourceActionDescriptor(new byte[n]));

        byte[] input = Descriptor().Bytes;
        var source = new SourceActionDescriptor(input);
        input[9] = 0x42;
        source.Bytes[9] = 0x43;
        var action = Encode(source);
        action.Bytes[3] = 0xFF;
        action.SourceDescriptor.Bytes[9] = 0x44;
        Equal(action.Bytes, new byte[] { 0, 0, 0, 4 }, "source and action ownership");
        Check(source.PrimaryNumericValue == 0x41 && source.Bytes[0] == 0xA7, "source preserves opaque bytes");
    }

    private static byte[] Seed(int capacity, int slot)
    {
        // Explicit offline fixture with opaque DWORDs, including macro-looking action bytes.
        var seed = new byte[capacity * 4];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(i * 37 + 13);
        BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(slot * 4, 4), 0x04000000);
        return seed;
    }

    private static void RejectPatch(byte[] seed, int capacity, int slot, SourceActionDescriptor oldSource,
        SourceActionDescriptor newSource, string reasonFragment)
    {
        byte[] before = (byte[])seed.Clone();
        Check(!G5OrdinaryActionCodec.TryPatchOfflineSeed(seed, capacity, slot, oldSource, newSource, out var result, out var reason), "patch must reject");
        Check(result == null && reason != null && reason.Contains(reasonFragment), "patch rejection detail: " + reason);
        Equal(seed, before, "rejected seed unchanged");
    }

    private static void Patches()
    {
        var oldSource = Descriptor();
        var newSource = Descriptor(0x42, 0x41, 0xFF);
        for (int capacity = 1; capacity <= 132; capacity++)
        {
            for (int slot = 0; slot < capacity; slot++)
            {
                byte[] seed = Seed(capacity, slot), before = (byte[])seed.Clone();
                Check(G5OrdinaryActionCodec.TryPatchOfflineSeed(seed, capacity, slot, oldSource, newSource,
                    out var result, out var reason), "all capacities/slots: " + reason);
                Check(reason == null && result.WireCapacity == capacity && result.SelectedSlot == slot, "patch metadata");
                byte[] expected = (byte[])seed.Clone();
                new byte[] { 0, 0xFF, 4, 5 }.CopyTo(expected, slot * 4);
                Equal(result.PatchedOfflineSeed, expected, "only selected DWORD changed; all opaque DWORDs preserved");
                Equal(seed, before, "input seed immutable");
                Equal(result.OfflineSeed, before, "original snapshot");
                Check(result.Changes.Count == 1 && result.Changes[0].Slot == slot && result.Changes[0].ByteOffset == slot * 4
                    && result.Changes[0].OldWireValue == 0x04000000 && result.Changes[0].NewWireValue == 0x0504FF00, "change report");
                Check(result.OldAction.WireValue == 0x04000000 && result.NewAction.WireValue == 0x0504FF00, "old/new typed actions");
                seed[0] ^= 0xFF;
                result.OfflineSeed[0] ^= 0xFF;
                result.PatchedOfflineSeed[0] ^= 0xFF;
                Equal(result.OfflineSeed, before, "original snapshot owns bytes");
                Equal(result.PatchedOfflineSeed, expected, "patched snapshot owns bytes");
            }
        }

        foreach (int capacity in new[] { 1, 126, 132 })
        {
            var seed = Seed(capacity, capacity - 1);
            Check(G5OrdinaryActionCodec.TryPatchOfflineSeed(seed, capacity, capacity - 1, oldSource, oldSource, out var noOp, out _)
                && noOp.Changes.Count == 0, "no-op reports no changes");
            Equal(noOp.PatchedOfflineSeed, seed, "no-op exact preservation");
            Throws<NotSupportedException>(() => ((IList<G5OrdinaryDwordChange>)noOp.Changes).Clear());
            foreach (int slot in new[] { int.MinValue, -1, capacity, 132, int.MaxValue })
                RejectPatch(seed, capacity, slot, oldSource, newSource, "slot");
            foreach (int length in new[] { 0, capacity * 4 - 1, capacity * 4 + 1, capacity * 4 + 4 })
                RejectPatch(new byte[length], capacity, 0, oldSource, newSource, "length");
        }
        foreach (int capacity in new[] { int.MinValue, -1, 0, 133, int.MaxValue })
            RejectPatch(Array.Empty<byte>(), capacity, 0, oldSource, newSource, "capacity");
        RejectPatch(Seed(126, 0), 132, 0, oldSource, newSource, "length");
        RejectPatch(Seed(132, 0), 126, 0, oldSource, newSource, "length");
        var mismatch = Seed(126, 0);
        mismatch[0] = 1;
        RejectPatch(mismatch, 126, 0, oldSource, newSource, "does not match");
        RejectPatch(new byte[504], 126, 0, oldSource, newSource, "does not match");
        foreach (var bad in new[] { Descriptor(tag: 5), Descriptor(tag: 0), Descriptor(0xFA), Descriptor(1), Descriptor(0x88), Descriptor(0), Descriptor(0x41, 0xFF), null })
        {
            // Even a forged ordinary-looking slot cannot make a macro/unknown source editable.
            RejectPatch(Seed(126, 0), 126, 0, bad, newSource, "Old source");
            RejectPatch(Seed(126, 0), 126, 0, oldSource, bad, "New source");
        }
        var macroSeed = Seed(126, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(macroSeed, 0x07000005);
        RejectPatch(macroSeed, 126, 0, oldSource, newSource, "does not match");
        RejectPatch(macroSeed, 126, 0, Descriptor(tag: 5), newSource, "Old source");
    }

    private static void ValidateBinary(string path)
    {
        // Optional, read-only static witness validator. Never loads/executes the vendor image.
        byte[] image = File.ReadAllBytes(path);
        Check(image.Length == 2326528, "exact source image length");
        Check(Convert.ToHexString(SHA256.HashData(image)).Equals(SourceHash, StringComparison.OrdinalIgnoreCase), "exact source image hash");
        using var stream = new MemoryStream(image, false);
        using var pe = new PEReader(stream);
        Check(pe.PEHeaders.PEHeader.ImageBase == 0x400000 && pe.PEHeaders.PEHeader.Magic == PEMagic.PE32, "source PE identity");

        byte[] Range(int startVa, int endVa)
        {
            int rva = startVa - 0x400000, count = endVa - startVa;
            foreach (var section in pe.PEHeaders.SectionHeaders)
            {
                int delta = rva - section.VirtualAddress;
                if (delta >= 0 && delta <= section.SizeOfRawData - count)
                    return image.AsSpan(section.PointerToRawData + delta, count).ToArray();
            }
            throw new Exception("Witness range is not backed by one PE section");
        }
        void HashRange(int start, int end, string expected)
            => Check(Convert.ToHexString(SHA256.HashData(Range(start, end))).Equals(expected, StringComparison.OrdinalIgnoreCase), "full witness range " + start.ToString("X8"));

        Equal(Range(0x5D2FC0, 0x5D30A4), Pairs, "all exact binary lookup facts");
        HashRange(0x5D2FC0, 0x5D30A4, TableHash);
        HashRange(0x463EE0, 0x463F00, "b9b102c086b39075e7a9f67045864794b0aa7cb89f305e9ce095454f81d6fef8");
        HashRange(0x4107A0, 0x410F00, "013d4d5440f6f5b0e672bcb82e6b0b6315e7b0d66fb32eba01629161b5bf1f9a");
        Equal(Range(0x41084C, 0x41084F), new byte[] { 0x83, 0xF9, 2 }, "tag-2 gate witness");
        Equal(Range(0x410965, 0x410970), Convert.FromHexString("0FB64E0A32DBE870350500"), "secondary lookup call witness");
        Equal(Range(0x4109D3, 0x4109D6), new byte[] { 0xC1, 0xE0, 8 }, "last packing shift witness");
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length > 1) throw new ArgumentException("Usage: G5OrdinaryAction.Tests [exact-4.06-DeviceDriver.exe]");
            NumericFacts();
            VectorsAndGuards();
            Patches();
            if (args.Length == 1) ValidateBinary(args[0]);
            Console.WriteLine("PASS: " + checks + " offline ordinary-subset checks. "
                + (args.Length == 1 ? "Exact binary/table/function witnesses verified." : "Optional exact-binary validation not requested.")
                + " No device read/write or current-settings claim.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }
}
