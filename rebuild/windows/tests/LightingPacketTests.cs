using System;
using System.Linq;
using RkRebuild;

internal static class LightingPacketTests
{
    private static int assertions;
    private static readonly byte[] Hw = { 0, 4, 8, 12, 16, 20 };
    private static readonly byte[] NoReset = new byte[6];
    private static byte[] Seed() => Enumerable.Repeat((byte)0xCC, 128).ToArray();
    private static LightingPacketRow Row(uint s = 0x12, uint b = 2, uint q = 0xAB, uint f = 0) => new(s, b, q, f);
    private static LightingPacketInputs Input(LightingPacketLayout layout = LightingPacketLayout.Ordinary, int count = 0) =>
        new() { Layout = layout, RowCount = count, GaoshouIndex = -1, RgbOffIndex = -1 };
    private static LightingPacketResult Run(LightingPacketInputs input, LightingPacketRow[] rows = null,
        uint[] maps = null, byte[] reset = null, byte[] seed = null, byte[] hw = null, byte[] debounce = null) =>
        LightingPacketCodec.Patch(seed ?? Seed(), input, rows ?? Array.Empty<LightingPacketRow>(),
            maps ?? new uint[24], hw ?? Hw, debounce ?? Array.Empty<byte>(), reset ?? NoReset);
    private static void Check(bool condition, string name)
    {
        assertions++;
        if (!condition) throw new Exception(name);
    }
    private static void Equal(byte[] actual, byte[] expected, string name) => Check(actual.SequenceEqual(expected), name);
    private static void Reject(Action action, string name)
    {
        bool rejected = false;
        try { action(); } catch (ArgumentException) { rejected = true; }
        Check(rejected, name);
    }
    // Expected packets are hand-computed patches to CC-filled seeds, not another encoder.
    private static byte[] OrdinaryBase()
    {
        byte[] e = Seed();
        e[9] = 0; e[10] = 1; e[11] = 0x20; e[0x38] = 0xFF; e[0x39] = 0xFF;
        e[0x16] = 0; e[0x1B] = 1;
        return e;
    }
    private static void Main()
    {
        byte[] seed = Seed();
        var basic = Run(Input(), seed: seed);
        Equal(basic.Bytes, OrdinaryBase(), "ordinary empty, preservation");
        Equal(seed, Seed(), "seed unchanged");
        Check(!ReferenceEquals(seed, basic.Bytes), "exact clone");
        Check(basic.Changes.Count == 7 && basic.Writes.Count == 7, "final change count");
        Check(basic.Changes.All(c => basic.Writes[c.FinalWrite].Offset == c.Offset), "final provenance links");

        var fallback = Run(Input(count: 2), new[] { Row(), Row(0x1F, 5, 0x42, 1) });
        byte[] e = OrdinaryBase(); e[0x3A] = 8; e[0x3B] = 0x2B; e[0x3C] = 20; e[0x3D] = 0xF7;
        Equal(fallback.Bytes, e, "ordinary sequential pair, nibble truncation, F override");

        uint[] maps = new uint[24]; maps[0] = 2; maps[1] = 2;
        var duplicates = Run(Input(count: 2), new[] { Row(), Row(3, 1, 4) }, maps);
        e = OrdinaryBase(); e[10] = 2; e[0x3C] = 4; e[0x3D] = 0x34;
        Equal(duplicates.Bytes, e, "ordinary duplicate mapping last wins");
        Check(duplicates.Collisions.Count == 2, "duplicate pair collisions");
        Check(duplicates.Collisions.All(c => duplicates.Writes[c.OverwritingWrite].Before == duplicates.Writes[c.PreviousWrite].After), "collision chain");

        maps = new uint[24]; maps[1] = 1;
        var zeroMap = Run(Input(count: 1), new[] { Row() }, maps);
        e = OrdinaryBase(); e[10] = 0; e[0x38] = 8; e[0x39] = 0x2B;
        Equal(zeroMap.Bytes, e, "ordinary mapped zero writes initialized pair");
        Check(zeroMap.Collisions.Count == 2, "initialization collisions reported");

        // First fifteen ONLY: cell 15 cannot enable mappings.
        maps = new uint[24]; maps[15] = uint.MaxValue;
        Equal(Run(Input(count: 1), new[] { Row() }, maps).Bytes,
            Run(Input(count: 1), new[] { Row() }).Bytes, "ignore mapping cells beyond first15 sum");
        maps = new uint[24]; maps[0] = uint.MaxValue; maps[1] = 2; // wrap -> +1
        e = OrdinaryBase(); e[10] = 0xFF;
        Equal(Run(Input(), maps: maps).Bytes, e, "signed wrap positive and header truncation");
        maps[1] = 0; // -1: fallback, not positive unsigned
        Equal(Run(Input(), maps: maps).Bytes, OrdinaryBase(), "signed negative sum fallback");
        maps[1] = 1; // wrap -> zero
        Equal(Run(Input(), maps: maps).Bytes, OrdinaryBase(), "wrapped zero sum fallback");
        maps[0] = 0x80000000; maps[1] = 0;
        Equal(Run(Input(), maps: maps).Bytes, OrdinaryBase(), "INT_MIN sum fallback");

        // Mask skips both a bad mapping and invalid brightness source.
        maps = new uint[15]; maps[0] = uint.MaxValue; maps[1] = 2;
        var masked = new LightingPacketInputs { RowCount = 1, LedMask = 1, GaoshouIndex = -1 };
        Run(masked, new[] { Row(b: uint.MaxValue) }, maps);
        Check(true, "masked invalid row not accessed");

        var special = new LightingPacketInputs { RowCount = 1, GaoshouIndex = 0, LedMask = 1 };
        e = OrdinaryBase(); e[9] = 1; e[0x5E] = 8;
        Equal(Run(special, new[] { Row() }).Bytes, e, "special brightness outside mask loop");
        maps = new uint[24]; maps[0] = 19; // 0x38+38=0x5E
        var overlapping = Run(new LightingPacketInputs { RowCount = 1, GaoshouIndex = 0 }, new[] { Row() }, maps);
        Check(overlapping.Collisions.Any(c => c.Offset == 0x5E), "special overlap even when same value");
        var off = new LightingPacketInputs { RgbOffIndex = 0, GaoshouIndex = -1, Field25C0 = 0xF0 };
        e = OrdinaryBase(); e[10] = 0; e[11] = 0x10;
        Equal(Run(off).Bytes, e, "off header override and field25C0 wrap");

        maps = new uint[24]; maps[0] = 2; maps[1] = 1;
        var fw = Run(Input(LightingPacketLayout.Firmware2, 2), new[] { Row(), Row(0x1F, 5, 0xAB) }, maps);
        e = Seed(); e[0x21] = 2; e[0x57] = 8; e[0x58] = 0x2B; e[0x55] = 20; e[0x56] = 0xFB;
        e[0x22] = 0xAB; e[0x23] = 20; e[0x24] = 15; e[8] = 0; e[5] = 0;
        Equal(fw.Bytes, e, "fw2 exact pairs and i==M(i), NOT selected");
        maps = new uint[24];
        var fwZero = Run(Input(LightingPacketLayout.Firmware2, 1), new[] { Row(b: uint.MaxValue) }, maps);
        e = Seed(); e[0x21] = 0; e[8] = 0; e[5] = 0;
        Equal(fwZero.Bytes, e, "fw2 zero skips brightness and leaves triplet");
        maps[0] = 9;
        var fwMasked = Run(new LightingPacketInputs { Layout = LightingPacketLayout.Firmware2, RowCount = 1, LedMask = 1 },
            new[] { Row(b: uint.MaxValue) }, maps);
        Check(fwMasked.Bytes[0x65] == 0xCC && fwMasked.Bytes[0x22] == 0xCC, "fw2 mask preserves output and triplet");
        maps[1] = 1; maps[2] = 2;
        var repeatedTriplet = Run(Input(LightingPacketLayout.Firmware2, 3),
            new[] { Row(), Row(3, 1, 0xAB), Row(4, 3, 0xCD, 1) }, maps);
        Check(repeatedTriplet.Bytes[0x22] == 7 && repeatedTriplet.Bytes[0x23] == 12 && repeatedTriplet.Bytes[0x24] == 4,
            "multiple i==M(i) rows: last triplet wins and F overrides");
        Check(repeatedTriplet.Collisions.Count == 3, "triplet collision count");
        maps[0] = 1; maps[1] = 1;
        var fwDup = Run(Input(LightingPacketLayout.Firmware2, 2), new[] { Row(), Row(3, 1, 4) }, maps);
        Check(fwDup.Bytes[0x55] == 4 && fwDup.Bytes[0x56] == 0x34 && fwDup.Collisions.Count == 2, "fw2 duplicate map");
        var fwOff = new LightingPacketInputs { Layout = LightingPacketLayout.Firmware2, RgbOffIndex = 0 };
        Check(Run(fwOff, maps: maps).Bytes[0x21] == 0, "fw2 off override");

        byte[] reset = { 10, 0x66, 0, 0, 127, 0x77 };
        var overlay = Run(new LightingPacketInputs { ApplyFlags = 0x10, GaoshouIndex = -1 }, reset: reset);
        e = OrdinaryBase(); e[127] = 0x77;
        Equal(overlay.Bytes, e, "overlay first, header wins, third pair applied");
        Check(overlay.Collisions.Any(c => c.Offset == 10), "overlay provenance collision");
        Equal(Run(Input(), reset: reset).Bytes, OrdinaryBase(), "overlay flags gate");
        reset = new byte[] { 0, 0, 0, 0, 127, 0x77 };
        Equal(Run(new LightingPacketInputs { ApplyFlags = 0x10, GaoshouIndex = -1 }, reset: reset).Bytes,
            OrdinaryBase(), "overlay first DWORD zero suppresses third pair");
        reset = new byte[] { 0, 0x55, 127, 0, 0, 0 };
        overlay = Run(new LightingPacketInputs { ApplyFlags = 0x10, GaoshouIndex = -1 }, reset: reset);
        Check(overlay.Bytes[0] == 0x55 && overlay.Bytes[127] == 0, "offset0 value and nonzero offset zero value");

        foreach (var layout in new[] { LightingPacketLayout.Ordinary, LightingPacketLayout.Firmware2 })
        {
            for (int sleep = -1; sleep <= 6; sleep++)
            {
                var fields = new LightingPacketInputs { Layout = layout, GaoshouIndex = -1,
                    DebounceGate = 1, Field3E02 = 1, Field3E08 = 0x123, Field3E14 = sleep, Field3E20 = 7 };
                var result = Run(fields, debounce: new byte[] { 6, 9 });
                bool ordinary = layout == LightingPacketLayout.Ordinary;
                Check(result.Bytes[3] == 9 && result.Bytes[2] == (ordinary ? 0xCC : 9), "debounce " + layout);
                Check(result.Bytes[ordinary ? 0x16 : 8] == 0x23, "tap truncation " + layout);
                byte expectedSleep = sleep >= 1 && sleep <= 5 ? new byte[] { 10, 20, 40, 60, 0 }[sleep - 1] : (byte)0xCC;
                Check(result.Bytes[ordinary ? 0x18 : 9] == expectedSleep, "sleep mapping/preservation " + sleep);
                if (ordinary) Check(result.Bytes[0x1B] == 0, "field3E20 nonzero");
            }
            var suppress = new LightingPacketInputs { Layout = layout, GaoshouIndex = -1, Field3E04 = 99, Field3E08 = 0xFF };
            Check(Run(suppress).Bytes[layout == LightingPacketLayout.Ordinary ? 0x16 : 8] == 0, "tap suppression");
        }

        // Inclusive final-byte destinations; overflow arithmetic must never wrap into seed.
        maps = new uint[24]; maps[0] = 35;
        Check(Run(Input(count: 1), new[] { Row() }, maps).Bytes[127] == 0x2B, "ordinary final valid pair");
        maps[0] = 36;
        Reject(() => Run(Input(count: 1), new[] { Row() }, maps), "ordinary out of bounds");
        maps[0] = 21;
        Check(Run(Input(LightingPacketLayout.Firmware2, 1), new[] { Row() }, maps).Bytes[126] == 0x2B, "fw2 final valid pair");
        maps[0] = 22;
        Reject(() => Run(Input(LightingPacketLayout.Firmware2, 1), new[] { Row() }, maps), "fw2 out of bounds");
        maps[0] = uint.MaxValue;
        Reject(() => Run(Input(LightingPacketLayout.Firmware2, 1), new[] { Row() }, maps), "destination multiplication cannot wrap");
        Reject(() => Run(Input(), seed: new byte[127]), "short seed");
        Reject(() => Run(Input(), seed: new byte[129]), "long seed");
        Reject(() => Run(null), "null input");
        Reject(() => Run(Input((LightingPacketLayout)99)), "bad layout");
        Reject(() => Run(Input(count: -1)), "negative rows");
        Reject(() => Run(Input(count: 25), new LightingPacketRow[25]), "too many rows");
        Reject(() => Run(Input(count: 1)), "missing row");
        Reject(() => Run(new LightingPacketInputs { SelectedOrdinal = 24 }), "bad selected ordinal");
        Reject(() => Run(Input(), maps: new uint[14]), "missing sum cell");
        Reject(() => Run(Input(LightingPacketLayout.Firmware2), maps: Array.Empty<uint>()), "missing selected mapping");
        Reject(() => Run(new LightingPacketInputs { SelectedOrdinal = 20, GaoshouIndex = -1 }, maps: Enumerable.Repeat(1u, 15).ToArray()), "missing mapped selected cell");
        Reject(() => Run(Input(count: 1), new[] { Row(b: 6) }), "LightHW source bound");
        Reject(() => Run(Input(count: 1), new[] { Row(b: uint.MaxValue) }), "LightHW uint source bound");
        Reject(() => Run(new LightingPacketInputs { GaoshouIndex = 0 }), "missing special row");
        Reject(() => Run(new LightingPacketInputs { DebounceGate = 1 }), "DebounceHW source bound");
        Reject(() => Run(Input(), reset: new byte[5]), "reset pairs length");
        seed = Seed();
        Reject(() => Run(new LightingPacketInputs { ApplyFlags = 0x10 }, reset: new byte[] { 1, 1, 128, 2, 0, 0 }, seed: seed), "late overlay destination invalid");
        Equal(seed, Seed(), "invalid overlay leaves seed unchanged");
        Reject(() => Run(new LightingPacketInputs { ApplyFlags = 0x10, DebounceGate = 1 }, reset: new byte[] { 1, 1, 0, 0, 0, 0 }, seed: seed), "late source invalid after valid planned writes");
        Equal(seed, Seed(), "invalid late source leaves seed unchanged");
        var noChanges = Run(Input(), seed: OrdinaryBase());
        Check(noChanges.Changes.Count == 0 && noChanges.Writes.Count == 7, "no-op writes retain provenance without final changes");
        var fullRows = Enumerable.Repeat(Row(), 24).ToArray();
        Check(Run(Input(count: 24), fullRows).Bytes[0x69] == 0x2B, "all24 fallback rows bounded");
        byte[] signedSeed = Seed(); signedSeed[126] = 0x5A; signedSeed[127] = 0xA5;
        var signedResult = Run(Input(), seed: signedSeed);
        Check(signedResult.Bytes[126] == 0x5A && signedResult.Bytes[127] == 0xA5, "existing signature preserved when not targeted");
        Check(Run(Input()).Bytes[127] == 0xCC, "no invented signature generation");
        Console.WriteLine("PASS: " + assertions + " lighting packet assertions (offline, dependency-free).");
    }
}
