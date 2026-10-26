using System;
using System.Linq;
using RkRebuild;

internal static class ProtocolFramesTests
{
    private static int checks;
    private static void Check(bool value, string name)
    {
        checks++;
        if (!value) throw new Exception(name);
    }
    private static void Reject(Action action, string name)
    {
        bool rejected = false;
        try { action(); } catch (ArgumentException) { rejected = true; }
        Check(rejected, name);
    }
    private static void Main()
    {
        byte[][] single = Rk3632Codec.EncodeRequest(4, 1, new byte[] { 1, 2, 3 });
        Check(single.Length == 1, "single frame");
        Check(Convert.ToHexString(single[0]) == "1304010013010203000000000000000000000031", "hand-computed request fixture");
        byte[][] split = Rk3632Codec.EncodeRequest(3, 2, Enumerable.Range(0, 15).Select(i => (byte)i).ToArray());
        Check(split.Length == 2 && split[0][19] == 0xA1 && split[1][19] == 0x48, "hand-computed split checksums");
        Check(split[1][2] == 2 && split[1][3] == 1 && split[1][4] == 0x21 && split[1][5] == 14, "split fields");
        for (int length = 1; length <= 512; length++)
        {
            byte[] payload = Enumerable.Range(0, length).Select(i => (byte)(i * 37)).ToArray();
            byte[][] frames = Rk3632Codec.EncodeRequest(0x82, 15, payload);
            byte[] recovered = frames.SelectMany(f => f.Skip(5).Take(f[4] & 15)).ToArray();
            Check(recovered.SequenceEqual(payload), "payload round trip " + length);
            Check(frames.Length == (length + 13) / 14, "chunk count " + length);
            for (int i = 0; i < frames.Length; i++)
            {
                byte[] frame = frames[i];
                Check(frame.Length == 20 && frame[0] == 0x13 && frame[1] == 0x82 && frame[2] == frames.Length && frame[3] == i, "header");
                Check(frame[19] == (byte)(frame.Take(19).Sum(v => v) & 255), "additive checksum wraps");
                Check(frame.Skip(5 + (frame[4] & 15)).Take(14 - (frame[4] & 15)).All(v => v == 0), "unused payload remains zero");
            }
        }
        Reject(() => Rk3632Codec.EncodeRequest(1, 0, Array.Empty<byte>()), "zero bytes rejected");
        Reject(() => Rk3632Codec.EncodeRequest(1, 0, new byte[513]), "native 512-byte bound");
        Reject(() => Rk3632Codec.EncodeRequest(1, -1, new byte[1]), "negative option");
        Reject(() => Rk3632Codec.EncodeRequest(1, 16, new byte[1]), "overflow option");
        Check(Rk3632Codec.EncodeRequest(1, 0, new byte[512]).Length == 37, "maximum request is 37 frames");
        for (int command = 0; command < 256; command++)
            Check(Rk3632Codec.RequiresResponse((byte)command) == (command < 128 && command != 6), "response wait predicate");
        byte[] response = new byte[20];
        response[1] = 4;
        Check(Rk3632Codec.InspectResponse(response, 4) == Rk3632ResponseKind.Match, "matching command");
        response[19] = 123;
        Check(Rk3632Codec.InspectResponse(response, 4) == Rk3632ResponseKind.Match, "no fabricated response checksum");
        Check(Rk3632Codec.InspectResponse(response, 3) == Rk3632ResponseKind.CommandMismatch, "different command");
        response[2] = 0x80;
        Check(Rk3632Codec.InspectResponse(response, 4) == Rk3632ResponseKind.DeviceErrorFlag, "error bit before command match");
        response[0] = 0xFF;
        Check(Rk3632Codec.InspectResponse(response, 4) == Rk3632ResponseKind.DisconnectMarker, "disconnect before error bit");
        response[1] = 0x0A;
        response[5] = 0x12; response[6] = 0x34; response[7] = 0x56;
        Check(Rk3632Codec.InspectResponse(response, 4) == Rk3632ResponseKind.StatusEvent, "dispatcher diverts status before queue");
        Check(Rk3632Codec.StatusMessageValue(response) == 0x563412, "status payload byte order");
        Reject(() => Rk3632Codec.InspectResponse(new byte[19], 1), "short record rejected");
        Reject(() => Rk3632Codec.InspectResponse(new byte[21], 1), "oversized record rejected");
        Reject(() => Rk3632Codec.StatusMessageValue(new byte[20]), "ordinary record is not status");
        Console.WriteLine(checks + " offline protocol checks passed; no device was accessed.");
    }
}
