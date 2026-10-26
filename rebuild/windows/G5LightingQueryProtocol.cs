using System;
using System.IO;

namespace RkRebuild
{
    internal static class G5LightingQueryProtocol
    {
        // Installed 4.06, SHA-256 in G5FeatureCodec.SourceSha256, true entry
        // 0x40FAD0. Query 84 is a configuration request, NOT a passive read.
        public static byte[] CreateQuery(byte reportId) =>
            G5FeatureCodec.BuildRequestPacket(reportId, 2, 0x84, 0, 128, 0, ReadOnlySpan<byte>.Empty);

        public static byte[] Decode(byte reportId, byte[] response)
        {
            if (response == null || response.Length != G5FeatureCodec.ReportBytes || response[0] != reportId)
                throw new InvalidDataException("G5 query requires the selected 520-byte feature report.");
            if (!G5FeatureCodec.MatchesVendorReadCommand(response, 0x84))
                throw new InvalidDataException("G5 lighting response has an unexpected command.");
            byte[] block = G5FeatureCodec.CopyReadPayload(response, 0x84, 128);
            // Caller-level configuration signature is independent of the
            // transport command check. Neither check is authentication.
            if (block[126] != 0x5a || block[127] != 0xa5)
                throw new InvalidDataException("G5 lighting block signature is invalid.");
            return block;
        }
    }
}
