using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace RkRebuild
{
    internal static class WirelessLightingProtocol
    {
        internal const int ReportBytes = 20;
        internal const int FrameCount = 10;

        // Native 0x40DA80, installed 4.06 SHA-256
        // c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6.
        // This is a query with no payload, NOT a serialized lighting configuration.
        public static byte[] CreateQuery()
        {
            var query = new byte[ReportBytes];
            query[0] = 0x13;
            query[1] = 0x44;
            query[2] = 0x01;
            query[19] = 0x58;
            return query;
        }

        public static byte[] DecodeBlock(IReadOnlyList<byte[]> frames)
        {
            if (frames == null) throw new ArgumentNullException(nameof(frames));
            if (frames.Count != FrameCount)
                throw new InvalidDataException("Lighting query requires exactly ten response frames.");
            var block = new byte[128];
            for (int index = 0; index < FrameCount; index++)
            {
                byte[] frame = frames[index];
                ValidateFrame(frame, index);
                int length = index == FrameCount - 1 ? 2 : 14;
                Buffer.BlockCopy(frame, 5, block, index * 14, length);
            }
            if (block[126] != 0x5a || block[127] != 0xa5)
                throw new InvalidDataException("Lighting block signature is invalid.");
            return block;
        }

        internal static void ValidateFrame(byte[] frame, int expectedIndex)
        {
            if (frame == null || frame.Length != ReportBytes)
                throw new InvalidDataException("Lighting response must be exactly twenty bytes.");
            if (frame[0] != 0x13 || frame[1] != 0x44)
                throw new InvalidDataException("Unexpected lighting response marker or command.");
            if ((frame[2] & 0x80) != 0)
                throw new InvalidDataException("Device returned a lighting query error.");
            if (frame[2] != FrameCount || frame[3] != expectedIndex)
                throw new InvalidDataException("Lighting response count or ordered index is invalid.");
            if ((frame[4] & 0x0f) != (expectedIndex == FrameCount - 1 ? 2 : 14))
                throw new InvalidDataException("Lighting response payload length is invalid.");
            // Do not validate byte 19: captured query responses do NOT use the
            // simple additive checksum, and the vendor consumer does not check it.
        }
    }

    internal static class WirelessLightingReader
    {
        internal const int MaximumSkippedFrames = 64;

        /// <summary>
        /// Read only the 3632 lighting block. The caller MUST first explicitly
        /// match the endpoint to the supported catalogue; metadata alone is not
        /// evidence of protocol compatibility. No probing or fallback is performed.
        /// DevicePath remains an opaque selection token and is never logged here.
        /// </summary>
        public static async Task<byte[]> ReadAsync(HidEndpoint endpoint, TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            ValidateEndpoint(endpoint);
            ValidateTimeout(timeout);
            cancellationToken.ThrowIfCancellationRequested();
            if (timeout == TimeSpan.Zero) throw new TimeoutException("Lighting query timed out.");
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Lighting HID transport requires Windows.");
            using var stream = new FileStream(endpoint.DevicePath, FileMode.Open,
                FileAccess.ReadWrite, FileShare.ReadWrite, bufferSize: 20, FileOptions.Asynchronous);
            return await ReadFromStreamAsync(stream, timeout, cancellationToken).ConfigureAwait(false);
        }

        internal static void ValidateEndpoint(HidEndpoint endpoint)
        {
            if (endpoint == null) throw new ArgumentNullException(nameof(endpoint));
            if (!string.IsNullOrEmpty(endpoint.Error) || !ValidId(endpoint.VendorId) || !ValidId(endpoint.ProductId) ||
                endpoint.UsagePage != "FF02" || endpoint.Usage != "0002" ||
                endpoint.InputReportBytes != 20 || endpoint.OutputReportBytes != 20)
                throw new ArgumentException("Endpoint is not an eligible 3632 vendor lighting interface.", nameof(endpoint));
            if (string.IsNullOrWhiteSpace(endpoint.DevicePath) || endpoint.DevicePath.IndexOf('\0') >= 0)
                throw new ArgumentException("Endpoint has no valid opaque device path.", nameof(endpoint));
        }

        private static bool ValidId(string id) => id != null && id.Length == 4 &&
            ushort.TryParse(id, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort value) && value != 0;

        private static void ValidateTimeout(TimeSpan timeout)
        {
            if (timeout < TimeSpan.Zero || timeout > TimeSpan.FromSeconds(15))
                throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be between zero and fifteen seconds.");
        }

        // Test seam, not a public arbitrary-packet API. The caller owns this stream.
        // One absolute deadline covers the write, flush, skipped records and reads.
        internal static async Task<byte[]> ReadFromStreamAsync(Stream stream, TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            ValidateTimeout(timeout);
            if (!stream.CanRead || !stream.CanWrite)
                throw new ArgumentException("A readable and writable stream is required.", nameof(stream));
            cancellationToken.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout == TimeSpan.Zero) deadline.Cancel();
            else deadline.CancelAfter(timeout);
            CancellationToken token = deadline.Token;
            try
            {
                token.ThrowIfCancellationRequested();
                await stream.WriteAsync(WirelessLightingProtocol.CreateQuery().AsMemory(), token).ConfigureAwait(false);
                await stream.FlushAsync(token).ConfigureAwait(false);
                var frames = new List<byte[]>(WirelessLightingProtocol.FrameCount);
                int skipped = 0;
                while (frames.Count < WirelessLightingProtocol.FrameCount)
                {
                    token.ThrowIfCancellationRequested();
                    var frame = new byte[WirelessLightingProtocol.ReportBytes];
                    int offset = 0;
                    while (offset < frame.Length)
                    {
                        int read = await stream.ReadAsync(frame.AsMemory(offset), token).ConfigureAwait(false);
                        if (read == 0) throw new EndOfStreamException("Lighting response ended before a complete block.");
                        offset += read;
                    }
                    if (frame[1] != 0x44)
                    {
                        // Includes status command 0x0A. Never collect its payload.
                        if (++skipped > MaximumSkippedFrames)
                            throw new InvalidDataException("Lighting query exceeded the unrelated-report limit.");
                        continue;
                    }
                    WirelessLightingProtocol.ValidateFrame(frame, frames.Count);
                    frames.Add(frame);
                }
                token.ThrowIfCancellationRequested();
                return WirelessLightingProtocol.DecodeBlock(frames);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
            {
                throw new TimeoutException("Lighting query timed out.");
            }
        }
    }
}
