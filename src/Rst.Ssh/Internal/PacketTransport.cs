using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Rst.Ssh.Internal;

/// <summary>Key material for one direction after NEWKEYS.</summary>
internal sealed class DirectionKeys : IDisposable
{
    public required string Cipher { get; init; }
    public AesCtr? Ctr { get; init; }
    public AesGcm? Gcm { get; init; }
    public byte[]? GcmIv { get; init; }
    public IncrementalHash? Mac { get; init; }
    public int MacLength { get; init; }
    public bool Etm { get; init; }

    public bool IsAead => Gcm is not null;
    public int BlockSize => 16;
    public int TagLength => IsAead ? 16 : MacLength;
    public bool LengthInClear => IsAead || Etm;

    public void Dispose() { Ctr?.Dispose(); Gcm?.Dispose(); Mac?.Dispose(); }
}

/// <summary>
/// Binary Packet Protocol (RFC 4253 §6) including ETM and AES-GCM (openssh.com variants).
/// Reading: exactly one reader. Writing: the caller serializes (send lock in the session).
/// </summary>
internal sealed class PacketTransport : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly int _maxPacketLength;
    private DirectionKeys? _in, _out;
    private uint _seqIn, _seqOut;

    public long BytesReceived { get; private set; }
    public long BytesSent { get; private set; }
    public long BytesSinceKexIn { get; private set; }
    public long BytesSinceKexOut { get; private set; }
    public uint PacketsSinceKex { get; private set; }

    public PacketTransport(Stream stream, int maxPacketLength)
    {
        _stream = stream;
        _maxPacketLength = maxPacketLength;
    }

    // ------------------------------------------------------------------ Version

    public async Task SendVersionAsync(string version, CancellationToken ct)
    {
        var bytes = Encoding.ASCII.GetBytes(version + "\r\n");
        await _stream.WriteAsync(bytes, ct);
        await _stream.FlushAsync(ct);
        BytesSent += bytes.Length;
    }

    /// <summary>Reads lines until "SSH-…" (RFC 4253 allows arbitrary text lines before it).</summary>
    public async Task<string> ReadVersionAsync(CancellationToken ct)
    {
        var line = new List<byte>(64);
        var one = new byte[1];
        for (var lines = 0; lines < 50; lines++)
        {
            line.Clear();
            while (true)
            {
                if (await _stream.ReadAsync(one, ct) == 0) throw new EndOfStreamException("Connection closed during version exchange");
                BytesReceived++;
                if (one[0] == '\n') break;
                if (line.Count > 255) throw new SshProtocolException("Version line too long");
                line.Add(one[0]);
            }
            var s = Encoding.ASCII.GetString(line.ToArray()).TrimEnd('\r');
            if (s.StartsWith("SSH-", StringComparison.Ordinal))
            {
                if (!s.StartsWith("SSH-2.0-", StringComparison.Ordinal) && !s.StartsWith("SSH-1.99-", StringComparison.Ordinal))
                    throw new SshProtocolException($"Unsupported protocol version: {s}", SshDisconnectReason.ProtocolVersionNotSupported);
                return s;
            }
        }
        throw new SshProtocolException("No SSH version line received");
    }

    // ------------------------------------------------------------------ Keys

    public void SetOutgoingKeys(DirectionKeys keys) { _out?.Dispose(); _out = keys; BytesSinceKexOut = 0; }
    public void SetIncomingKeys(DirectionKeys keys) { _in?.Dispose(); _in = keys; BytesSinceKexIn = 0; PacketsSinceKex = 0; }
    public void ResetOutgoingSequence() => _seqOut = 0;
    public void ResetIncomingSequence() => _seqIn = 0;
    public uint IncomingSequence => _seqIn;

    // ------------------------------------------------------------------ Sending

    public async ValueTask WritePacketAsync(ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        var buffer = EncodePacket(payload.Span);
        await _stream.WriteAsync(buffer, ct);
        await _stream.FlushAsync(ct);

        _seqOut++;
        BytesSent += buffer.Length;
        BytesSinceKexOut += buffer.Length;
    }

    private byte[] EncodePacket(ReadOnlySpan<byte> payload)
    {
        var keys = _out;
        var blockSize = keys?.BlockSize ?? 8;
        var lengthInClear = keys?.LengthInClear ?? false;
        var tagLength = keys?.TagLength ?? 0;

        var unpadded = 1 + payload.Length + (lengthInClear ? 0 : 4);
        var padding = blockSize - unpadded % blockSize;
        if (padding < 4) padding += blockSize;
        var packetLength = 1 + payload.Length + padding;

        var buffer = new byte[4 + packetLength + tagLength];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)packetLength);
        buffer[4] = (byte)padding;
        payload.CopyTo(buffer.AsSpan(5));
        RandomNumberGenerator.Fill(buffer.AsSpan(5 + payload.Length, padding));

        var body = buffer.AsSpan(4, packetLength);
        if (keys is null)
        {
            // Plaintext before the first NEWKEYS.
        }
        else if (keys.IsAead)
        {
            keys.Gcm!.Encrypt(keys.GcmIv!, body, body, buffer.AsSpan(4 + packetLength, 16), buffer.AsSpan(0, 4));
            CryptoUtil.IncrementGcmCounter(keys.GcmIv!);
        }
        else if (keys.Etm)
        {
            keys.Ctr!.Transform(body);
            ComputeMac(keys, _seqOut, buffer.AsSpan(0, 4 + packetLength), buffer.AsSpan(4 + packetLength));
        }
        else
        {
            ComputeMac(keys, _seqOut, buffer.AsSpan(0, 4 + packetLength), buffer.AsSpan(4 + packetLength));
            keys.Ctr!.Transform(buffer.AsSpan(0, 4 + packetLength));
        }
        return buffer;
    }

    // ------------------------------------------------------------------ Receiving

    /// <summary>Returns the payload of the next packet; null on a clean end of the connection.</summary>
    public async ValueTask<byte[]?> ReadPacketAsync(CancellationToken ct)
    {
        var keys = _in;
        var blockSize = keys?.BlockSize ?? 8;
        var tagLength = keys?.TagLength ?? 0;

        byte[] packet;      // 4-byte length + plaintext (padlen, payload, padding)
        if (keys is not null && keys.LengthInClear)
        {
            var lenBytes = new byte[4];
            if (!await ReadExactAsync(lenBytes, ct)) return null;
            var length = ValidateLength(BinaryPrimitives.ReadUInt32BigEndian(lenBytes), blockSize, lengthIncluded: false);

            var rest = new byte[length + tagLength];
            if (!await ReadExactAsync(rest, ct)) throw new EndOfStreamException();
            packet = new byte[4 + length];
            lenBytes.CopyTo(packet, 0);

            if (keys.IsAead)
            {
                try
                {
                    keys.Gcm!.Decrypt(keys.GcmIv!, rest.AsSpan(0, length), rest.AsSpan(length, 16), packet.AsSpan(4), lenBytes);
                }
                catch (CryptographicException)
                {
                    throw new SshProtocolException("Packet authentication failed (GCM)", SshDisconnectReason.MacError);
                }
                CryptoUtil.IncrementGcmCounter(keys.GcmIv!);
            }
            else
            {
                rest.AsSpan(0, length).CopyTo(packet.AsSpan(4));
                var mac = new byte[keys.MacLength];
                ComputeMac(keys, _seqIn, packet, mac);           // ETM: MAC over length + ciphertext
                if (!CryptoUtil.FixedTimeEquals(mac, rest.AsSpan(length, tagLength)))
                    throw new SshProtocolException("MAC error", SshDisconnectReason.MacError);
                keys.Ctr!.Transform(packet.AsSpan(4));
            }
        }
        else
        {
            var first = new byte[blockSize];
            if (!await ReadExactAsync(first, ct)) return null;
            keys?.Ctr!.Transform(first);
            var length = ValidateLength(BinaryPrimitives.ReadUInt32BigEndian(first), blockSize, lengthIncluded: true);

            packet = new byte[4 + length];
            first.CopyTo(packet, 0);
            var remaining = 4 + length - blockSize;
            var rest = new byte[remaining + tagLength];
            if (!await ReadExactAsync(rest, ct)) throw new EndOfStreamException();
            rest.AsSpan(0, remaining).CopyTo(packet.AsSpan(blockSize));

            if (keys is not null)
            {
                keys.Ctr!.Transform(packet.AsSpan(blockSize));
                var mac = new byte[keys.MacLength];
                ComputeMac(keys, _seqIn, packet, mac);           // classic: MAC over plaintext
                if (!CryptoUtil.FixedTimeEquals(mac, rest.AsSpan(remaining, tagLength)))
                    throw new SshProtocolException("MAC error", SshDisconnectReason.MacError);
            }
        }

        var paddingLength = packet[4];
        var payloadLength = packet.Length - 5 - paddingLength;
        if (paddingLength < 4 || payloadLength < 1)
            throw new SshProtocolException("Invalid padding");

        _seqIn++;
        PacketsSinceKex++;
        var total = packet.Length + tagLength;
        BytesReceived += total;
        BytesSinceKexIn += total;
        return packet.AsSpan(5, payloadLength).ToArray();
    }

    private int ValidateLength(uint length, int blockSize, bool lengthIncluded)
    {
        if (length < 5 || length > _maxPacketLength)
            throw new SshProtocolException($"Invalid packet length {length}");
        if (((lengthIncluded ? length + 4 : length) % (uint)blockSize) != 0)
            throw new SshProtocolException("Packet length not aligned to block size");
        return (int)length;
    }

    private static void ComputeMac(DirectionKeys keys, uint sequence, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> seq = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(seq, sequence);
        keys.Mac!.AppendData(seq);
        keys.Mac.AppendData(data);
        keys.Mac.GetHashAndReset(destination);
    }

    private async ValueTask<bool> ReadExactAsync(Memory<byte> buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await _stream.ReadAsync(buffer[read..], ct);
            if (n == 0)
            {
                if (read == 0) return false;
                throw new EndOfStreamException("Connection closed in the middle of a packet");
            }
            read += n;
        }
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        _in?.Dispose();
        _out?.Dispose();
        await _stream.DisposeAsync();
    }
}
