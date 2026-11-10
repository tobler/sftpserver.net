using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>
/// ChaCha20 stream cipher (Bernstein / RFC 8439 core) with the original 64-bit counter + 64-bit
/// nonce layout that OpenSSH's chacha20-poly1305@openssh.com uses (not the IETF 96-bit-nonce AEAD
/// that <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> exposes).
/// </summary>
internal static class ChaCha20
{
    // "expand 32-byte k"
    private const uint C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574;

    /// <summary>XORs the ChaCha20 keystream for the given 8-byte nonce and starting block counter into <paramref name="data"/>.</summary>
    public static void XorKeyStream(Span<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ulong counter)
    {
        Span<uint> state = stackalloc uint[16];
        state[0] = C0; state[1] = C1; state[2] = C2; state[3] = C3;
        for (var i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        state[12] = (uint)counter;
        state[13] = (uint)(counter >> 32);
        state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[..4]);
        state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));

        Span<byte> block = stackalloc byte[64];
        var offset = 0;
        while (offset < data.Length)
        {
            Block(state, block);
            var n = Math.Min(64, data.Length - offset);
            for (var i = 0; i < n; i++) data[offset + i] ^= block[i];
            offset += n;

            if (++state[12] == 0) state[13]++;      // 64-bit block counter
        }
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
        CryptographicOperations.ZeroMemory(block);
    }

    private static void Block(ReadOnlySpan<uint> state, Span<byte> output)
    {
        uint x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3];
        uint x4 = state[4], x5 = state[5], x6 = state[6], x7 = state[7];
        uint x8 = state[8], x9 = state[9], x10 = state[10], x11 = state[11];
        uint x12 = state[12], x13 = state[13], x14 = state[14], x15 = state[15];

        for (var i = 0; i < 10; i++)
        {
            Quarter(ref x0, ref x4, ref x8, ref x12);
            Quarter(ref x1, ref x5, ref x9, ref x13);
            Quarter(ref x2, ref x6, ref x10, ref x14);
            Quarter(ref x3, ref x7, ref x11, ref x15);
            Quarter(ref x0, ref x5, ref x10, ref x15);
            Quarter(ref x1, ref x6, ref x11, ref x12);
            Quarter(ref x2, ref x7, ref x8, ref x13);
            Quarter(ref x3, ref x4, ref x9, ref x14);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output[0..], x0 + state[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[4..], x1 + state[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[8..], x2 + state[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[12..], x3 + state[3]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[16..], x4 + state[4]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[20..], x5 + state[5]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[24..], x6 + state[6]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[28..], x7 + state[7]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[32..], x8 + state[8]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[36..], x9 + state[9]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[40..], x10 + state[10]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[44..], x11 + state[11]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[48..], x12 + state[12]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[52..], x13 + state[13]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[56..], x14 + state[14]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[60..], x15 + state[15]);
    }

    private static void Quarter(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d ^= a; d = BitOperations.RotateLeft(d, 16);
        c += d; b ^= c; b = BitOperations.RotateLeft(b, 12);
        a += b; d ^= a; d = BitOperations.RotateLeft(d, 8);
        c += d; b ^= c; b = BitOperations.RotateLeft(b, 7);
    }
}

/// <summary>Poly1305 one-time authenticator (RFC 8439 §2.5). Port of the public-domain poly1305-donna 32-bit variant.</summary>
internal ref struct Poly1305
{
    private readonly uint _r0, _r1, _r2, _r3, _r4;
    private readonly uint _s1, _s2, _s3, _s4;      // r[1..4] * 5
    private readonly uint _pad0, _pad1, _pad2, _pad3;
    private uint _h0, _h1, _h2, _h3, _h4;
    private Span<byte> _buffer;                      // leftover bytes (< 16)
    private int _leftover;

    public Poly1305(ReadOnlySpan<byte> key, Span<byte> scratch16)
    {
        // r &= 0xffffffc0ffffffc0ffffffc0fffffff  (clamp)
        _r0 = Load(key, 0) & 0x3ffffff;
        _r1 = (Load(key, 3) >> 2) & 0x3ffff03;
        _r2 = (Load(key, 6) >> 4) & 0x3ffc0ff;
        _r3 = (Load(key, 9) >> 6) & 0x3f03fff;
        _r4 = (Load(key, 12) >> 8) & 0x00fffff;
        _s1 = _r1 * 5; _s2 = _r2 * 5; _s3 = _r3 * 5; _s4 = _r4 * 5;
        _pad0 = Load(key, 16); _pad1 = Load(key, 20); _pad2 = Load(key, 24); _pad3 = Load(key, 28);
        _h0 = _h1 = _h2 = _h3 = _h4 = 0;
        _buffer = scratch16;
        _leftover = 0;
    }

    private static uint Load(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.Slice(o, 4));

    public void Update(ReadOnlySpan<byte> data)
    {
        if (_leftover > 0)
        {
            var want = Math.Min(16 - _leftover, data.Length);
            data[..want].CopyTo(_buffer[_leftover..]);
            _leftover += want;
            data = data[want..];
            if (_leftover < 16) return;
            Blocks(_buffer, final: false);
            _leftover = 0;
        }

        while (data.Length >= 16)
        {
            Blocks(data[..16], final: false);
            data = data[16..];
        }

        if (!data.IsEmpty)
        {
            data.CopyTo(_buffer);
            _leftover = data.Length;
        }
    }

    public void Finish(Span<byte> tag)
    {
        if (_leftover > 0)
        {
            _buffer[_leftover] = 1;
            _buffer[(_leftover + 1)..16].Clear();
            Blocks(_buffer[..16], final: true);
        }

        // fully carry h
        uint h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
        uint c = h1 >> 26; h1 &= 0x3ffffff;
        h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
        h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
        h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        // compute h + -p
        uint g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        uint g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        uint g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        uint g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        uint g4 = h4 + c - (1u << 26);

        // select h if h < p, or h + -p if h >= p
        var mask = (g4 >> 31) - 1;        // 0 if borrow (h < p), else 0xffffffff
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % 2^128
        h0 = h0 | (h1 << 26);
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        // mac = (h + pad) % 2^128
        ulong f = (ulong)h0 + _pad0; h0 = (uint)f;
        f = (ulong)h1 + _pad1 + (f >> 32); h1 = (uint)f;
        f = (ulong)h2 + _pad2 + (f >> 32); h2 = (uint)f;
        f = (ulong)h3 + _pad3 + (f >> 32); h3 = (uint)f;

        BinaryPrimitives.WriteUInt32LittleEndian(tag[0..], h0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], h1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], h2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], h3);
    }

    private void Blocks(ReadOnlySpan<byte> m, bool final)
    {
        var hibit = final ? 0u : 1u << 24;   // 2^128

        _h0 += Load(m, 0) & 0x3ffffff;
        _h1 += (Load(m, 3) >> 2) & 0x3ffffff;
        _h2 += (Load(m, 6) >> 4) & 0x3ffffff;
        _h3 += (Load(m, 9) >> 6) & 0x3ffffff;
        _h4 += (Load(m, 12) >> 8) | hibit;

        ulong d0 = (ulong)_h0 * _r0 + (ulong)_h1 * _s4 + (ulong)_h2 * _s3 + (ulong)_h3 * _s2 + (ulong)_h4 * _s1;
        ulong d1 = (ulong)_h0 * _r1 + (ulong)_h1 * _r0 + (ulong)_h2 * _s4 + (ulong)_h3 * _s3 + (ulong)_h4 * _s2;
        ulong d2 = (ulong)_h0 * _r2 + (ulong)_h1 * _r1 + (ulong)_h2 * _r0 + (ulong)_h3 * _s4 + (ulong)_h4 * _s3;
        ulong d3 = (ulong)_h0 * _r3 + (ulong)_h1 * _r2 + (ulong)_h2 * _r1 + (ulong)_h3 * _r0 + (ulong)_h4 * _s4;
        ulong d4 = (ulong)_h0 * _r4 + (ulong)_h1 * _r3 + (ulong)_h2 * _r2 + (ulong)_h3 * _r1 + (ulong)_h4 * _r0;

        uint c = (uint)(d0 >> 26); _h0 = (uint)d0 & 0x3ffffff;
        d1 += c; c = (uint)(d1 >> 26); _h1 = (uint)d1 & 0x3ffffff;
        d2 += c; c = (uint)(d2 >> 26); _h2 = (uint)d2 & 0x3ffffff;
        d3 += c; c = (uint)(d3 >> 26); _h3 = (uint)d3 & 0x3ffffff;
        d4 += c; c = (uint)(d4 >> 26); _h4 = (uint)d4 & 0x3ffffff;
        _h0 += c * 5; c = _h0 >> 26; _h0 &= 0x3ffffff;
        _h1 += c;
    }

    /// <summary>One-shot tag over the concatenation of <paramref name="a"/> and <paramref name="b"/>.</summary>
    public static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> tag)
    {
        Span<byte> scratch = stackalloc byte[16];
        var mac = new Poly1305(key, scratch);
        mac.Update(a);
        mac.Update(b);
        mac.Finish(tag);
    }
}

/// <summary>
/// The chacha20-poly1305@openssh.com AEAD (see OpenSSH PROTOCOL.chacha20poly1305). 512-bit key
/// split into K_2 (first 256 bits, payload + Poly1305 key) and K_1 (second 256 bits, packet length).
/// The packet sequence number is the nonce.
/// </summary>
internal sealed class ChaCha20Poly1305Cipher : IDisposable
{
    public const int KeyLength = 64;
    public const int TagLength = 16;

    private readonly byte[] _mainKey = new byte[32];     // K_2
    private readonly byte[] _headerKey = new byte[32];   // K_1

    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength) throw new SshProtocolException("Invalid chacha20-poly1305 key length");
        key[..32].CopyTo(_mainKey);
        key.Slice(32, 32).CopyTo(_headerKey);
    }

    private static void Nonce(uint sequence, Span<byte> nonce) => BinaryPrimitives.WriteUInt64BigEndian(nonce, sequence);

    /// <summary>
    /// Encrypts a packet in place. <paramref name="packet"/> holds the 4-byte length, the body, and a
    /// 16-byte slot for the tag; i.e. its length is 4 + bodyLength + 16.
    /// </summary>
    public void Encrypt(uint sequence, Span<byte> packet)
    {
        Span<byte> nonce = stackalloc byte[8];
        Nonce(sequence, nonce);

        Span<byte> polyKey = stackalloc byte[32];
        ChaCha20.XorKeyStream(polyKey, _mainKey, nonce, 0);          // block 0 -> Poly1305 key

        var cipherText = packet[..^TagLength];                      // length (4) + body
        ChaCha20.XorKeyStream(cipherText[..4], _headerKey, nonce, 0); // length with K_1
        ChaCha20.XorKeyStream(cipherText[4..], _mainKey, nonce, 1);   // body with K_2, block 1

        Poly1305.ComputeTag(polyKey, cipherText, default, packet[^TagLength..]);
        CryptographicOperations.ZeroMemory(polyKey);
    }

    /// <summary>Decrypts the 4-byte length field only (needed to know how much more to read).</summary>
    public uint DecryptLength(uint sequence, ReadOnlySpan<byte> encryptedLength)
    {
        Span<byte> nonce = stackalloc byte[8];
        Nonce(sequence, nonce);
        Span<byte> length = stackalloc byte[4];
        encryptedLength.CopyTo(length);
        ChaCha20.XorKeyStream(length, _headerKey, nonce, 0);
        return BinaryPrimitives.ReadUInt32BigEndian(length);
    }

    /// <summary>
    /// Verifies the Poly1305 tag over (encrypted length ‖ encrypted body) and, on success, decrypts the
    /// body into <paramref name="bodyOut"/>. Returns false on authentication failure.
    /// </summary>
    public bool VerifyAndDecryptBody(uint sequence, ReadOnlySpan<byte> encryptedLength,
        ReadOnlySpan<byte> encryptedBody, ReadOnlySpan<byte> tag, Span<byte> bodyOut)
    {
        Span<byte> nonce = stackalloc byte[8];
        Nonce(sequence, nonce);

        Span<byte> polyKey = stackalloc byte[32];
        ChaCha20.XorKeyStream(polyKey, _mainKey, nonce, 0);

        Span<byte> expected = stackalloc byte[TagLength];
        Poly1305.ComputeTag(polyKey, encryptedLength, encryptedBody, expected);
        CryptographicOperations.ZeroMemory(polyKey);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag)) return false;

        encryptedBody.CopyTo(bodyOut);
        ChaCha20.XorKeyStream(bodyOut, _mainKey, nonce, 1);
        return true;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_mainKey);
        CryptographicOperations.ZeroMemory(_headerKey);
    }
}
