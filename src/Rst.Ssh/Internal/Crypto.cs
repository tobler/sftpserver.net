using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>AES in CTR mode (RFC 4344), built on AES-ECB from the BCL (AES-NI).</summary>
/// <remarks>
/// The keystream is generated in 16 KB chunks at once (one ECB call instead of many small ones);
/// the XOR is vectorized (AVX2/SSE/NEON via Vector&lt;byte&gt;).
/// </remarks>
internal sealed class AesCtr : IDisposable
{
    private const int ChunkBlocks = 1024;
    private readonly Aes _aes;
    private ulong _counterHigh, _counterLow;
    private readonly byte[] _counterBlocks = new byte[ChunkBlocks * 16];
    private readonly byte[] _keystream = new byte[ChunkBlocks * 16];
    private int _pos = ChunkBlocks * 16;

    public AesCtr(byte[] key, byte[] iv)
    {
        _aes = Aes.Create();
        _aes.Key = key;
        _counterHigh = BinaryPrimitives.ReadUInt64BigEndian(iv);
        _counterLow = BinaryPrimitives.ReadUInt64BigEndian(iv.AsSpan(8));
    }

    public void Transform(Span<byte> data)
    {
        while (!data.IsEmpty)
        {
            if (_pos == _keystream.Length) Refill();
            var n = Math.Min(data.Length, _keystream.Length - _pos);
            Xor(data[..n], _keystream.AsSpan(_pos, n));
            data = data[n..];
            _pos += n;
        }
    }

    private void Refill()
    {
        var blocks = _counterBlocks.AsSpan();
        for (var b = 0; b < ChunkBlocks; b++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(blocks.Slice(b * 16), _counterHigh);
            BinaryPrimitives.WriteUInt64BigEndian(blocks.Slice(b * 16 + 8), _counterLow);
            if (++_counterLow == 0) _counterHigh++;          // 128-bit counter, big endian
        }
        _aes.EncryptEcb(_counterBlocks, _keystream, PaddingMode.None);
        _pos = 0;
    }

    internal static void Xor(Span<byte> data, ReadOnlySpan<byte> keystream)
    {
        var i = 0;
        if (Vector.IsHardwareAccelerated && data.Length >= Vector<byte>.Count)
        {
            var d = MemoryMarshal.Cast<byte, Vector<byte>>(data);
            var k = MemoryMarshal.Cast<byte, Vector<byte>>(keystream);
            for (var v = 0; v < d.Length; v++) d[v] ^= k[v];
            i = d.Length * Vector<byte>.Count;
        }
        for (; i < data.Length; i++) data[i] ^= keystream[i];
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_keystream);
        _aes.Dispose();
    }
}

/// <summary>X25519 (RFC 7748), constant-time.</summary>
/// <remarks>
/// Port of the field arithmetic from TweetNaCl (Bernstein et al., public domain): 16 limbs of 16 bits in Int64.
/// No branches and no memory access depend on the secret scalar – the ladder swap uses bit masks
/// (Sel25519), the inversion a fixed exponent chain. Only conditions on indices/constants (public) branch.
/// </remarks>
internal static class X25519
{
    private static readonly byte[] BasePoint = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private static readonly long[] A24 = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];   // 121665

    public static (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        return (priv, ScalarMult(priv, BasePoint));
    }

    public static byte[] ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32) throw new SshProtocolException("Invalid Curve25519 key length");

        Span<byte> z = stackalloc byte[32];
        scalar.CopyTo(z);
        z[31] = (byte)((z[31] & 127) | 64);
        z[0] &= 248;

        Span<long> x = stackalloc long[16];
        Span<long> a = stackalloc long[16], b = stackalloc long[16], c = stackalloc long[16];
        Span<long> d = stackalloc long[16], e = stackalloc long[16], f = stackalloc long[16];
        Span<long> t = stackalloc long[31];

        Unpack(x, uCoordinate);
        x.CopyTo(b);
        a.Clear(); c.Clear(); d.Clear();
        a[0] = d[0] = 1;

        for (var i = 254; i >= 0; --i)
        {
            long r = (z[i >> 3] >> (i & 7)) & 1;
            Sel(a, b, r);
            Sel(c, d, r);
            Add(e, a, c);
            Sub(a, a, c);
            Add(c, b, d);
            Sub(b, b, d);
            Mul(d, e, e, t);
            Mul(f, a, a, t);
            Mul(a, c, a, t);
            Mul(c, b, e, t);
            Add(e, a, c);
            Sub(a, a, c);
            Mul(b, a, a, t);
            Sub(c, d, f);
            Mul(a, c, A24, t);
            Add(a, a, d);
            Mul(c, c, a, t);
            Mul(a, d, f, t);
            Mul(d, b, x, t);
            Mul(b, e, e, t);
            Sel(a, b, r);
            Sel(c, d, r);
        }

        Invert(c, c, t);
        Mul(a, a, c, t);
        var output = new byte[32];
        Pack(output, a);

        CryptographicOperations.ZeroMemory(z);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(a));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(b));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(c));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(d));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(e));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(f));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(t));
        return output;
    }

    // ---- Field arithmetic mod 2^255-19 -------------------------------------------------

    internal static void Unpack(Span<long> o, ReadOnlySpan<byte> n)
    {
        for (var i = 0; i < 16; i++) o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }

    private static void Carry(Span<long> o)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            var c = o[i] >> 16;
            if (i < 15) o[i + 1] += c - 1;            // branches only on the (public) index
            else o[0] += 38 * (c - 1);
            o[i] -= c << 16;
        }
    }

    /// <summary>Swaps p and q if b == 1 – without branching.</summary>
    private static void Sel(Span<long> p, Span<long> q, long b)
    {
        var mask = ~(b - 1);
        for (var i = 0; i < 16; i++)
        {
            var t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    internal static void Pack(Span<byte> o, ReadOnlySpan<long> n)
    {
        Span<long> m = stackalloc long[16];
        Span<long> t = stackalloc long[16];
        n.CopyTo(t);
        Carry(t); Carry(t); Carry(t);
        for (var j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            var borrow = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            Sel(t, m, 1 - borrow);
        }
        for (var i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[2 * i + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Add(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
    }

    private static void Sub(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
    }

    /// <summary>o = a * b. o may alias a or b (intermediate result in t).</summary>
    internal static void Mul(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b, Span<long> t)
    {
        t.Clear();
        for (var i = 0; i < 16; i++)
        {
            var ai = a[i];
            for (var j = 0; j < 16; j++) t[i + j] += ai * b[j];
        }
        for (var i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        t[..16].CopyTo(o);
        Carry(o);
        Carry(o);
    }

    /// <summary>o = i^(p-2) – fixed sequence of squarings/multiplications (the exponent is public).</summary>
    internal static void Invert(Span<long> o, ReadOnlySpan<long> input, Span<long> t)
    {
        Span<long> c = stackalloc long[16];
        Span<long> inv = stackalloc long[16];
        input.CopyTo(inv);
        input.CopyTo(c);
        for (var a = 253; a >= 0; a--)
        {
            Mul(c, c, c, t);
            if (a != 2 && a != 4) Mul(c, c, inv, t);
        }
        c.CopyTo(o);
    }
}

internal static class CryptoUtil
{
    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => CryptographicOperations.FixedTimeEquals(a, b);

    public static void IncrementGcmCounter(byte[] iv)
    {
        var counter = BinaryPrimitives.ReadUInt64BigEndian(iv.AsSpan(4));
        BinaryPrimitives.WriteUInt64BigEndian(iv.AsSpan(4), counter + 1);
    }
}
