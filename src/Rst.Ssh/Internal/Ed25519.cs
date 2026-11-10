using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>Ed25519 signatures (RFC 8032), for ssh-ed25519 host keys and client public-key auth.</summary>
/// <remarks>
/// Port of the reference implementation from TweetNaCl (Bernstein et al., public domain), built on the
/// same 16×16-bit limb field arithmetic as <see cref="X25519"/>. The scalar multiplication uses a
/// constant-time Montgomery-style ladder (cswap + unconditional add/double), so signing does not branch
/// on the secret scalar. Verification uses only public data. Validated against the RFC 8032 §7.1 vectors.
/// </remarks>
internal static class Ed25519
{
    // Field constants mod 2^255-19 (TweetNaCl gf[16], 16-bit little-endian limbs).
    private static readonly long[] Gf0 = new long[16];
    private static readonly long[] Gf1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private static readonly long[] D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
    private static readonly long[] D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
    private static readonly long[] X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
    private static readonly long[] Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
    private static readonly long[] I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

    // Group order L = 2^252 + 27742317777372353535851937790883648493 (little-endian bytes).
    private static readonly long[] L =
    [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    public const int KeySize = 32;
    public const int SignatureSize = 64;
    public const int SeedSize = 32;

    // ---- Public API --------------------------------------------------------------------

    public static (byte[] Seed, byte[] PublicKey) GenerateKeyPair()
    {
        var seed = RandomNumberGenerator.GetBytes(SeedSize);
        return (seed, PublicKeyFromSeed(seed));
    }

    /// <summary>Derives the 32-byte public key from a 32-byte seed.</summary>
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
    {
        var d = SHA512.HashData(seed);
        Clamp(d);
        var p = NewPoint();
        Scalarbase(p, d);
        var pk = new byte[KeySize];
        Pack(pk, p);
        CryptographicOperations.ZeroMemory(d);
        return pk;
    }

    /// <summary>Signs <paramref name="message"/>, returning the 64-byte signature (R ‖ S).</summary>
    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> publicKey)
    {
        var d = SHA512.HashData(seed);            // d[0..32) = clamped scalar a, d[32..64) = prefix
        Clamp(d);

        // r = SHA512(prefix ‖ M) mod L
        var prefixed = new byte[32 + message.Length];
        d.AsSpan(32, 32).CopyTo(prefixed);
        message.CopyTo(prefixed.AsSpan(32));
        var r = SHA512.HashData(prefixed);
        Reduce(r);

        var pr = NewPoint();
        Scalarbase(pr, r);
        var signature = new byte[SignatureSize];
        Pack(signature, pr);                      // signature[0..32) = R

        // h = SHA512(R ‖ A ‖ M) mod L
        var toHash = new byte[64 + message.Length];
        signature.AsSpan(0, 32).CopyTo(toHash);
        publicKey[..32].CopyTo(toHash.AsSpan(32));
        message.CopyTo(toHash.AsSpan(64));
        var h = SHA512.HashData(toHash);
        Reduce(h);

        // S = (r + h*a) mod L
        var x = new long[64];
        for (var i = 0; i < 32; i++) x[i] = r[i];
        for (var i = 0; i < 32; i++)
            for (var j = 0; j < 32; j++)
                x[i + j] += h[i] * (long)d[j];
        var s = new byte[32];
        ModL(s, x);
        s.CopyTo(signature.AsSpan(32));

        CryptographicOperations.ZeroMemory(d);
        return signature;
    }

    /// <summary>Verifies a 64-byte Ed25519 signature over <paramref name="message"/>. Returns false on any malformed input.</summary>
    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureSize || publicKey.Length != KeySize) return false;

        // Reject non-canonical S (S must be < L) to avoid malleability.
        if (!ScalarInRange(signature.Slice(32, 32))) return false;

        var q = NewPoint();
        if (!UnpackNeg(q, publicKey)) return false;   // q = -A

        var toHash = new byte[64 + message.Length];
        signature[..32].CopyTo(toHash);               // R
        publicKey.CopyTo(toHash.AsSpan(32));          // A
        message.CopyTo(toHash.AsSpan(64));
        var h = SHA512.HashData(toHash);
        Reduce(h);

        var p = NewPoint();
        Scalarmult(p, q, h);                          // p = h·(-A)
        var sb = NewPoint();
        Scalarbase(sb, signature.Slice(32, 32));      // sb = S·B
        Add(p, sb);                                   // p = S·B - h·A

        var t = new byte[32];
        Pack(t, p);
        return CryptographicOperations.FixedTimeEquals(t, signature[..32]);   // R == S·B - h·A ?
    }

    // ---- Scalar helpers ----------------------------------------------------------------

    private static void Clamp(byte[] d)
    {
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
    }

    /// <summary>True if the little-endian 32-byte scalar is strictly less than the group order L.</summary>
    private static bool ScalarInRange(ReadOnlySpan<byte> s)
    {
        for (var i = 31; i >= 0; i--)
        {
            if (s[i] < L[i]) return true;
            if (s[i] > L[i]) return false;
        }
        return false;   // equal to L is out of range
    }

    private static void ModL(byte[] r, long[] x)
    {
        long carry;
        int i, j = 0;
        for (i = 63; i >= 32; --i)
        {
            carry = 0;
            for (j = i - 32; j < i - 12; ++j)
            {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }
            x[j] += carry;
            x[i] = 0;
        }
        carry = 0;
        for (j = 0; j < 32; ++j)
        {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for (j = 0; j < 32; ++j) x[j] -= carry * L[j];
        for (i = 0; i < 32; ++i)
        {
            x[i + 1] += x[i] >> 8;
            r[i] = (byte)(x[i] & 255);
        }
    }

    private static void Reduce(byte[] r)
    {
        var x = new long[64];
        for (var i = 0; i < 64; i++) x[i] = r[i];
        Array.Clear(r, 0, r.Length);
        ModL(r, x);
    }

    // ---- Point arithmetic (extended coordinates P = {X, Y, Z, T}) ----------------------

    private static long[][] NewPoint() => [new long[16], new long[16], new long[16], new long[16]];

    private static void Set(long[] r, long[] a) => a.CopyTo(r, 0);

    private static void Scalarmult(long[][] p, long[][] q, ReadOnlySpan<byte> s)
    {
        Set(p[0], Gf0);
        Set(p[1], Gf1);
        Set(p[2], Gf1);
        Set(p[3], Gf0);
        for (var i = 255; i >= 0; --i)
        {
            var b = (byte)((s[i >> 3] >> (i & 7)) & 1);
            Cswap(p, q, b);
            Add(q, p);
            Add(p, p);
            Cswap(p, q, b);
        }
    }

    private static void Scalarbase(long[][] p, ReadOnlySpan<byte> s)
    {
        var q = NewPoint();
        Set(q[0], X);
        Set(q[1], Y);
        Set(q[2], Gf1);
        M(q[3], X, Y);
        Scalarmult(p, q, s);
    }

    private static void Cswap(long[][] p, long[][] q, byte b)
    {
        for (var i = 0; i < 4; i++) Sel25519(p[i], q[i], b);
    }

    private static void Add(long[][] p, long[][] q)
    {
        long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16];
        long[] t = new long[16], e = new long[16], f = new long[16], g = new long[16], h = new long[16];

        Z(a, p[1], p[0]);
        Z(t, q[1], q[0]);
        M(a, a, t);
        A(b, p[0], p[1]);
        A(t, q[0], q[1]);
        M(b, b, t);
        M(c, p[3], q[3]);
        M(c, c, D2);
        M(d, p[2], q[2]);
        A(d, d, d);
        Z(e, b, a);
        Z(f, d, c);
        A(g, d, c);
        A(h, b, a);

        M(p[0], e, f);
        M(p[1], h, g);
        M(p[2], g, f);
        M(p[3], e, h);
    }

    private static void Pack(byte[] r, long[][] p)
    {
        long[] tx = new long[16], ty = new long[16], zi = new long[16];
        Inv25519(zi, p[2]);
        M(tx, p[0], zi);
        M(ty, p[1], zi);
        Pack25519(r, ty);
        r[31] ^= (byte)(Par25519(tx) << 7);
    }

    /// <summary>Decodes a compressed point and returns its negation (−A), as TweetNaCl's unpackneg. False if invalid.</summary>
    private static bool UnpackNeg(long[][] r, ReadOnlySpan<byte> p)
    {
        long[] t = new long[16], chk = new long[16], num = new long[16], den = new long[16];
        long[] den2 = new long[16], den4 = new long[16], den6 = new long[16];

        Set(r[2], Gf1);
        Unpack25519(r[1], p);
        S(num, r[1]);            // y^2
        M(den, num, D);          // d*y^2
        Z(num, num, r[2]);       // y^2 - 1
        A(den, r[2], den);       // d*y^2 + 1

        S(den2, den);
        S(den4, den2);
        M(den6, den4, den2);
        M(t, den6, num);
        M(t, t, den);

        Pow2523(t, t);
        M(t, t, num);
        M(t, t, den);
        M(t, t, den);
        M(r[0], t, den);

        S(chk, r[0]);
        M(chk, chk, den);
        if (Neq25519(chk, num)) M(r[0], r[0], I);

        S(chk, r[0]);
        M(chk, chk, den);
        if (Neq25519(chk, num)) return false;

        if (Par25519(r[0]) == (p[31] >> 7)) Z(r[0], Gf0, r[0]);

        M(r[3], r[0], r[1]);
        return true;
    }

    // ---- Field arithmetic mod 2^255-19 -------------------------------------------------

    private static void Car25519(long[] o)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            var c = o[i] >> 16;
            if (i < 15) o[i + 1] += c - 1;
            else o[0] += 38 * (c - 1);
            o[i] -= c << 16;
        }
    }

    private static void Sel25519(long[] p, long[] q, long b)
    {
        var mask = ~(b - 1);
        for (var i = 0; i < 16; i++)
        {
            var t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack25519(byte[] o, long[] n)
    {
        long[] m = new long[16], t = new long[16];
        n.CopyTo(t, 0);
        Car25519(t); Car25519(t); Car25519(t);
        for (var j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            var b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            Sel25519(t, m, 1 - b);
        }
        for (var i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[2 * i + 1] = (byte)(t[i] >> 8);
        }
    }

    private static bool Neq25519(long[] a, long[] b)
    {
        byte[] c = new byte[32], d = new byte[32];
        Pack25519(c, a);
        Pack25519(d, b);
        return !CryptographicOperations.FixedTimeEquals(c, d);
    }

    private static byte Par25519(long[] a)
    {
        var d = new byte[32];
        Pack25519(d, a);
        return (byte)(d[0] & 1);
    }

    private static void Unpack25519(long[] o, ReadOnlySpan<byte> n)
    {
        for (var i = 0; i < 16; i++) o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }

    private static void A(long[] o, long[] a, long[] b)
    {
        for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
    }

    private static void Z(long[] o, long[] a, long[] b)
    {
        for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
    }

    private static void M(long[] o, long[] a, long[] b)
    {
        var t = new long[31];
        for (var i = 0; i < 16; i++)
            for (var j = 0; j < 16; j++)
                t[i + j] += a[i] * b[j];
        for (var i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        for (var i = 0; i < 16; i++) o[i] = t[i];
        Car25519(o);
        Car25519(o);
    }

    private static void S(long[] o, long[] a) => M(o, a, a);

    private static void Inv25519(long[] o, long[] i)
    {
        var c = new long[16];
        i.CopyTo(c, 0);
        for (var a = 253; a >= 0; a--)
        {
            S(c, c);
            if (a != 2 && a != 4) M(c, c, i);
        }
        c.CopyTo(o, 0);
    }

    private static void Pow2523(long[] o, long[] i)
    {
        var c = new long[16];
        i.CopyTo(c, 0);
        for (var a = 250; a >= 0; a--)
        {
            S(c, c);
            if (a != 1) M(c, c, i);
        }
        c.CopyTo(o, 0);
    }
}
