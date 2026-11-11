using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>
/// ML-KEM-768 (FIPS 203), the post-quantum KEM used by the mlkem768x25519-sha256 hybrid key
/// exchange. Self-contained port of the FIPS 203 pseudocode / CRYSTALS-Kyber reference arithmetic;
/// it relies only on <see cref="Keccak"/> (SHA3/SHAKE) from this assembly.
/// </summary>
/// <remarks>
/// The SSH server only needs <see cref="Encapsulate"/> (the client sends the encapsulation key),
/// but key generation and decapsulation are implemented too for self-tests and completeness.
/// </remarks>
internal static class MlKem768
{
    private const int N = 256;
    private const int Q = 3329;
    private const int K = 3;
    private const int Eta = 2;            // η1 = η2 = 2
    private const int Du = 10, Dv = 4;
    private const short QInv = unchecked((short)62209);   // q^-1 mod 2^16
    private const short MontR2 = 1353;    // 2^32 mod q  (for conversion into Montgomery domain)

    public const int EncapsKeyLength = 384 * K + 32;          // 1184
    public const int DecapsKeyLength = 768 * K + 96;          // 2400
    public const int CiphertextLength = 32 * (Du * K + Dv);   // 1088
    public const int SharedSecretLength = 32;

    // Montgomery-domain twiddle factors (CRYSTALS-Kyber reference zetas table).
    private static readonly short[] Zetas =
    [
        -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
        573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
        1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
        -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
        -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653,
        -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75,
        817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
        -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
    ];

    // ---------------------------------------------------------------- field arithmetic

    private static short MontgomeryReduce(int a)
    {
        var t = (short)(a * QInv);
        return (short)((a - t * Q) >> 16);
    }

    private static short BarrettReduce(short a)
    {
        const int v = ((1 << 26) + Q / 2) / Q;   // 20159
        var t = (short)((v * a + (1 << 25)) >> 26);
        return (short)(a - t * Q);
    }

    private static short FqMul(short a, short b) => MontgomeryReduce(a * b);

    /// <summary>Maps each coefficient to its canonical representative in [0, Q).</summary>
    private static void ToUnsigned(short[] p)
    {
        for (var i = 0; i < N; i++)
        {
            var t = BarrettReduce(p[i]);
            p[i] = (short)(t + ((t >> 15) & Q));
        }
    }

    // ---------------------------------------------------------------- polynomial ops

    private static void Ntt(short[] r)
    {
        var k = 1;
        for (var len = 128; len >= 2; len >>= 1)
            for (var start = 0; start < N; start += 2 * len)
            {
                var zeta = Zetas[k++];
                for (var j = start; j < start + len; j++)
                {
                    var t = FqMul(zeta, r[j + len]);
                    r[j + len] = (short)(r[j] - t);
                    r[j] = (short)(r[j] + t);
                }
            }
        for (var i = 0; i < N; i++) r[i] = BarrettReduce(r[i]);
    }

    private static void InvNtt(short[] r)
    {
        const short f = 1441;        // mont^2 / 128
        var k = 127;
        for (var len = 2; len <= 128; len <<= 1)
            for (var start = 0; start < N; start += 2 * len)
            {
                var zeta = Zetas[k--];
                for (var j = start; j < start + len; j++)
                {
                    var t = r[j];
                    r[j] = BarrettReduce((short)(t + r[j + len]));
                    r[j + len] = (short)(r[j + len] - t);
                    r[j + len] = FqMul(zeta, r[j + len]);
                }
            }
        for (var i = 0; i < N; i++) r[i] = FqMul(r[i], f);
    }

    /// <summary>Base multiplication of two degree-255 polynomials in the NTT domain.</summary>
    private static short[] BaseMul(short[] a, short[] b)
    {
        var r = new short[N];
        for (var i = 0; i < N / 4; i++)
        {
            BaseCase(a, b, r, 4 * i, Zetas[64 + i]);
            BaseCase(a, b, r, 4 * i + 2, (short)-Zetas[64 + i]);
        }
        return r;
    }

    private static void BaseCase(short[] a, short[] b, short[] r, int o, short zeta)
    {
        r[o] = (short)(FqMul(FqMul(a[o + 1], b[o + 1]), zeta) + FqMul(a[o], b[o]));
        r[o + 1] = (short)(FqMul(a[o], b[o + 1]) + FqMul(a[o + 1], b[o]));
    }

    private static void ToMont(short[] p) { for (var i = 0; i < N; i++) p[i] = FqMul(p[i], MontR2); }
    private static void Add(short[] r, short[] a) { for (var i = 0; i < N; i++) r[i] = (short)(r[i] + a[i]); }

    // ---------------------------------------------------------------- encode / decode

    /// <summary>Packs 256 d-bit coefficients into 32·d bytes (FIPS 203 ByteEncode).</summary>
    private static byte[] ByteEncode(short[] coeffs, int d)
    {
        var outBytes = new byte[32 * d];
        var bit = 0;
        foreach (var c in coeffs)
            for (var i = 0; i < d; i++)
            {
                if (((c >> i) & 1) != 0) outBytes[bit >> 3] |= (byte)(1 << (bit & 7));
                bit++;
            }
        return outBytes;
    }

    private static short[] ByteDecode(ReadOnlySpan<byte> data, int d)
    {
        var coeffs = new short[N];
        var bit = 0;
        for (var c = 0; c < N; c++)
        {
            var value = 0;
            for (var i = 0; i < d; i++)
            {
                value |= ((data[bit >> 3] >> (bit & 7)) & 1) << i;
                bit++;
            }
            coeffs[c] = (short)(d == 12 ? value % Q : value);
        }
        return coeffs;
    }

    // ---------------------------------------------------------------- compression

    private static short Compress(short x, int d) => (short)(((((x < 0 ? x + Q : x) << d) + Q / 2) / Q) & ((1 << d) - 1));
    private static short Decompress(short y, int d) => (short)((Q * y + (1 << (d - 1))) >> d);

    private static short[] CompressPoly(short[] p, int d)
    {
        var r = new short[N];
        for (var i = 0; i < N; i++) r[i] = Compress(p[i], d);
        return r;
    }

    private static short[] DecompressPoly(short[] p, int d)
    {
        var r = new short[N];
        for (var i = 0; i < N; i++) r[i] = Decompress(p[i], d);
        return r;
    }

    // ---------------------------------------------------------------- sampling

    /// <summary>Samples a polynomial in the NTT domain by rejection sampling from SHAKE128 (FIPS 203 Algorithm 7).</summary>
    private static short[] SampleNtt(ReadOnlySpan<byte> rho, byte b0, byte b1)
    {
        Span<byte> seed = stackalloc byte[34];
        rho.CopyTo(seed);
        seed[32] = b0;
        seed[33] = b1;

        var sponge = new Keccak.Sponge(168, 0x1F);
        sponge.Absorb(seed);

        var a = new short[N];
        var count = 0;
        Span<byte> three = stackalloc byte[3];
        while (count < N)
        {
            sponge.Squeeze(three);
            int d1 = three[0] + 256 * (three[1] & 0x0F);
            int d2 = (three[1] >> 4) + 16 * three[2];
            if (d1 < Q) a[count++] = (short)d1;
            if (d2 < Q && count < N) a[count++] = (short)d2;
        }
        return a;
    }

    /// <summary>Centered binomial distribution with η = 2 (FIPS 203 Algorithm 8).</summary>
    private static short[] SampleCbd2(ReadOnlySpan<byte> buf)
    {
        var r = new short[N];
        for (var i = 0; i < N / 8; i++)
        {
            uint t = buf[4 * i] | ((uint)buf[4 * i + 1] << 8) | ((uint)buf[4 * i + 2] << 16) | ((uint)buf[4 * i + 3] << 24);
            var d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;
            for (var j = 0; j < 8; j++)
            {
                var x = (short)((d >> (4 * j)) & 0x3);
                var y = (short)((d >> (4 * j + 2)) & 0x3);
                r[8 * i + j] = (short)(x - y);
            }
        }
        return r;
    }

    private static short[] PrfCbd(ReadOnlySpan<byte> sigma, byte nonce)
    {
        Span<byte> input = stackalloc byte[33];
        sigma.CopyTo(input);
        input[32] = nonce;
        return SampleCbd2(Keccak.Shake256(input, 64 * Eta));
    }

    // ---------------------------------------------------------------- K-PKE

    private static (byte[] EkPke, byte[] DkPke) KPkeKeyGen(ReadOnlySpan<byte> d)
    {
        Span<byte> gInput = stackalloc byte[33];
        d.CopyTo(gInput);
        gInput[32] = K;
        var g = Keccak.Sha3_512(gInput);
        var rho = g.AsSpan(0, 32);
        var sigma = g.AsSpan(32, 32);

        var a = GenMatrix(rho);
        var s = new short[K][];
        var e = new short[K][];
        byte nonce = 0;
        for (var i = 0; i < K; i++) { s[i] = PrfCbd(sigma, nonce++); Ntt(s[i]); }
        for (var i = 0; i < K; i++) { e[i] = PrfCbd(sigma, nonce++); Ntt(e[i]); }

        var t = new short[K][];
        for (var i = 0; i < K; i++)
        {
            t[i] = new short[N];
            for (var j = 0; j < K; j++) Add(t[i], BaseMul(a[i][j], s[j]));
            ToMont(t[i]);
            Add(t[i], e[i]);
            ToUnsigned(t[i]);
        }

        var ek = new byte[EncapsKeyLength];
        for (var i = 0; i < K; i++) ByteEncode(t[i], 12).CopyTo(ek, i * 384);
        rho.CopyTo(ek.AsSpan(384 * K));

        var dk = new byte[384 * K];
        for (var i = 0; i < K; i++) { ToUnsigned(s[i]); ByteEncode(s[i], 12).CopyTo(dk, i * 384); }
        return (ek, dk);
    }

    private static byte[] KPkeEncrypt(ReadOnlySpan<byte> ek, ReadOnlySpan<byte> m, ReadOnlySpan<byte> r)
    {
        var t = new short[K][];
        for (var i = 0; i < K; i++) t[i] = ByteDecode(ek.Slice(i * 384, 384), 12);
        var rho = ek.Slice(384 * K, 32);
        var a = GenMatrix(rho);

        var y = new short[K][];
        var e1 = new short[K][];
        byte nonce = 0;
        for (var i = 0; i < K; i++) { y[i] = PrfCbd(r, nonce++); Ntt(y[i]); }
        for (var i = 0; i < K; i++) e1[i] = PrfCbd(r, nonce++);
        var e2 = PrfCbd(r, nonce);

        // u = InvNTT(A^T ∘ ŷ) + e1
        var u = new short[K][];
        for (var i = 0; i < K; i++)
        {
            u[i] = new short[N];
            for (var j = 0; j < K; j++) Add(u[i], BaseMul(a[j][i], y[j]));   // A^T: a[j][i]
            InvNtt(u[i]);
            Add(u[i], e1[i]);
        }

        // v = InvNTT(t̂^T ∘ ŷ) + e2 + Decompress1(m)
        var v = new short[N];
        for (var i = 0; i < K; i++) Add(v, BaseMul(t[i], y[i]));
        InvNtt(v);
        Add(v, e2);
        Add(v, DecompressPoly(ByteDecode(m, 1), 1));

        var c1 = new byte[32 * Du * K];
        for (var i = 0; i < K; i++) ByteEncode(CompressPoly(u[i], Du), Du).CopyTo(c1, i * 32 * Du);
        var c2 = ByteEncode(CompressPoly(v, Dv), Dv);

        var c = new byte[CiphertextLength];
        c1.CopyTo(c, 0);
        c2.CopyTo(c, c1.Length);
        return c;
    }

    private static byte[] KPkeDecrypt(ReadOnlySpan<byte> dkPke, ReadOnlySpan<byte> c)
    {
        var u = new short[K][];
        for (var i = 0; i < K; i++)
        {
            u[i] = DecompressPoly(ByteDecode(c.Slice(i * 32 * Du, 32 * Du), Du), Du);
            Ntt(u[i]);
        }
        var v = DecompressPoly(ByteDecode(c.Slice(32 * Du * K, 32 * Dv), Dv), Dv);

        var s = new short[K][];
        for (var i = 0; i < K; i++) s[i] = ByteDecode(dkPke.Slice(i * 384, 384), 12);

        var w = new short[N];
        for (var i = 0; i < K; i++) Add(w, BaseMul(s[i], u[i]));
        InvNtt(w);
        for (var i = 0; i < N; i++) w[i] = (short)(v[i] - w[i]);

        return ByteEncode(CompressPoly(w, 1), 1);
    }

    private static short[][][] GenMatrix(ReadOnlySpan<byte> rho)
    {
        var a = new short[K][][];
        for (var i = 0; i < K; i++)
        {
            a[i] = new short[K][];
            for (var j = 0; j < K; j++) a[i][j] = SampleNtt(rho, (byte)j, (byte)i);
        }
        return a;
    }

    // ---------------------------------------------------------------- ML-KEM (FO transform)

    internal static (byte[] Ek, byte[] Dk) KeyGenInternal(ReadOnlySpan<byte> d, ReadOnlySpan<byte> z)
    {
        var (ekPke, dkPke) = KPkeKeyGen(d);
        var dk = new byte[DecapsKeyLength];
        dkPke.CopyTo(dk, 0);
        ekPke.CopyTo(dk, 384 * K);
        Keccak.Sha3_256(ekPke).CopyTo(dk, 768 * K + 32);
        z.CopyTo(dk.AsSpan(768 * K + 64));
        return (ekPke, dk);
    }

    internal static (byte[] SharedSecret, byte[] Ciphertext) EncapsInternal(ReadOnlySpan<byte> ek, ReadOnlySpan<byte> m)
    {
        Span<byte> gInput = stackalloc byte[64];
        m.CopyTo(gInput);
        Keccak.Sha3_256(ek).CopyTo(gInput[32..]);
        var g = Keccak.Sha3_512(gInput);
        var sharedSecret = g[..32];
        var r = g.AsSpan(32, 32);
        var c = KPkeEncrypt(ek, m, r);
        return (sharedSecret, c);
    }

    internal static byte[] DecapsInternal(ReadOnlySpan<byte> dk, ReadOnlySpan<byte> c)
    {
        var dkPke = dk[..(384 * K)];
        var ekPke = dk.Slice(384 * K, EncapsKeyLength);
        var h = dk.Slice(768 * K + 32, 32);
        var z = dk.Slice(768 * K + 64, 32);

        var m = KPkeDecrypt(dkPke, c);

        Span<byte> gInput = stackalloc byte[64];
        m.CopyTo(gInput);
        h.CopyTo(gInput[32..]);
        var g = Keccak.Sha3_512(gInput);
        var kPrime = g[..32];
        var r = g.AsSpan(32, 32);

        Span<byte> jInput = stackalloc byte[32 + CiphertextLength];
        z.CopyTo(jInput);
        c.CopyTo(jInput[32..]);
        var kReject = Keccak.Shake256(jInput, 32);

        var cPrime = KPkeEncrypt(ekPke, m, r);
        var match = CryptographicOperations.FixedTimeEquals(c, cPrime);
        return match ? kPrime : kReject;
    }

    // ---------------------------------------------------------------- public API

    public static (byte[] Ek, byte[] Dk) GenerateKeyPair()
        => KeyGenInternal(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));

    /// <summary>Server side of the KEX: produces a shared secret and a ciphertext for the given encapsulation key.</summary>
    public static (byte[] SharedSecret, byte[] Ciphertext) Encapsulate(ReadOnlySpan<byte> ek)
    {
        if (ek.Length != EncapsKeyLength) throw new SshProtocolException("Invalid ML-KEM-768 encapsulation key length");
        ValidateEncapsKey(ek);
        return EncapsInternal(ek, RandomNumberGenerator.GetBytes(32));
    }

    /// <summary>
    /// FIPS 203 §7.2 "modulus check": every packed 12-bit coefficient of t̂ must be a canonical
    /// residue (&lt; q), i.e. ByteEncode12(ByteDecode12(ek)) == ek. Rejects malformed keys.
    /// </summary>
    private static void ValidateEncapsKey(ReadOnlySpan<byte> ek)
    {
        var bit = 0;
        for (var c = 0; c < N * K; c++)
        {
            var value = 0;
            for (var i = 0; i < 12; i++) { value |= ((ek[bit >> 3] >> (bit & 7)) & 1) << i; bit++; }
            if (value >= Q) throw new SshProtocolException("Invalid ML-KEM-768 encapsulation key (non-canonical coefficient)");
        }
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> dk, ReadOnlySpan<byte> c)
    {
        if (c.Length != CiphertextLength) throw new SshProtocolException("Invalid ML-KEM-768 ciphertext length");
        return DecapsInternal(dk, c);
    }
}
