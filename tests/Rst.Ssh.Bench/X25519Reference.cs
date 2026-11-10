using System.Numerics;
using System.Security.Cryptography;

namespace BenchRef;

/// <summary>Old BigInteger reference implementation – kept only as a test oracle.</summary>
/// <remarks>NOT constant-time. Do not use in production code.</remarks>
internal static class X25519Reference
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger A24 = 121665;
    private static readonly byte[] BasePoint = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public static (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        return (priv, ScalarMult(priv, BasePoint));
    }

    public static byte[] ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32) throw new ArgumentException();

        Span<byte> k = stackalloc byte[32];
        scalar.CopyTo(k);
        k[0] &= 248; k[31] &= 127; k[31] |= 64;

        Span<byte> u = stackalloc byte[32];
        uCoordinate.CopyTo(u);
        u[31] &= 127;

        var kn = new BigInteger(k, isUnsigned: true, isBigEndian: false);
        var x1 = new BigInteger(u, isUnsigned: true, isBigEndian: false) % P;
        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        var swap = 0;

        for (var t = 254; t >= 0; t--)
        {
            var kt = (int)((kn >> t) & 1);
            swap ^= kt;
            if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
            swap = kt;

            var a = (x2 + z2) % P;
            var aa = a * a % P;
            var b = Mod(x2 - z2);
            var bb = b * b % P;
            var e = Mod(aa - bb);
            var c = (x3 + z3) % P;
            var d = Mod(x3 - z3);
            var da = d * a % P;
            var cb = c * b % P;
            x3 = BigInteger.Pow((da + cb) % P, 2) % P;
            z3 = x1 * BigInteger.Pow(Mod(da - cb), 2) % P;
            x2 = aa * bb % P;
            z2 = e * ((aa + A24 * e) % P) % P;
        }
        if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }

        var result = x2 * BigInteger.ModPow(z2, P - 2, P) % P;
        var output = new byte[32];
        result.TryWriteBytes(output, out _, isUnsigned: true, isBigEndian: false);
        return output;
    }

    private static BigInteger Mod(BigInteger v) => ((v % P) + P) % P;
}

