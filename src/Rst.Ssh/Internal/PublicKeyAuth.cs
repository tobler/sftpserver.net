using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>
/// Verifies client public-key authentication signatures (RFC 4252 §7).
/// RSA and ECDSA are handled with the .NET BCL; ssh-ed25519 support is added separately.
/// </summary>
internal static class PublicKeyAuth
{
    /// <summary>Public-key algorithms the server accepts for authentication, in preference order.</summary>
    public static readonly string[] SupportedAlgorithms =
    [
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "rsa-sha2-512", "rsa-sha2-256",
    ];

    public static bool IsSupported(string algorithm) => Array.IndexOf(SupportedAlgorithms, algorithm) >= 0;

    /// <summary>
    /// Verifies <paramref name="signature"/> (an SSH signature blob) over <paramref name="signedData"/>
    /// using the public key in <paramref name="keyBlob"/>, for the named <paramref name="algorithm"/>.
    /// Returns false on any malformed input rather than throwing.
    /// </summary>
    public static bool Verify(string algorithm, ReadOnlySpan<byte> keyBlob, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signedData)
    {
        try
        {
            var key = new SshReader(keyBlob.ToArray());
            var keyType = key.ReadString();

            if (keyType == "ssh-rsa" && algorithm is "rsa-sha2-256" or "rsa-sha2-512")
                return VerifyRsa(algorithm, key, signature, signedData);

            if (keyType == algorithm && keyType.StartsWith("ecdsa-sha2-nistp", StringComparison.Ordinal))
                return VerifyEcdsa(keyType, key, signature, signedData);

            return false;
        }
        catch (Exception e) when (e is SshProtocolException or FormatException or CryptographicException or ArgumentException or IndexOutOfRangeException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool VerifyRsa(string algorithm, SshReader key, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signedData)
    {
        var e = Unsigned(key.ReadBinary());
        var n = Unsigned(key.ReadBinary());
        using var rsa = RSA.Create(new RSAParameters { Exponent = e, Modulus = n });

        if (ReadSignatureBlob(signature, algorithm) is not { } sig) return false;
        var hash = algorithm == "rsa-sha2-512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
        return rsa.VerifyData(signedData, sig, hash, RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyEcdsa(string keyType, SshReader key, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signedData)
    {
        _ = key.ReadString();                        // curve name ("nistp256" …) – implied by keyType
        var q = key.ReadBinary();                    // 0x04 || X || Y (uncompressed point)

        var (curve, hash, coord) = keyType switch
        {
            "ecdsa-sha2-nistp256" => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, 32),
            "ecdsa-sha2-nistp384" => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, 48),
            "ecdsa-sha2-nistp521" => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, 66),
            _ => throw new FormatException("Unsupported ECDSA curve"),
        };
        if (q.Length != 1 + 2 * coord || q[0] != 4) return false;

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = q.Slice(1, coord).ToArray(), Y = q.Slice(1 + coord, coord).ToArray() },
        });

        // Signature blob: string(keyType) string( mpint(r) || mpint(s) ).
        var outer = new SshReader(signature.ToArray());
        if (outer.ReadString() != keyType) return false;
        var inner = new SshReader(outer.ReadBinary().ToArray());
        var r = inner.ReadBinary();
        var s = inner.ReadBinary();

        var p1363 = new byte[2 * coord];
        RightAlign(r, p1363.AsSpan(0, coord));
        RightAlign(s, p1363.AsSpan(coord, coord));
        return ecdsa.VerifyData(signedData, p1363, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>Reads an SSH signature blob (string algorithm, string signature) and returns the signature bytes if the algorithm matches.</summary>
    private static byte[]? ReadSignatureBlob(ReadOnlySpan<byte> signature, string expectedAlgorithm)
    {
        var r = new SshReader(signature.ToArray());
        return r.ReadString() == expectedAlgorithm ? r.ReadBinaryArray() : null;
    }

    /// <summary>Strips the leading sign byte / zeros of an SSH mpint to get the unsigned big-endian magnitude.</summary>
    private static byte[] Unsigned(ReadOnlySpan<byte> mpint)
    {
        var i = 0;
        while (i < mpint.Length - 1 && mpint[i] == 0) i++;
        return mpint[i..].ToArray();
    }

    /// <summary>Right-aligns a big-endian magnitude into a fixed-width field (left-pads with zeros, drops any sign byte).</summary>
    private static void RightAlign(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        while (value.Length > destination.Length && value[0] == 0) value = value[1..];
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }
}
