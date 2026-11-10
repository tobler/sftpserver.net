using System.Security.Cryptography;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Round-trip tests for client public-key signature verification (RFC 4252 §7): build an SSH
/// public-key blob and signature the way an OpenSSH client would, then check PublicKeyAuth.Verify.
/// </summary>
public class PublicKeyAuthTests
{
    private static readonly byte[] Data = "data to be signed during userauth"u8.ToArray();

    [Theory]
    [InlineData("rsa-sha2-256")]
    [InlineData("rsa-sha2-512")]
    public void Rsa_signature_round_trips(string algorithm)
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var blob = new SshWriter().String("ssh-rsa").MPIntFromUnsigned(p.Exponent!).MPIntFromUnsigned(p.Modulus!).ToArray();

        var hash = algorithm == "rsa-sha2-512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
        var raw = rsa.SignData(Data, hash, RSASignaturePadding.Pkcs1);
        var sig = new SshWriter().String(algorithm).Binary(raw).ToArray();

        Assert.True(PublicKeyAuth.Verify(algorithm, blob, sig, Data));
        Assert.False(PublicKeyAuth.Verify(algorithm, blob, sig, "different data"u8));     // wrong signed data
        raw[10] ^= 0xFF;
        var tampered = new SshWriter().String(algorithm).Binary(raw).ToArray();
        Assert.False(PublicKeyAuth.Verify(algorithm, blob, tampered, Data));              // tampered signature
    }

    [Theory]
    [InlineData("ecdsa-sha2-nistp256", 256, 32)]
    [InlineData("ecdsa-sha2-nistp384", 384, 48)]
    [InlineData("ecdsa-sha2-nistp521", 521, 66)]
    public void Ecdsa_signature_round_trips(string keyType, int bits, int coord)
    {
        var curve = bits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ecdsa = ECDsa.Create(curve);
        var p = ecdsa.ExportParameters(false);

        var point = new byte[1 + 2 * coord];
        point[0] = 4;
        RightPad(p.Q.X!, point.AsSpan(1, coord));
        RightPad(p.Q.Y!, point.AsSpan(1 + coord, coord));
        var blob = new SshWriter().String(keyType).String(keyType["ecdsa-sha2-".Length..]).Binary(point).ToArray();

        var hash = bits switch { 256 => HashAlgorithmName.SHA256, 384 => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
        var p1363 = ecdsa.SignData(Data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var inner = new SshWriter().MPIntFromUnsigned(p1363.AsSpan(0, coord)).MPIntFromUnsigned(p1363.AsSpan(coord)).ToArray();
        var sig = new SshWriter().String(keyType).Binary(inner).ToArray();

        Assert.True(PublicKeyAuth.Verify(keyType, blob, sig, Data));
        Assert.False(PublicKeyAuth.Verify(keyType, blob, sig, "different data"u8));
    }

    [Fact]
    public void Ed25519_signature_round_trips()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var blob = new SshWriter().String("ssh-ed25519").Binary(pub).ToArray();

        var raw = Ed25519.Sign(Data, seed, pub);
        var sig = new SshWriter().String("ssh-ed25519").Binary(raw).ToArray();

        Assert.True(PublicKeyAuth.Verify("ssh-ed25519", blob, sig, Data));
        Assert.False(PublicKeyAuth.Verify("ssh-ed25519", blob, sig, "different data"u8));   // wrong signed data
        raw[10] ^= 0xFF;
        var tampered = new SshWriter().String("ssh-ed25519").Binary(raw).ToArray();
        Assert.False(PublicKeyAuth.Verify("ssh-ed25519", blob, tampered, Data));            // tampered signature
    }

    [Fact]
    public void Unsupported_algorithms_are_rejected()
    {
        Assert.True(PublicKeyAuth.IsSupported("ssh-ed25519"));
        Assert.False(PublicKeyAuth.IsSupported("ssh-rsa"));       // SHA-1, intentionally not accepted
        Assert.True(PublicKeyAuth.IsSupported("rsa-sha2-256"));
        Assert.True(PublicKeyAuth.IsSupported("ecdsa-sha2-nistp256"));
        Assert.False(PublicKeyAuth.Verify("ssh-ed25519", [1, 2, 3], [4, 5, 6], Data));   // malformed blob
    }

    private static void RightPad(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        while (value.Length > destination.Length && value[0] == 0) value = value[1..];
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }
}
