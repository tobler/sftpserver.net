using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

public class CryptoTests
{
    // RFC 7748 §5.2 and §6.1
    [Fact]
    public void X25519_RFC7748_test_vector()
    {
        var k = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        var u = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", Convert.ToHexString(X25519.ScalarMult(k, u)).ToLowerInvariant());
    }

    [Fact]
    public void X25519_Diffie_Hellman_RFC7748()
    {
        var alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPriv = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        var basePoint = new byte[32]; basePoint[0] = 9;
        var alicePub = X25519.ScalarMult(alicePriv, basePoint);
        var bobPub = X25519.ScalarMult(bobPriv, basePoint);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Convert.ToHexString(alicePub).ToLowerInvariant());
        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Convert.ToHexString(X25519.ScalarMult(alicePriv, bobPub)).ToLowerInvariant());
        Assert.Equal(X25519.ScalarMult(alicePriv, bobPub), X25519.ScalarMult(bobPriv, alicePub));
    }

    [Fact]
    public void SshWriter_mpint_per_RFC4251()
    {
        Assert.Equal("00000000", Convert.ToHexString(new SshWriter().MPIntFromUnsigned([0]).ToArray()));
        Assert.Equal("000000020080", Convert.ToHexString(new SshWriter().MPIntFromUnsigned([0x80]).ToArray()));
        Assert.Equal("0000000809A378F9B2E332A7", Convert.ToHexString(new SshWriter().MPIntFromUnsigned([0, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]).ToArray()));
    }
}

public class CryptoTests2
{
    [Fact]
    public void X25519_matches_reference_for_1000_random_values()
    {
        for (var i = 0; i < 1000; i++)
        {
            var k = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var u = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            Assert.Equal(X25519Reference.ScalarMult(k, u), X25519.ScalarMult(k, u));
        }
    }

    [Fact]
    public void X25519_edge_cases()
    {
        var k = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        // u = 0, u = p (≡ 0), u = p-1, u with bit 255 set, u = 2^255-1
        var cases = new[]
        {
            new byte[32],
            Convert.FromHexString("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            Convert.FromHexString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            Convert.FromHexString("0900000000000000000000000000000000000000000000000000000000000080"),
            Convert.FromHexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        };
        foreach (var u in cases) Assert.Equal(X25519Reference.ScalarMult(k, u), X25519.ScalarMult(k, u));
    }

    // RFC 7748 §5.2: 1000 iterations
    [Fact]
    public void X25519_RFC7748_1000_iterations()
    {
        var k = new byte[32]; k[0] = 9;
        var u = (byte[])k.Clone();
        for (var i = 0; i < 1000; i++)
        {
            var r = X25519.ScalarMult(k, u);
            u = k; k = r;
        }
        Assert.Equal("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Convert.ToHexString(k).ToLowerInvariant());
    }

    // NIST SP 800-38A F.5.1 (AES-128-CTR)
    [Fact]
    public void AesCtr_NIST_test_vector_and_arbitrary_chunking()
    {
        var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plain = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        var expected = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

        var data = (byte[])plain.Clone();
        using (var ctr = new AesCtr(key, iv)) ctr.Transform(data);
        Assert.Equal(expected, Convert.ToHexString(data).ToLowerInvariant());

        // Processing in odd-sized chunks (1, 7, 13 … bytes) must give the same result
        data = (byte[])plain.Clone();
        using (var ctr = new AesCtr(key, iv))
        {
            var pos = 0; var size = 1;
            while (pos < data.Length) { var n = Math.Min(size, data.Length - pos); ctr.Transform(data.AsSpan(pos, n)); pos += n; size += 6; }
        }
        Assert.Equal(expected, Convert.ToHexString(data).ToLowerInvariant());
    }

    [Fact]
    public void AesCtr_counter_overflow_and_large_data_match_reference()
    {
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var iv = Convert.FromHexString("00000000000000fffffffffffffffff0");   // lower word overflows right away
        var data = System.Security.Cryptography.RandomNumberGenerator.GetBytes(100_000);

        var ours = (byte[])data.Clone();
        using (var ctr = new AesCtr(key, iv)) { ctr.Transform(ours.AsSpan(0, 33333)); ctr.Transform(ours.AsSpan(33333)); }

        // Reference: build counter blocks with BigInteger, encrypt with ECB, XOR
        using var aes = System.Security.Cryptography.Aes.Create(); aes.Key = key;
        var counter = new System.Numerics.BigInteger(iv, isUnsigned: true, isBigEndian: true);
        var reference = (byte[])data.Clone();
        for (var off = 0; off < reference.Length; off += 16)
        {
            var block = new byte[16];
            var cb = (counter % System.Numerics.BigInteger.Pow(2, 128)).ToByteArray(isUnsigned: true, isBigEndian: true);
            cb.CopyTo(block, 16 - cb.Length);
            var ks = aes.EncryptEcb(block, System.Security.Cryptography.PaddingMode.None);
            for (var j = 0; j < 16 && off + j < reference.Length; j++) reference[off + j] ^= ks[j];
            counter++;
        }
        Assert.Equal(reference, ours);
    }
}
