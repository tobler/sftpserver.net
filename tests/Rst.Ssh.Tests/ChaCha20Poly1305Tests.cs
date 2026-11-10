using System;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Validates the ChaCha20 core, the Poly1305 authenticator and the chacha20-poly1305@openssh.com
/// AEAD against reference vectors from an independent implementation (Python's cryptography) and
/// the RFC 8439 Poly1305 test vector. End-to-end interop with OpenSSH is covered separately.
/// </summary>
public class ChaCha20Poly1305Tests
{
    private static byte[] Hex(string h) => Convert.FromHexString(h);

    [Fact]
    public void ChaCha20_AllZero_MatchesReferenceKeystream()
    {
        // RFC 7539 / Strombergson TC1: zero key, zero nonce, counter 0.
        var data = new byte[64];
        ChaCha20.XorKeyStream(data, new byte[32], new byte[8], 0);
        Assert.Equal(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
            + "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            Convert.ToHexString(data).ToLowerInvariant());
    }

    [Fact]
    public void ChaCha20_NonZeroNonceAndCounter_MatchesReferenceKeystream()
    {
        var key = new byte[32];
        for (var i = 0; i < 32; i++) key[i] = (byte)i;
        var nonce = Hex("000000000000004a");
        var data = new byte[64];
        ChaCha20.XorKeyStream(data, key, nonce, counter: 1);
        Assert.Equal(
            "51780e6d8dc1a1bda9c46adc892f56f2fe6365185365b9f15ec572f40d5adc69"
            + "89386f1e78af4b19194dd07f900043bed2cbf552b07b8fdfb5ea6063ddec158c",
            Convert.ToHexString(data).ToLowerInvariant());
    }

    [Fact]
    public void ChaCha20_XorIsInvolution()
    {
        var key = new byte[32];
        for (var i = 0; i < 32; i++) key[i] = (byte)(i * 3);
        var nonce = Hex("0102030405060708");
        var plain = new byte[200];
        for (var i = 0; i < plain.Length; i++) plain[i] = (byte)(i ^ 0x5a);

        var buf = (byte[])plain.Clone();
        ChaCha20.XorKeyStream(buf, key, nonce, 5);
        Assert.NotEqual(plain, buf);
        ChaCha20.XorKeyStream(buf, key, nonce, 5);
        Assert.Equal(plain, buf);
    }

    [Fact]
    public void Poly1305_Rfc8439_Vector()
    {
        var key = Hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var msg = "Cryptographic Forum Research Group"u8.ToArray();
        var tag = new byte[16];
        Poly1305.ComputeTag(key, msg, default, tag);
        Assert.Equal("a8061dc1305136c6c22b8baf0c0127a9", Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Poly1305_SplitInputMatchesOneShot()
    {
        var key = Hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var msg = "Cryptographic Forum Research Group"u8.ToArray();
        var tag = new byte[16];
        // 4-byte "aad" head + remainder, boundary not at a block edge
        Poly1305.ComputeTag(key, msg.AsSpan(0, 4), msg.AsSpan(4), tag);
        Assert.Equal("a8061dc1305136c6c22b8baf0c0127a9", Convert.ToHexString(tag).ToLowerInvariant());
    }

    // Reference packet for key = 00..3f, seq = 3, length field 0x00000012, 18-byte body.
    private static readonly byte[] Key64 = BuildRange(64);
    private const uint Seq = 3;
    private static readonly byte[] LengthField = Hex("00000012");
    private static readonly byte[] Body = Hex("0a68656c6c6f20636861636861deadbeef11");
    private static readonly byte[] ExpectedPacket = Hex("fb1a92988a2d79d75e258412e02e9f62da393bfd88cdc249a98a135517403603d65adc306df0");

    private static byte[] BuildRange(int n)
    {
        var b = new byte[n];
        for (var i = 0; i < n; i++) b[i] = (byte)i;
        return b;
    }

    [Fact]
    public void OpenSshAead_Encrypt_MatchesReferencePacket()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var packet = new byte[4 + Body.Length + ChaCha20Poly1305Cipher.TagLength];
        LengthField.CopyTo(packet, 0);
        Body.CopyTo(packet, 4);

        cipher.Encrypt(Seq, packet);
        Assert.Equal(ExpectedPacket, packet);
    }

    [Fact]
    public void OpenSshAead_DecryptLength_ReturnsPlaintextLength()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var encLen = ExpectedPacket.AsSpan(0, 4);
        Assert.Equal(18u, cipher.DecryptLength(Seq, encLen));
    }

    [Fact]
    public void OpenSshAead_VerifyAndDecrypt_RoundTrips()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var encLen = ExpectedPacket.AsSpan(0, 4).ToArray();
        var encBody = ExpectedPacket.AsSpan(4, Body.Length).ToArray();
        var tag = ExpectedPacket.AsSpan(4 + Body.Length, ChaCha20Poly1305Cipher.TagLength).ToArray();

        var body = new byte[Body.Length];
        Assert.True(cipher.VerifyAndDecryptBody(Seq, encLen, encBody, tag, body));
        Assert.Equal(Body, body);
    }

    [Fact]
    public void OpenSshAead_TamperedTag_IsRejected()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var encLen = ExpectedPacket.AsSpan(0, 4).ToArray();
        var encBody = ExpectedPacket.AsSpan(4, Body.Length).ToArray();
        var tag = ExpectedPacket.AsSpan(4 + Body.Length, ChaCha20Poly1305Cipher.TagLength).ToArray();
        tag[0] ^= 0x01;

        var body = new byte[Body.Length];
        Assert.False(cipher.VerifyAndDecryptBody(Seq, encLen, encBody, tag, body));
    }

    [Fact]
    public void OpenSshAead_TamperedCiphertext_IsRejected()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var encLen = ExpectedPacket.AsSpan(0, 4).ToArray();
        var encBody = ExpectedPacket.AsSpan(4, Body.Length).ToArray();
        var tag = ExpectedPacket.AsSpan(4 + Body.Length, ChaCha20Poly1305Cipher.TagLength).ToArray();
        encBody[2] ^= 0x80;

        var body = new byte[Body.Length];
        Assert.False(cipher.VerifyAndDecryptBody(Seq, encLen, encBody, tag, body));
    }

    [Fact]
    public void OpenSshAead_WrongSequence_IsRejected()
    {
        using var cipher = new ChaCha20Poly1305Cipher(Key64);
        var encLen = ExpectedPacket.AsSpan(0, 4).ToArray();
        var encBody = ExpectedPacket.AsSpan(4, Body.Length).ToArray();
        var tag = ExpectedPacket.AsSpan(4 + Body.Length, ChaCha20Poly1305Cipher.TagLength).ToArray();

        var body = new byte[Body.Length];
        Assert.False(cipher.VerifyAndDecryptBody(Seq + 1, encLen, encBody, tag, body));
    }
}
