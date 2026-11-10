using System.Linq;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Validates the Ed25519 port (RFC 8032) against reference vectors produced by an independent
/// implementation (OpenSSL via Python's cryptography): public keys derived from fixed seeds and
/// signatures over fixed messages must match byte for byte, and Verify must accept/reject correctly.
/// </summary>
public class Ed25519Tests
{
    // Messages matching the reference generator: "", "abc", and 1000 bytes of (i*7 & 0xff).
    private static byte[] Message(string name) => name switch
    {
        "empty" => [],
        "abc" => "abc"u8.ToArray(),
        "long" => Enumerable.Range(0, 1000).Select(i => (byte)((i * 7) & 0xff)).ToArray(),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static byte[] Hex(string h) => Convert.FromHexString(h);

    public static TheoryData<string, string> PublicKeys => new()
    {
        { "0000000000000000000000000000000000000000000000000000000000000000", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29" },
        { "0100000000000000000000000000000000000000000000000000000000000000", "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc" },
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8" },
    };

    // seed, message name, public key, signature.
    public static TheoryData<string, string, string, string> Signatures => new()
    {
        { "0000000000000000000000000000000000000000000000000000000000000000", "empty", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", "8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803" },
        { "0000000000000000000000000000000000000000000000000000000000000000", "abc", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", "885dfb07cab2796eb960531a2f09b972ad59b97bb125bef5fdda0855d6bebebf24447e705fa11575639df396c201ccf52a1a16b014a7a2f0ce73a7a161757308" },
        { "0000000000000000000000000000000000000000000000000000000000000000", "long", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", "81f60ebbc36beecf9b54d9470d70daea37f5a44ad9d723be9e37825a9bb1eec1b72856e5dd1819595308e07fa38769cdf9f695abf5d67b732a0f83b3e282d80b" },
        { "0100000000000000000000000000000000000000000000000000000000000000", "empty", "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc", "6c9e53d9cf36b71c2950235f954ade00118285c93209d07c98acc8496ab5fa4c88b197d0ce46df3402253b1a1d318e264893f033b51bf99ffeff42eb4a4d4302" },
        { "0100000000000000000000000000000000000000000000000000000000000000", "abc", "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc", "cb49a07be599ce1003713e447ca2cbbfe8a96af0d1b934f0ee4718b0ef735987af4631db851ff2990b7c3e4c852453e0bc9f74ba486ca408324bbd200d881608" },
        { "0100000000000000000000000000000000000000000000000000000000000000", "long", "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc", "f4309aa9b0ea39106f57a871bbe368a00b7b7827e664aa50c38afbe7ad05338f6a505637e93d8f9c940667d2385ab8ad55a7d28705aa8d931e53fe38e1a34502" },
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "empty", "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5", "ee00ac6e44a6a43bc3a701c137b467473e32a4bed47d3293fe6186fe9868c7d254024f65ffa552487bdbd34aaccd1e82c1a20a191d183dbb64c3523cccd89c0f" },
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "abc", "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5", "aec6ab6a9122aff0f7dcb9667ff613136894732b6e78c26f5b673101e267fe2e2b65fa4d53dad478a1ada64d50fd1dfdb7d94920dc3e1a564a647b1cba356001" },
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "long", "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5", "80d09833dbfe75ace8d1cb0be3b96d6684028e0dceb250a740b95e0fd92f889ca64a0dca529696dcc23c9ea8426a208aa661b1d40cec4ddb9d71af80f62a6901" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "empty", "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "abc", "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "cc46d62d3754f41754b27b6ea2cb2c272bafa7a5a1f6062bd060f414e50caaeac2da66ad39cef4424a90236ea907b7d8057e3443dc5abfc9986967ee7213a407" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "long", "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "da6136076b66c252328353c96dd2a80675f9962be64159d7236711c1963f5ec671baea9a53f1944e9856fd61d15f3e67ebdb35cc57ac06c4ce75c0cdc925420b" },
    };

    [Theory]
    [MemberData(nameof(PublicKeys))]
    public void Public_key_derivation_matches_reference(string seedHex, string pubHex)
    {
        Assert.Equal(pubHex, Convert.ToHexString(Ed25519.PublicKeyFromSeed(Hex(seedHex))).ToLowerInvariant());
    }

    [Theory]
    [MemberData(nameof(Signatures))]
    public void Signing_matches_reference(string seedHex, string msgName, string pubHex, string sigHex)
    {
        var sig = Ed25519.Sign(Message(msgName), Hex(seedHex), Hex(pubHex));
        Assert.Equal(sigHex, Convert.ToHexString(sig).ToLowerInvariant());
    }

    [Theory]
    [MemberData(nameof(Signatures))]
    public void Verify_accepts_valid_signatures(string seedHex, string msgName, string pubHex, string sigHex)
    {
        _ = seedHex;
        Assert.True(Ed25519.Verify(Message(msgName), Hex(sigHex), Hex(pubHex)));
    }

    [Fact]
    public void Verify_rejects_tampered_signature_message_and_key()
    {
        var seed = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var pub = Hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        var msg = "abc"u8.ToArray();
        var sig = Ed25519.Sign(msg, seed, pub);

        Assert.True(Ed25519.Verify(msg, sig, pub));

        var tamperedSig = (byte[])sig.Clone();
        tamperedSig[10] ^= 0x01;
        Assert.False(Ed25519.Verify(msg, tamperedSig, pub));

        Assert.False(Ed25519.Verify("abd"u8, sig, pub));          // wrong message

        var wrongPub = Hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
        Assert.False(Ed25519.Verify(msg, sig, wrongPub));         // wrong key
    }

    [Fact]
    public void Verify_rejects_malformed_inputs()
    {
        var pub = Hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        Assert.False(Ed25519.Verify("x"u8, new byte[63], pub));   // short signature
        Assert.False(Ed25519.Verify("x"u8, new byte[64], new byte[31]));  // short key
    }

    [Fact]
    public void Verify_rejects_non_canonical_scalar()
    {
        var seed = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var pub = Hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        var msg = "abc"u8.ToArray();
        var sig = Ed25519.Sign(msg, seed, pub);

        // Set S to L itself (little-endian) – a non-canonical scalar that must be rejected.
        byte[] l = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
        l.CopyTo(sig.AsSpan(32));
        Assert.False(Ed25519.Verify(msg, sig, pub));
    }

    [Fact]
    public void Generated_key_pair_round_trips()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        Assert.Equal(pub, Ed25519.PublicKeyFromSeed(seed));
        var msg = "round trip"u8.ToArray();
        Assert.True(Ed25519.Verify(msg, Ed25519.Sign(msg, seed, pub), pub));
    }
}
