using System;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>FIPS 202 known-answer tests for the self-contained Keccak/SHA-3/SHAKE used by ML-KEM.</summary>
public class KeccakTests
{
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void Sha3_256_Empty()
        => Assert.Equal("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", Hex(Keccak.Sha3_256([])));

    [Fact]
    public void Sha3_256_Abc()
        => Assert.Equal("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", Hex(Keccak.Sha3_256("abc"u8)));

    [Fact]
    public void Sha3_512_Empty()
        => Assert.Equal(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            Hex(Keccak.Sha3_512([])));

    [Fact]
    public void Sha3_512_Abc()
        => Assert.Equal(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            Hex(Keccak.Sha3_512("abc"u8)));

    [Fact]
    public void Shake128_Empty_32()
        => Assert.Equal("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", Hex(Keccak.Shake128([], 32)));

    [Fact]
    public void Shake256_Empty_32()
        => Assert.Equal("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", Hex(Keccak.Shake256([], 32)));

    [Fact]
    public void Shake256_Empty_64()
        => Assert.Equal(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            Hex(Keccak.Shake256([], 64)));

    [Fact]
    public void Shake128_StreamingMatchesOneShot()
    {
        var input = "The quick brown fox"u8.ToArray();
        var oneShot = Keccak.Shake128(input, 500);

        var sponge = new Keccak.Sponge(168, 0x1F);
        sponge.Absorb(input);
        var a = new byte[200];
        var b = new byte[300];
        sponge.Squeeze(a);
        sponge.Squeeze(b);
        var streamed = new byte[500];
        a.CopyTo(streamed, 0);
        b.CopyTo(streamed, 200);

        Assert.Equal(oneShot, streamed);
    }
}
