using System;
using System.Security.Cryptography;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>ML-KEM-768 (FIPS 203): round-trip consistency, implicit rejection, and size invariants.</summary>
public class MlKem768Tests
{
    [Fact]
    public void RoundTrip_SharedSecretsMatch()
    {
        var (ek, dk) = MlKem768.GenerateKeyPair();
        Assert.Equal(MlKem768.EncapsKeyLength, ek.Length);
        Assert.Equal(MlKem768.DecapsKeyLength, dk.Length);

        var (ssEnc, ct) = MlKem768.Encapsulate(ek);
        Assert.Equal(MlKem768.CiphertextLength, ct.Length);
        Assert.Equal(MlKem768.SharedSecretLength, ssEnc.Length);

        var ssDec = MlKem768.Decapsulate(dk, ct);
        Assert.Equal(ssEnc, ssDec);
    }

    [Fact]
    public void RoundTrip_ManyIterations()
    {
        for (var i = 0; i < 25; i++)
        {
            var (ek, dk) = MlKem768.GenerateKeyPair();
            var (ss, ct) = MlKem768.Encapsulate(ek);
            Assert.Equal(ss, MlKem768.Decapsulate(dk, ct));
        }
    }

    [Fact]
    public void TamperedCiphertext_ImplicitReject_DoesNotMatch()
    {
        var (ek, dk) = MlKem768.GenerateKeyPair();
        var (ss, ct) = MlKem768.Encapsulate(ek);
        ct[100] ^= 0x01;
        var ssDec = MlKem768.Decapsulate(dk, ct);
        Assert.NotEqual(ss, ssDec);                // implicit rejection yields an unrelated key
        Assert.Equal(MlKem768.SharedSecretLength, ssDec.Length);
    }

    [Fact]
    public void Decaps_IsDeterministicForImplicitReject()
    {
        // The rejection key depends only on (z, c), so decapsulating the same bad ct twice is stable.
        var (_, dk) = MlKem768.GenerateKeyPair();
        var badCt = RandomNumberGenerator.GetBytes(MlKem768.CiphertextLength);
        Assert.Equal(MlKem768.Decapsulate(dk, badCt), MlKem768.Decapsulate(dk, badCt));
    }
}
