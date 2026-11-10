using Rst.Ssh;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Tests the ssh-ed25519 host key: blob/algorithm wiring, that its handshake signatures verify the
/// same way a client's would (same wire format), and PKCS#8 PEM save/load round-trips.
/// </summary>
public class Ed25519HostKeyTests
{
    [Fact]
    public void Generated_host_key_has_expected_shape()
    {
        using var key = HostKey.GenerateEd25519();
        Assert.Equal("ssh-ed25519", key.KeyType);
        Assert.Equal(["ssh-ed25519"], key.SignatureAlgorithms);
        Assert.StartsWith("SHA256:", key.Fingerprint);
        Assert.StartsWith("ssh-ed25519 ", key.PublicKeyLine);

        var reader = new SshReader(key.PublicKeyBlob);
        Assert.Equal("ssh-ed25519", reader.ReadString());
        Assert.Equal(Ed25519.KeySize, reader.ReadBinary().Length);     // 32-byte public point
    }

    [Fact]
    public void Host_key_signature_verifies_as_an_ssh_ed25519_signature()
    {
        using var key = HostKey.GenerateEd25519();
        var data = "exchange hash H"u8.ToArray();

        var signatureBlob = key.Sign("ssh-ed25519", data);

        // The host-key signature blob and public-key blob use the same wire format the client verifier reads.
        Assert.True(PublicKeyAuth.Verify("ssh-ed25519", key.PublicKeyBlob, signatureBlob, data));
        Assert.False(PublicKeyAuth.Verify("ssh-ed25519", key.PublicKeyBlob, signatureBlob, "other"u8));
    }

    [Fact]
    public void Pem_round_trips_through_pkcs8()
    {
        using var original = HostKey.GenerateEd25519();
        var pem = original.ExportPem();
        Assert.Contains("BEGIN PRIVATE KEY", pem);

        using var loaded = HostKey.LoadPem(pem);
        Assert.Equal("ssh-ed25519", loaded.KeyType);
        Assert.Equal(original.PublicKeyBlob, loaded.PublicKeyBlob);     // same key material

        // A signature from the reloaded key still verifies against the original public blob.
        var data = "persisted key"u8.ToArray();
        Assert.True(PublicKeyAuth.Verify("ssh-ed25519", original.PublicKeyBlob, loaded.Sign("ssh-ed25519", data), data));
    }
}
