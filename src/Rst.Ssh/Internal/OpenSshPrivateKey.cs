using System.Numerics;
using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>
/// Parser for the "openssh-key-v1" private key format (what <c>ssh-keygen</c> writes by default,
/// <c>-----BEGIN OPENSSH PRIVATE KEY-----</c>). Unencrypted keys only (cipher/kdf "none"); a
/// passphrase-protected key needs the bcrypt KDF, which is not implemented.
/// See OpenSSH PROTOCOL.key.
/// </summary>
internal static class OpenSshPrivateKey
{
    private static ReadOnlySpan<byte> Magic => "openssh-key-v1\0"u8;

    public static bool TryImport(string pem, out HostKey key)
    {
        key = null!;
        if (!PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "OPENSSH PRIVATE KEY") return false;

        byte[] data;
        try { data = Convert.FromBase64String(pem[fields.Base64Data].Replace("\n", "").Replace("\r", "")); }
        catch (FormatException) { return false; }

        if (data.Length < Magic.Length || !data.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            return false;

        var r = new SshReader(data.AsMemory(Magic.Length));
        var cipherName = r.ReadAscii();
        var kdfName = r.ReadAscii();
        r.ReadBinary();                      // kdfoptions
        var keyCount = r.ReadUInt32();
        r.ReadBinary();                      // public key (recomputed from the private half)
        var privateSection = r.ReadBinary();

        if (cipherName != "none" || kdfName != "none")
            throw new NotSupportedException(
                "This OpenSSH key is passphrase-protected (bcrypt); decrypt it first with " +
                "`ssh-keygen -p -f <key>` (empty new passphrase) or convert it with `ssh-keygen -p -m PEM -f <key>`.");
        if (keyCount != 1)
            throw new SshProtocolException($"Unsupported OpenSSH key file with {keyCount} keys");

        var p = new SshReader(privateSection.ToArray());
        if (p.ReadUInt32() != p.ReadUInt32())
            throw new SshProtocolException("Corrupt OpenSSH private key (check bytes differ)");

        key = p.ReadAscii() switch
        {
            "ssh-ed25519" => ReadEd25519(p),
            "ssh-rsa" => ReadRsa(p),
            var t when t.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) => ReadEcdsa(p, t),
            var t => throw new SshProtocolException($"Unsupported OpenSSH key type {t}"),
        };
        return true;
    }

    private static HostKey ReadEd25519(SshReader p)
    {
        p.ReadBinary();                      // public key (32 bytes)
        var priv = p.ReadBinary();           // 64 bytes: seed ‖ public key
        if (priv.Length != 64) throw new SshProtocolException("Invalid Ed25519 private key length");
        return new Ed25519HostKey(priv[..32].ToArray());
    }

    private static HostKey ReadRsa(SshReader p)
    {
        var n = Unsigned(p.ReadMPInt());
        var e = Unsigned(p.ReadMPInt());
        var d = p.ReadMPInt();
        var iqmp = p.ReadMPInt();
        var prime1 = p.ReadMPInt();
        var prime2 = p.ReadMPInt();

        var modLen = n.Length;
        var halfLen = (modLen + 1) / 2;
        var parameters = new RSAParameters
        {
            Modulus = n,
            Exponent = e,
            D = ToFixed(d, modLen),
            P = ToFixed(prime1, halfLen),
            Q = ToFixed(prime2, halfLen),
            DP = ToFixed(d % (prime1 - BigInteger.One), halfLen),
            DQ = ToFixed(d % (prime2 - BigInteger.One), halfLen),
            InverseQ = ToFixed(iqmp, halfLen),
        };
        var rsa = RSA.Create();
        try { rsa.ImportParameters(parameters); }
        catch { rsa.Dispose(); throw; }
        return new RsaHostKey(rsa);
    }

    private static HostKey ReadEcdsa(SshReader p, string keyType)
    {
        var curveName = p.ReadAscii();
        var point = p.ReadBinary();          // 0x04 ‖ X ‖ Y
        var d = p.ReadMPInt();

        var (curve, coordinateLength) = curveName switch
        {
            "nistp256" => (ECCurve.NamedCurves.nistP256, 32),
            "nistp384" => (ECCurve.NamedCurves.nistP384, 48),
            "nistp521" => (ECCurve.NamedCurves.nistP521, 66),
            _ => throw new SshProtocolException($"Unsupported ECDSA curve {curveName}"),
        };
        if (keyType != "ecdsa-sha2-" + curveName)
            throw new SshProtocolException("OpenSSH ECDSA key type and curve mismatch");
        if (point.Length != 1 + 2 * coordinateLength || point[0] != 4)
            throw new SshProtocolException("Invalid ECDSA public point");

        var parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = point.Slice(1, coordinateLength).ToArray(),
                Y = point.Slice(1 + coordinateLength, coordinateLength).ToArray(),
            },
            D = ToFixed(d, coordinateLength),
        };
        var ecdsa = ECDsa.Create();
        try { ecdsa.ImportParameters(parameters); }
        catch { ecdsa.Dispose(); throw; }
        return new EcdsaHostKey(ecdsa);
    }

    private static byte[] Unsigned(BigInteger v) => v.ToByteArray(isUnsigned: true, isBigEndian: true);

    /// <summary>Big-endian unsigned encoding of a non-negative value, left-padded/truncated to exactly <paramref name="length"/> bytes.</summary>
    private static byte[] ToFixed(BigInteger v, int length)
    {
        var bytes = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length == length) return bytes;
        var result = new byte[length];
        if (bytes.Length < length)
            bytes.CopyTo(result, length - bytes.Length);
        else
            bytes.AsSpan(bytes.Length - length).CopyTo(result);   // drop any leading zero bytes
        return result;
    }
}
