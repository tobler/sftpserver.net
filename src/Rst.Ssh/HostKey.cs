using System.Formats.Asn1;
using System.Security.Cryptography;
using Rst.Ssh.Internal;

namespace Rst.Ssh;

/// <summary>Server host key. Supported: Ed25519, ECDSA (P-256/384/521), RSA (rsa-sha2-256/512).</summary>
public abstract class HostKey : IDisposable
{
    private protected HostKey() { }

    /// <summary>Type in the key blob ("ecdsa-sha2-nistp256", "ssh-rsa").</summary>
    public abstract string KeyType { get; }

    /// <summary>Signature algorithms that can be offered with this key.</summary>
    public abstract IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Public key in SSH wire format.</summary>
    public abstract byte[] PublicKeyBlob { get; }

    /// <summary>"SHA256:…" wie ssh-keygen -l.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(PublicKeyBlob)).TrimEnd('=');

    /// <summary>Line for known_hosts / authorized_keys ("ecdsa-sha2-nistp256 AAAA…").</summary>
    public string PublicKeyLine => KeyType + " " + Convert.ToBase64String(PublicKeyBlob);

    internal abstract byte[] Sign(string algorithm, ReadOnlySpan<byte> data);

    public static HostKey GenerateEcdsa(int bits = 256) => new EcdsaHostKey(ECDsa.Create(bits switch
    {
        256 => ECCurve.NamedCurves.nistP256,
        384 => ECCurve.NamedCurves.nistP384,
        521 => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(bits)),
    }));

    public static HostKey GenerateRsa(int bits = 3072) => new RsaHostKey(RSA.Create(bits));

    public static HostKey GenerateEd25519() => new Ed25519HostKey(Ed25519.GenerateKeyPair().Seed);

    /// <summary>
    /// Loads a key in PEM format: the OpenSSH format ("BEGIN OPENSSH PRIVATE KEY", unencrypted),
    /// PKCS#8 ("BEGIN PRIVATE KEY") for Ed25519/ECDSA/RSA, or the legacy "BEGIN EC/RSA PRIVATE KEY".
    /// </summary>
    public static HostKey LoadPem(string pem)
    {
        if (pem.Contains("BEGIN OPENSSH PRIVATE KEY"))
            return OpenSshPrivateKey.TryImport(pem, out var ossh)
                ? ossh
                : throw new SshProtocolException("Malformed OPENSSH PRIVATE KEY");

        if (pem.Contains("RSA PRIVATE KEY")) { var r = RSA.Create(); r.ImportFromPem(pem); return new RsaHostKey(r); }
        if (pem.Contains("EC PRIVATE KEY")) { var e = ECDsa.Create(); e.ImportFromPem(pem); return new EcdsaHostKey(e); }

        // Generic PKCS#8 ("BEGIN PRIVATE KEY"): .NET cannot import Ed25519, so dispatch on the algorithm OID.
        if (Ed25519HostKey.TryImportPkcs8Pem(pem, out var ed)) return ed;

        try { var e = ECDsa.Create(); e.ImportFromPem(pem); return new EcdsaHostKey(e); }
        catch (CryptographicException) { var r = RSA.Create(); r.ImportFromPem(pem); return new RsaHostKey(r); }
    }

    public static HostKey Load(string path) => LoadPem(File.ReadAllText(path));

    public abstract string ExportPem();

    public void Save(string path)
    {
        File.WriteAllText(path, ExportPem());
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public abstract void Dispose();
}

internal sealed class EcdsaHostKey : HostKey
{
    private readonly ECDsa _key;
    private readonly object _signLock = new();    // ECDsa instances are not thread-safe for concurrent signing
    private readonly string _curve;           // nistp256 …
    private readonly HashAlgorithmName _hash;
    private readonly byte[] _blob;

    public EcdsaHostKey(ECDsa key)
    {
        _key = key;
        var p = key.ExportParameters(false);
        (_curve, _hash) = key.KeySize switch
        {
            256 => ("nistp256", HashAlgorithmName.SHA256),
            384 => ("nistp384", HashAlgorithmName.SHA384),
            521 => ("nistp521", HashAlgorithmName.SHA512),
            _ => throw new NotSupportedException($"ECDSA curve with {key.KeySize} bits is not supported"),
        };
        var point = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        point[0] = 4;
        p.Q.X.CopyTo(point, 1);
        p.Q.Y.CopyTo(point, 1 + p.Q.X.Length);
        _blob = new SshWriter().String(KeyType).String(_curve).Binary(point).ToArray();
    }

    public override string KeyType => "ecdsa-sha2-" + _curve;
    public override IReadOnlyList<string> SignatureAlgorithms => [KeyType];
    public override byte[] PublicKeyBlob => _blob;

    internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
    {
        byte[] sig;
        lock (_signLock)
            sig = _key.SignData(data, _hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var half = sig.Length / 2;
        var inner = new SshWriter().MPIntFromUnsigned(sig.AsSpan(0, half)).MPIntFromUnsigned(sig.AsSpan(half)).ToArray();
        return new SshWriter().String(KeyType).Binary(inner).ToArray();
    }

    public override string ExportPem() => _key.ExportPkcs8PrivateKeyPem();
    public override void Dispose() => _key.Dispose();
}

internal sealed class Ed25519HostKey : HostKey
{
    private const string Oid = "1.3.101.112";          // id-Ed25519 (RFC 8410)
    private readonly byte[] _seed;                      // 32-byte private seed
    private readonly byte[] _publicKey;                 // 32-byte public point
    private readonly byte[] _blob;

    public Ed25519HostKey(byte[] seed)
    {
        if (seed.Length != Ed25519.SeedSize) throw new ArgumentException("Ed25519 seed must be 32 bytes", nameof(seed));
        _seed = (byte[])seed.Clone();
        _publicKey = Ed25519.PublicKeyFromSeed(_seed);
        _blob = new SshWriter().String(KeyType).Binary(_publicKey).ToArray();
    }

    public override string KeyType => "ssh-ed25519";
    public override IReadOnlyList<string> SignatureAlgorithms => [KeyType];
    public override byte[] PublicKeyBlob => _blob;

    internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data) =>
        new SshWriter().String(KeyType).Binary(Ed25519.Sign(data, _seed, _publicKey)).ToArray();

    // PKCS#8 (RFC 8410): SEQUENCE { INTEGER 0, SEQUENCE { OID id-Ed25519 }, OCTET STRING { OCTET STRING seed } }.
    public override string ExportPem()
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteOctetString(_seed);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence()) writer.WriteObjectIdentifier(Oid);
            writer.WriteOctetString(inner.Encode());
        }
        return PemEncoding.WriteString("PRIVATE KEY", writer.Encode());
    }

    /// <summary>Imports an Ed25519 PKCS#8 PEM. Returns false if the PEM is not an Ed25519 "PRIVATE KEY".</summary>
    public static bool TryImportPkcs8Pem(string pem, out HostKey key)
    {
        key = null!;
        if (!PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "PRIVATE KEY") return false;

        byte[] der;
        try { der = Convert.FromBase64String(pem[fields.Base64Data].Replace("\n", "").Replace("\r", "")); }
        catch (FormatException) { return false; }

        try
        {
            var seq = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            seq.ReadInteger();                                        // version 0
            var oid = seq.ReadSequence().ReadObjectIdentifier();
            if (oid != Oid) return false;
            var seed = new AsnReader(seq.ReadOctetString(), AsnEncodingRules.DER).ReadOctetString();
            if (seed.Length != Ed25519.SeedSize) return false;
            key = new Ed25519HostKey(seed);
            return true;
        }
        catch (AsnContentException) { return false; }
        catch (ArgumentException) { return false; }
    }

    public override void Dispose() => CryptographicOperations.ZeroMemory(_seed);
}

internal sealed class RsaHostKey : HostKey
{
    private readonly RSA _key;
    private readonly object _signLock = new();    // RSA instances are not thread-safe for concurrent signing
    private readonly byte[] _blob;

    public RsaHostKey(RSA key)
    {
        if (key.KeySize < 2048) throw new NotSupportedException("RSA keys shorter than 2048 bits are not supported");
        _key = key;
        var p = key.ExportParameters(false);
        _blob = new SshWriter().String("ssh-rsa").MPIntFromUnsigned(p.Exponent).MPIntFromUnsigned(p.Modulus).ToArray();
    }

    public override string KeyType => "ssh-rsa";
    public override IReadOnlyList<string> SignatureAlgorithms => ["rsa-sha2-512", "rsa-sha2-256"];
    public override byte[] PublicKeyBlob => _blob;

    internal override byte[] Sign(string algorithm, ReadOnlySpan<byte> data)
    {
        var hash = algorithm switch
        {
            "rsa-sha2-256" => HashAlgorithmName.SHA256,
            "rsa-sha2-512" => HashAlgorithmName.SHA512,
            _ => throw new SshProtocolException($"RSA signature algorithm {algorithm} is not supported"),
        };
        byte[] sig;
        lock (_signLock)
            sig = _key.SignData(data, hash, RSASignaturePadding.Pkcs1);
        return new SshWriter().String(algorithm).Binary(sig).ToArray();
    }

    public override string ExportPem() => _key.ExportPkcs8PrivateKeyPem();
    public override void Dispose() => _key.Dispose();
}
