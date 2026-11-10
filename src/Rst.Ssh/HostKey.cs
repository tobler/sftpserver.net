using System.Security.Cryptography;
using Rst.Ssh.Internal;

namespace Rst.Ssh;

/// <summary>Server host key. Supported: ECDSA (P-256/384/521), RSA (rsa-sha2-256/512).</summary>
/// <remarks>Ed25519 will follow, based on the built-in Curve25519 implementation.</remarks>
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

    /// <summary>Loads a key in PEM format (PKCS#8, "BEGIN PRIVATE KEY" / "BEGIN EC PRIVATE KEY" / "BEGIN RSA PRIVATE KEY").</summary>
    /// <remarks>The OpenSSH-specific format ("BEGIN OPENSSH PRIVATE KEY") will follow later.</remarks>
    public static HostKey LoadPem(string pem)
    {
        if (pem.Contains("BEGIN OPENSSH PRIVATE KEY"))
            throw new NotSupportedException("The OpenSSH key format is not supported yet – please use PEM (ssh-keygen -m PEM).");

        if (pem.Contains("RSA PRIVATE KEY")) { var r = RSA.Create(); r.ImportFromPem(pem); return new RsaHostKey(r); }
        if (pem.Contains("EC PRIVATE KEY")) { var e = ECDsa.Create(); e.ImportFromPem(pem); return new EcdsaHostKey(e); }

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
