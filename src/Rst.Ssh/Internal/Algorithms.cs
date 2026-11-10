using System.Security.Cryptography;

namespace Rst.Ssh.Internal;

/// <summary>What the core actually implements. Presets in SshAlgorithmSet may only contain these names.</summary>
internal static class Algorithms
{
    public static readonly string[] KeyExchange =
    [
        "curve25519-sha256", "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    ];

    public static readonly string[] HostKey =
    [
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256",
    ];

    public static readonly string[] Encryption =
    [
        "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr",
    ];

    public static readonly string[] Mac =
    [
        "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512",
    ];

    public static readonly string[] Compression = ["none"];

    public static bool IsAead(string cipher) => cipher.EndsWith("-gcm@openssh.com", StringComparison.Ordinal);

    public static (int KeyLength, int IvLength) CipherSizes(string cipher) => cipher switch
    {
        "aes128-ctr" => (16, 16),
        "aes192-ctr" => (24, 16),
        "aes256-ctr" => (32, 16),
        "aes128-gcm@openssh.com" => (16, 12),
        "aes256-gcm@openssh.com" => (32, 12),
        _ => throw new SshProtocolException($"Unknown cipher {cipher}"),
    };

    public static (HashAlgorithmName Hash, int Length, bool Etm) MacInfo(string mac) => mac switch
    {
        "hmac-sha2-256" => (HashAlgorithmName.SHA256, 32, false),
        "hmac-sha2-512" => (HashAlgorithmName.SHA512, 64, false),
        "hmac-sha2-256-etm@openssh.com" => (HashAlgorithmName.SHA256, 32, true),
        "hmac-sha2-512-etm@openssh.com" => (HashAlgorithmName.SHA512, 64, true),
        _ => throw new SshProtocolException($"Unknown MAC {mac}"),
    };

    public static HashAlgorithmName KexHash(string kex) => kex switch
    {
        "curve25519-sha256" or "curve25519-sha256@libssh.org" or "ecdh-sha2-nistp256" => HashAlgorithmName.SHA256,
        "ecdh-sha2-nistp384" => HashAlgorithmName.SHA384,
        "ecdh-sha2-nistp521" => HashAlgorithmName.SHA512,
        _ => throw new SshProtocolException($"Unknown key exchange {kex}"),
    };

    /// <summary>First entry of the client's list that the server also supports (RFC 4253 §7.1).</summary>
    public static string? Negotiate(IEnumerable<string> client, IReadOnlyCollection<string> server) =>
        client.FirstOrDefault(c => server.Contains(c) && !IsPseudo(c));

    private static bool IsPseudo(string name) =>
        name.StartsWith("ext-info-", StringComparison.Ordinal) || name.StartsWith("kex-strict-", StringComparison.Ordinal);
}
