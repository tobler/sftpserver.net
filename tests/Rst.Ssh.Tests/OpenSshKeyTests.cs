using System;
using System.Security.Cryptography;
using Rst.Ssh;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Loads real keys produced by <c>ssh-keygen</c> in the default OpenSSH format
/// (<c>-----BEGIN OPENSSH PRIVATE KEY-----</c>). The public half is checked against the fingerprint
/// ssh-keygen reported; the private half is proven by signing and verifying with the public key.
/// </summary>
public class OpenSshKeyTests
{
    // key PEM, expected ssh-keygen fingerprint, expected KeyType.
    public static TheoryData<string, string, string> Keys => new()
    {
        { Ed25519Key, "SHA256:5LKSa6J0gwQj9cM9+23u8sSJ4sY7XbY9eAIIig2QP4o", "ssh-ed25519" },
        { Ecdsa256, "SHA256:JEP4r6hbYV80k3vuoxfpLATBbK8kUliuGqms99R9gMw", "ecdsa-sha2-nistp256" },
        { Ecdsa384, "SHA256:RgImEliC7Q2wxm+CpbMRNfxLpsncjbs1JLdsmFx0AE0", "ecdsa-sha2-nistp384" },
        { Ecdsa521, "SHA256:Ltvww5ZHEsiR9v2Oouab4kEadCAsgEc6LfSfFzKtwE4", "ecdsa-sha2-nistp521" },
        { Rsa2048, "SHA256:KBdjwR1O+SJtFfJ2TCIKfaGI2raZSGY+P9NG6mxR1iw", "ssh-rsa" },
    };

    [Theory]
    [MemberData(nameof(Keys))]
    public void Load_MatchesFingerprintAndType(string pem, string fingerprint, string keyType)
    {
        using var key = HostKey.LoadPem(pem);
        Assert.Equal(keyType, key.KeyType);
        Assert.Equal(fingerprint, key.Fingerprint);
    }

    [Theory]
    [MemberData(nameof(Keys))]
    public void Load_PrivateKeyCanSignAndVerify(string pem, string fingerprint, string keyType)
    {
        _ = (fingerprint, keyType);
        using var key = HostKey.LoadPem(pem);
        var data = "the quick brown fox jumps over the lazy dog"u8.ToArray();
        var algorithm = key.SignatureAlgorithms[0];
        var signature = key.Sign(algorithm, data);
        Assert.True(VerifySignature(key.PublicKeyBlob, signature, data), "signature must verify against the public key");
    }

    private static bool VerifySignature(byte[] publicBlob, byte[] signature, byte[] data)
    {
        var pub = new SshReader(publicBlob);
        var type = pub.ReadAscii();
        var sig = new SshReader(signature);
        var sigAlg = sig.ReadAscii();          // signature algorithm name

        switch (type)
        {
            case "ssh-ed25519":
                return Ed25519.Verify(data, sig.ReadBinary(), pub.ReadBinary());

            case "ssh-rsa":
            {
                var e = pub.ReadMPInt();
                var n = pub.ReadMPInt();
                using var rsa = RSA.Create(new RSAParameters
                {
                    Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
                    Modulus = n.ToByteArray(isUnsigned: true, isBigEndian: true),
                });
                var hash = sigAlg == "rsa-sha2-512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
                return rsa.VerifyData(data, sig.ReadBinary(), hash, RSASignaturePadding.Pkcs1);
            }

            default:   // ecdsa-sha2-nistp*
            {
                var curveName = pub.ReadAscii();
                var point = pub.ReadBinary();
                var (curve, coordLen, hash) = curveName switch
                {
                    "nistp256" => (ECCurve.NamedCurves.nistP256, 32, HashAlgorithmName.SHA256),
                    "nistp384" => (ECCurve.NamedCurves.nistP384, 48, HashAlgorithmName.SHA384),
                    _ => (ECCurve.NamedCurves.nistP521, 66, HashAlgorithmName.SHA512),
                };
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = point.Slice(1, coordLen).ToArray(), Y = point.Slice(1 + coordLen, coordLen).ToArray() },
                });
                var inner = new SshReader(sig.ReadBinary().ToArray());
                var r = Fixed(inner.ReadMPInt(), coordLen);
                var s = Fixed(inner.ReadMPInt(), coordLen);
                var p1363 = new byte[2 * coordLen];
                r.CopyTo(p1363, 0);
                s.CopyTo(p1363, coordLen);
                return ecdsa.VerifyData(data, p1363, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }
    }

    private static byte[] Fixed(System.Numerics.BigInteger v, int len)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (b.Length == len) return b;
        var r = new byte[len];
        b.AsSpan(Math.Max(0, b.Length - len)).CopyTo(r.AsSpan(Math.Max(0, len - b.Length)));
        return r;
    }

    [Fact]
    public void EncryptedKey_GivesHelpfulError()
    {
        // A bcrypt-protected key: cipher != "none". We don't implement bcrypt; the error must guide the user.
        var ex = Assert.Throws<NotSupportedException>(() => HostKey.LoadPem(EncryptedEd25519));
        Assert.Contains("passphrase", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private const string Ed25519Key =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBd2RgSWA1Ft5AZeK3DsmQlP52Zu8z28YR2+K2nTcohoQAAAJBtASplbQEq
        ZQAAAAtzc2gtZWQyNTUxOQAAACBd2RgSWA1Ft5AZeK3DsmQlP52Zu8z28YR2+K2nTcohoQ
        AAAEDdepXuuXWft4OOMK5IpNyjdLXafLx3j0p/N+a7leT6YV3ZGBJYDUW3kBl4rcOyZCU/
        nZm7zPbxhHb4radNyiGhAAAADHRlc3QtZWQyNTUxOQE=
        -----END OPENSSH PRIVATE KEY-----
        """;

    private const string Ecdsa256 =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRNJW6i7AIfjCtJU9PYkzboEQZOc6x2
        wZ/qUCNZJ0HkK02+yIPaE7TWzzRnqaumTPl85kZc8J7dSiG/FA1JmK1rAAAAqERhloxEYZ
        aMAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE0lbqLsAh+MK0lT
        09iTNugRBk5zrHbBn+pQI1knQeQrTb7Ig9oTtNbPNGepq6ZM+XzmRlzwnt1KIb8UDUmYrW
        sAAAAgdL9x22Ld9rKDVLM3P4BK1IiPL+93M9TURMo4w9eKDRwAAAANdGVzdC1lY2RzYTI1
        NgECAw==
        -----END OPENSSH PRIVATE KEY-----
        """;

    private const string Ecdsa384 =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
        1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSkifQW3mLclVPqAHVM/cYJ0qCarwv4
        zPYd/yEpTb7XvQlviL9S1jTRriCutkDEo9J9hVAdcxituNcxrCUGlmpKJ1SAx6JU+iZI9G
        BwDfef6pTEulP4s1IzrYgyc0OM+O0AAADYIv7qICL+6iAAAAATZWNkc2Etc2hhMi1uaXN0
        cDM4NAAAAAhuaXN0cDM4NAAAAGEEpIn0Ft5i3JVT6gB1TP3GCdKgmq8L+Mz2Hf8hKU2+17
        0Jb4i/UtY00a4grrZAxKPSfYVQHXMYrbjXMawlBpZqSidUgMeiVPomSPRgcA33n+qUxLpT
        +LNSM62IMnNDjPjtAAAAMQCABH5+ZrBxME9CvJyw2SOW1tqLsN/Q8ivAEqcNC4NVai127r
        zgQIkSEpMNbhzdv1AAAAANdGVzdC1lY2RzYTM4NAEC
        -----END OPENSSH PRIVATE KEY-----
        """;

    private const string Ecdsa521 =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
        1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQArgm8/TJcauhODCMd8LruNh+KhNEh
        Ljf7DOe2pGVUPUucD6vWFUBSJ7vFiI/e5wogPQLEyL3nUyMGbxQ5P7B8cvIB/d8YrKJUk3
        6z9Et0BSVN7esLhLNrngVAixWPcUTC53PtFyz+zpAi8TNXaQIIGCnk8JqjDI6PnxurP2tE
        mO2t/ZkAAAEQGwF2MxsBdjMAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
        AAAIUEAK4JvP0yXGroTgwjHfC67jYfioTRIS43+wzntqRlVD1LnA+r1hVAUie7xYiP3ucK
        ID0CxMi951MjBm8UOT+wfHLyAf3fGKyiVJN+s/RLdAUlTe3rC4Sza54FQIsVj3FEwudz7R
        cs/s6QIvEzV2kCCBgp5PCaowyOj58bqz9rRJjtrf2ZAAAAQgE8zS8djZz2yAc/j1YXiD4T
        SJKAsc0SapXETARCeGvEdybviJq6BJu5NXywExtG4wR/BZnsyEONjdaTcmSJ5jEezgAAAA
        10ZXN0LWVjZHNhNTIxAQIDBAU=
        -----END OPENSSH PRIVATE KEY-----
        """;

    private const string Rsa2048 =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAQEAn1pJ2pUI4o5FXnPbGQCml5cUDAzj25oQZ67sYArKtkxA0S6fNKf8
        1fDnw+U2MydLYwvho1/02rowFa9nsJlbvdSOcDPEWPnDSCJQPpJnt7c/aABLAMgcq4bBQM
        FXcaaypJJOmUvB8+tWHVtrqgY4ofkefVZTPwixwhugjYelUjt7YAA5cRtQJ1xVUWJZ5ugx
        mawNY6xTZjUAb7NQF9w+taAjqNAIve+Z92QL0KEnGniJOW/nZnhlwgyyoDVBVnpBscwdki
        SruN9D1OdKcWc661hn06KjdFLhNuy1EimvDIaubWYBT8lc4Ya/jAAn+XzqmsorAk4T0J5p
        9D7AXqXYrwAAA8jE7z2fxO89nwAAAAdzc2gtcnNhAAABAQCfWknalQjijkVec9sZAKaXlx
        QMDOPbmhBnruxgCsq2TEDRLp80p/zV8OfD5TYzJ0tjC+GjX/TaujAVr2ewmVu91I5wM8RY
        +cNIIlA+kme3tz9oAEsAyByrhsFAwVdxprKkkk6ZS8Hz61YdW2uqBjih+R59VlM/CLHCG6
        CNh6VSO3tgADlxG1AnXFVRYlnm6DGZrA1jrFNmNQBvs1AX3D61oCOo0Ai975n3ZAvQoSca
        eIk5b+dmeGXCDLKgNUFWekGxzB2SJKu430PU50pxZzrrWGfToqN0UuE27LUSKa8Mhq5tZg
        FPyVzhhr+MACf5fOqayisCThPQnmn0PsBepdivAAAAAwEAAQAAAQBX593f9+Eb4bIAxday
        tzovW8dSUnYMObQdDlEVNj7XS79h5d8rlBQVDT09Qp+gnmem7vH9RzzywE0wWT/RGviSAs
        TEvrns/3MrwsoTin4uyabvv2Ggv8OZF9BZ4Y5Ugsn/oTo8tJ786PDrZvhApgftylh4efuY
        RTqSQt1R1edsMccm8SmmQtontqlCQuhOXrobmOhmRSs6ccxqHjxyggOQrVScl2t7zf2xQw
        R05c4vXakZm2WMsJV5s8K68SJ4pXPpI7R4WBnNQ6EzRwlI1OZmNjlTtPBELqd//y9ahq95
        FLr9OFBjFGlrSmfN3Eege8RNmRIrcrvDrkO1uvo8u/rJAAAAgDH//R/CUAheGPIdfEYHv8
        UGBGBceSnVk2JW6+4DsWW7D4dREyMiqpHNM5NT06gIPDm5+38Ya0tQoOyUnz0vg3STIHjx
        FyHw2KFyMmEV7z002uF6FwCiSoOnKa2Qiwsi+gZYHMGNGjAOklUpVERgz/8XFxjxiNPRpJ
        MQiTtFBoSvAAAAgQDL3ILC1HjQ1q1iS1oHFnINoKyimDjjzbUA4MgDfIkK9WT8Ym8SoAbQ
        ikryER37wJ99nas68aekXPSm2oj0yYcVhsd/BQUoxG8BbbGdue1mNSGgTe1N+HHaj3NY9M
        uo/LWPMFWM6TSoaMvGBw8GVuJdjDwead0sB0eV/1QIqmJmxQAAAIEAyBulDmIkWmenz9Ta
        imtodrR3sDHLwQB2mk6yYMZ5NJiB3pa9saCtnURkLr5w+HVfcmM1ap+ct0RbUdV29G3LQL
        3Ei8WllR10roYcC2QNml7YD1TVUa438M39bOYV462Sy18O3w8smnjjLEYuqXcEa7lTOpU/
        iPnO+6OF1abdWOMAAAAMdGVzdC1yc2EyMDQ4AQIDBAUGBw==
        -----END OPENSSH PRIVATE KEY-----
        """;

    // Real ed25519 key written by `ssh-keygen` with a passphrase (bcrypt KDF, aes256-ctr cipher).
    private const string EncryptedEd25519 =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBu9vi65N
        ObR6UPxJ5cFvWEAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMzZDx6Of5gWtELM
        fjE4u7KrRUzCrU7Fp8lj057YgRdNAAAAkBF8sju5M/p4SdKwW5t9bF7ijMBge2ZCRWvQAe
        dyPQBxWf+miIwo03a607LHd008mXKrXKzKE/Lmrc78OhpypDj3FEhCWGNRW2U1TdRpxXx0
        g08duS5yuh/+rWKNHP6fInVWK/eS+MBbmKUe4bE3oqsQlDYwKDYvFTtJyVfPu9toRQmUol
        8tRgKmFANZh0BZhg==
        -----END OPENSSH PRIVATE KEY-----
        """;
}
