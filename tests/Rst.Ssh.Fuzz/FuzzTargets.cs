using System.Text;
using Rst.Ssh.Internal;
using Rst.Ssh.Sftp;

namespace Rst.Ssh.Fuzz;

/// <summary>
/// Fuzz targets over the library's untrusted-input parsers. Each target swallows only the exceptions
/// the parser is contractually allowed to raise on malformed input; any other exception escapes, so
/// the fuzzer (and the cross-platform robustness tests that reuse these targets) records it as a bug.
/// </summary>
public static class FuzzTargets
{
    public static readonly IReadOnlyDictionary<string, Action<byte[]>> All = new Dictionary<string, Action<byte[]>>
    {
        ["ssh-reader"] = SshReaderFields,
        ["sftp-attrs"] = SftpAttributes,
        ["sftp-path"] = SftpPathParse,
        ["pubkey-verify"] = PublicKeyVerify,
    };

    /// <summary>The core SSH wire parser (RFC 4251 §5): read a data-driven sequence of typed fields.</summary>
    public static void SshReaderFields(byte[] data)
    {
        var r = new SshReader(data);
        try
        {
            while (!r.AtEnd)
            {
                switch (r.ReadByte() % 6)
                {
                    case 0: r.ReadUInt32(); break;
                    case 1: r.ReadUInt64(); break;
                    case 2: _ = r.ReadString(); break;
                    case 3: _ = r.ReadNameList(); break;
                    case 4: _ = r.ReadMPInt(); break;
                    default: _ = r.ReadBinaryArray(); break;
                }
            }
        }
        catch (SshProtocolException) { /* the only exception a short/garbled packet may raise */ }
    }

    /// <summary>The SFTP attribute parser (SSH_FXP_ATTRS body).</summary>
    public static void SftpAttributes(byte[] data)
    {
        try { SftpSubsystem.ReadAttrs(new SshReader(data)); }
        catch (SshProtocolException) { }
    }

    /// <summary>The SFTP path parser (normalization, traversal, NUL rejection).</summary>
    public static void SftpPathParse(byte[] data)
    {
        try { SftpPath.Parse(Encoding.UTF8.GetString(data)); }
        catch (SftpException) { }
    }

    /// <summary>Public-key signature verification. Contract: it never throws, whatever the inputs.</summary>
    public static void PublicKeyVerify(byte[] data)
    {
        string algorithm;
        byte[] keyBlob, signature, signedData;
        try
        {
            var r = new SshReader(data);
            algorithm = r.ReadString();
            keyBlob = r.ReadBinaryArray();
            signature = r.ReadBinaryArray();
            signedData = r.ReadRest().ToArray();
        }
        catch (SshProtocolException) { return; }   // framing of the fuzz input itself was invalid

        PublicKeyAuth.Verify(algorithm, keyBlob, signature, signedData);   // must not throw
    }
}
