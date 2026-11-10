using System.Collections.Concurrent;
using System.Security.Cryptography;
using Rst.Ssh;
using Rst.Ssh.Internal;
using Xunit;

namespace Rst.Ssh.Tests;

/// <summary>
/// Regression test for the concurrent-signing race: every SSH handshake signs the exchange hash
/// with the shared host key. .NET's ECDsa/RSA instances are not thread-safe for concurrent signing,
/// so without a lock around <c>Sign</c> parallel connections (e.g. a Cyberduck multi-file upload,
/// which opens several connections at once) could get corrupt signatures, a thrown exception or a
/// stalled handshake. These tests sign from many threads at once and verify every signature.
/// </summary>
public class HostKeyConcurrencyTests
{
    private const int Threads = 32;
    private const int SignsPerThread = 40;

    [Fact]
    public void Ecdsa_host_key_signs_correctly_under_concurrency()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new EcdsaHostKey(ecdsa);
        var coordinateLength = (ecdsa.KeySize + 7) / 8;

        // Collect (data, signature) pairs while signing concurrently; verify afterwards single-threaded
        // (verification on one ECDsa instance would itself not be thread-safe).
        var results = SignConcurrently(data => key.Sign(key.KeyType, data));

        using var verifier = ECDsa.Create(ecdsa.ExportParameters(false));
        foreach (var (data, blob) in results)
        {
            var reader = new SshReader(blob);
            Assert.Equal(key.KeyType, reader.ReadString());
            var inner = new SshReader(reader.ReadBinary().ToArray());
            var r = inner.ReadBinary().ToArray();
            var s = inner.ReadBinary().ToArray();

            var p1363 = new byte[2 * coordinateLength];
            RightAlign(r, p1363.AsSpan(0, coordinateLength));
            RightAlign(s, p1363.AsSpan(coordinateLength, coordinateLength));

            Assert.True(verifier.VerifyData(data, p1363, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                "A signature produced under concurrent load did not verify.");
        }
    }

    [Fact]
    public void Rsa_host_key_signs_correctly_under_concurrency()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaHostKey(rsa);

        var results = SignConcurrently(data => key.Sign("rsa-sha2-256", data));

        using var verifier = RSA.Create(rsa.ExportParameters(false));
        foreach (var (data, blob) in results)
        {
            var reader = new SshReader(blob);
            Assert.Equal("rsa-sha2-256", reader.ReadString());
            var signature = reader.ReadBinary().ToArray();
            Assert.True(verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "A signature produced under concurrent load did not verify.");
        }
    }

    private static List<(byte[] Data, byte[] Blob)> SignConcurrently(Func<byte[], byte[]> sign)
    {
        var results = new ConcurrentQueue<(byte[], byte[])>();
        var errors = new ConcurrentQueue<Exception>();
        using var ready = new Barrier(Threads);

        var workers = Enumerable.Range(0, Threads).Select(t => new Thread(() =>
        {
            var rng = new Random(t);
            ready.SignalAndWait();   // start all threads as simultaneously as possible
            for (var i = 0; i < SignsPerThread; i++)
            {
                var data = new byte[64];
                rng.NextBytes(data);
                try { results.Enqueue((data, sign(data))); }
                catch (Exception e) { errors.Enqueue(e); }
            }
        })).ToList();

        foreach (var w in workers) w.Start();
        foreach (var w in workers) w.Join();

        Assert.True(errors.IsEmpty, $"Signing threw under concurrency: {errors.FirstOrDefault()}");
        Assert.Equal(Threads * SignsPerThread, results.Count);
        return results.ToList();
    }

    private static void RightAlign(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        // Strip any leading sign byte / zeros, then right-align the magnitude into a fixed-width field.
        while (value.Length > destination.Length && value[0] == 0) value = value[1..];
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }
}
