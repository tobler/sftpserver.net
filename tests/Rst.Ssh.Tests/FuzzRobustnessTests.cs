using Rst.Ssh.Fuzz;
using Rst.Ssh.Internal;
using Xunit;
using Xunit.Sdk;

namespace Rst.Ssh.Tests;

/// <summary>
/// Cross-platform robustness check that runs the same targets as the SharpFuzz harness
/// (<see cref="FuzzTargets"/>) over a large volume of random, edge-case and mutated inputs. A parser
/// that hits an unexpected exception (anything other than the one it swallows) lets it escape the
/// target, which fails the test. This runs in CI everywhere; the SharpFuzz harness adds coverage-guided
/// fuzzing on Linux (see tests/Rst.Ssh.Fuzz/README.md).
/// </summary>
public class FuzzRobustnessTests
{
    public static TheoryData<string> TargetNames()
    {
        var d = new TheoryData<string>();
        foreach (var name in FuzzTargets.All.Keys) d.Add(name);
        return d;
    }

    [Theory]
    [MemberData(nameof(TargetNames))]
    public void Target_survives_random_edge_and_mutated_input(string name)
    {
        var target = FuzzTargets.All[name];
        var rng = new Random(0xC0FFEE);

        // Degenerate and boundary inputs.
        foreach (var edge in new[]
                 {
                     Array.Empty<byte>(), new byte[1], new byte[3], new byte[4], new byte[8],
                     new byte[] { 0xff, 0xff, 0xff, 0xff }, new byte[] { 0x80, 0, 0, 0 },
                     new byte[64], Enumerable.Repeat((byte)0xff, 256).ToArray(),
                 })
            Invoke(target, edge, name);

        // Purely random inputs of varied length.
        for (var i = 0; i < 15000; i++)
        {
            var buf = new byte[rng.Next(0, 300)];
            rng.NextBytes(buf);
            Invoke(target, buf, name);
        }

        // Bit/byte mutations of well-formed, structurally-meaningful seeds.
        foreach (var seed in StructuredSeeds())
            for (var i = 0; i < 4000; i++)
                Invoke(target, Mutate(seed, rng), name);
    }

    private static void Invoke(Action<byte[]> target, byte[] input, string name)
    {
        try
        {
            target(input);
        }
        catch (Exception e)
        {
            throw new XunitException(
                $"Fuzz target '{name}' threw {e.GetType().Name} on input [{Convert.ToHexString(input)}]: {e.Message}");
        }
    }

    /// <summary>Valid-ish encodings that give the mutator realistic structure to perturb.</summary>
    private static IEnumerable<byte[]> StructuredSeeds()
    {
        // An ssh-ed25519 public-key blob + a signature blob + signed data (for pubkey-verify).
        var pub = new byte[32];
        yield return new SshWriter()
            .String("ssh-ed25519").Binary(pub)
            .String("ssh-ed25519").Binary(new byte[64])
            .Raw("signed"u8).ToArray();

        // An ssh-rsa public-key blob shape.
        yield return new SshWriter()
            .String("ssh-rsa").MPIntFromUnsigned([0x01, 0x00, 0x01]).MPIntFromUnsigned(new byte[256]).ToArray();

        // SFTP attributes with every flag set.
        yield return new SshWriter()
            .UInt32(0x8000000F).UInt64(1234).UInt32(1000).UInt32(1000).UInt32(0x1ff)
            .UInt32(1_700_000_000).UInt32(1_700_000_000).UInt32(1).Binary("x"u8).Binary("y"u8).ToArray();

        // A path with traversal and a name list, as UTF-8 and as SSH fields.
        yield return "/home/../etc/./passwd"u8.ToArray();
        yield return new SshWriter().String("curve25519-sha256,ecdh-sha2-nistp256").UInt32(42).ToArray();
    }

    private static byte[] Mutate(byte[] seed, Random rng)
    {
        var buf = (byte[])seed.Clone();
        var edits = rng.Next(1, 6);
        for (var i = 0; i < edits && buf.Length > 0; i++)
        {
            switch (rng.Next(3))
            {
                case 0: buf[rng.Next(buf.Length)] ^= (byte)(1 << rng.Next(8)); break;   // flip a bit
                case 1: buf[rng.Next(buf.Length)] = (byte)rng.Next(256); break;          // random byte
                case 2:                                                                   // truncate
                    if (buf.Length > 1) Array.Resize(ref buf, rng.Next(1, buf.Length));
                    break;
            }
        }
        return buf;
    }
}
