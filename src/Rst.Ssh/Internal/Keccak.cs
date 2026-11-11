using System.Numerics;

namespace Rst.Ssh.Internal;

/// <summary>
/// Keccak-f[1600] sponge and the FIPS 202 functions ML-KEM needs: SHA3-256, SHA3-512, SHAKE128
/// and SHAKE256. The platform's <see cref="System.Security.Cryptography.SHA3_256"/> &amp; co. are
/// unavailable on macOS (they depend on the OS crypto library), so this is a self-contained port.
/// </summary>
internal static class Keccak
{
    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    // Combined rho offsets and pi lane destinations for the 24-step rho/pi walk (standard Keccak tables).
    private static readonly int[] RhoOffset = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
    private static readonly int[] PiLane = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    public static void Permute(Span<ulong> a)
    {
        Span<ulong> b = stackalloc ulong[5];
        for (var round = 0; round < 24; round++)
        {
            // Theta
            for (var x = 0; x < 5; x++) b[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (var x = 0; x < 5; x++)
            {
                var t = b[(x + 4) % 5] ^ BitOperations.RotateLeft(b[(x + 1) % 5], 1);
                for (var y = 0; y < 25; y += 5) a[y + x] ^= t;
            }

            // Rho + Pi
            var cur = a[1];
            for (var t = 0; t < 24; t++)
            {
                var idx = PiLane[t];
                var tmp = a[idx];
                a[idx] = BitOperations.RotateLeft(cur, RhoOffset[t]);
                cur = tmp;
            }

            // Chi
            for (var y = 0; y < 25; y += 5)
            {
                for (var x = 0; x < 5; x++) b[x] = a[y + x];
                for (var x = 0; x < 5; x++) a[y + x] = b[x] ^ (~b[(x + 1) % 5] & b[(x + 2) % 5]);
            }

            // Iota
            a[0] ^= RoundConstants[round];
        }
    }

    public static byte[] Sha3_256(ReadOnlySpan<byte> input) => Fixed(input, rate: 136, ds: 0x06, outLen: 32);
    public static byte[] Sha3_512(ReadOnlySpan<byte> input) => Fixed(input, rate: 72, ds: 0x06, outLen: 64);
    public static byte[] Shake256(ReadOnlySpan<byte> input, int outLen) => Fixed(input, rate: 136, ds: 0x1F, outLen: outLen);
    public static byte[] Shake128(ReadOnlySpan<byte> input, int outLen) => Fixed(input, rate: 168, ds: 0x1F, outLen: outLen);

    private static byte[] Fixed(ReadOnlySpan<byte> input, int rate, byte ds, int outLen)
    {
        var sponge = new Sponge(rate, ds);
        sponge.Absorb(input);
        var output = new byte[outLen];
        sponge.Squeeze(output);
        return output;
    }

    /// <summary>
    /// Incremental Keccak sponge: absorb once, then squeeze arbitrarily much. Used as a streaming XOF
    /// (SHAKE128) for ML-KEM's matrix rejection sampling.
    /// </summary>
    public struct Sponge
    {
        private readonly ulong[] _state;
        private readonly int _rate;        // bytes
        private readonly byte _ds;
        private int _offset;               // byte position within the current block
        private bool _squeezing;

        public Sponge(int rate, byte ds)
        {
            _state = new ulong[25];
            _rate = rate;
            _ds = ds;
            _offset = 0;
            _squeezing = false;
        }

        private readonly void Xor(int byteIndex, byte value) => _state[byteIndex >> 3] ^= (ulong)value << ((byteIndex & 7) * 8);
        private readonly byte Get(int byteIndex) => (byte)(_state[byteIndex >> 3] >> ((byteIndex & 7) * 8));

        public void Absorb(ReadOnlySpan<byte> data)
        {
            foreach (var t in data)
            {
                Xor(_offset++, t);
                if (_offset == _rate) { Permute(_state); _offset = 0; }
            }
        }

        private void Pad()
        {
            Xor(_offset, _ds);
            Xor(_rate - 1, 0x80);
            Permute(_state);
            _offset = 0;
            _squeezing = true;
        }

        public void Squeeze(Span<byte> output)
        {
            if (!_squeezing) Pad();
            for (var i = 0; i < output.Length; i++)
            {
                if (_offset == _rate) { Permute(_state); _offset = 0; }
                output[i] = Get(_offset++);
            }
        }
    }
}
