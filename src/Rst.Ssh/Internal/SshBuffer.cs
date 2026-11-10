using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Rst.Ssh.Internal;

/// <summary>Reads SSH data types (RFC 4251 §5). Throws SshProtocolException on malformed data.</summary>
internal sealed class SshReader
{
    private readonly ReadOnlyMemory<byte> _data;
    private int _pos;

    public SshReader(ReadOnlyMemory<byte> data) { _data = data; _pos = 0; }

    public int Remaining => _data.Length - _pos;
    public bool AtEnd => _pos >= _data.Length;

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || n > Remaining) throw new SshProtocolException("Packet too short");
        var s = _data.Span.Slice(_pos, n);
        _pos += n;
        return s;
    }

    public byte ReadByte() => Take(1)[0];
    public bool ReadBoolean() => ReadByte() != 0;
    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));
    public ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

    public ReadOnlySpan<byte> ReadBinary()
    {
        var len = ReadUInt32();
        if (len > int.MaxValue) throw new SshProtocolException("String too long");
        return Take((int)len);
    }

    public byte[] ReadBinaryArray() => ReadBinary().ToArray();
    public string ReadString() => Encoding.UTF8.GetString(ReadBinary());
    public string ReadAscii() => Encoding.ASCII.GetString(ReadBinary());
    public string[] ReadNameList()
    {
        var s = ReadAscii();
        return s.Length == 0 ? [] : s.Split(',');
    }

    public BigInteger ReadMPInt() => new(ReadBinary(), isUnsigned: false, isBigEndian: true);

    public ReadOnlySpan<byte> ReadRest() => Take(Remaining);
}

/// <summary>Writes SSH data types into a growing buffer.</summary>
internal sealed class SshWriter
{
    private byte[] _buf;
    private int _len;

    public SshWriter(int capacity = 256) { _buf = new byte[capacity]; }

    public int Length => _len;
    public ReadOnlySpan<byte> Span => _buf.AsSpan(0, _len);
    public ReadOnlyMemory<byte> Memory => _buf.AsMemory(0, _len);
    public byte[] ToArray() => Span.ToArray();

    private Span<byte> Grow(int n)
    {
        if (_len + n > _buf.Length)
            Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _len + n));
        var s = _buf.AsSpan(_len, n);
        _len += n;
        return s;
    }

    public SshWriter Byte(byte b) { Grow(1)[0] = b; return this; }
    public SshWriter Byte(SshMessage m) => Byte((byte)m);
    public SshWriter Boolean(bool b) => Byte(b ? (byte)1 : (byte)0);
    public SshWriter UInt32(uint v) { BinaryPrimitives.WriteUInt32BigEndian(Grow(4), v); return this; }
    public SshWriter UInt64(ulong v) { BinaryPrimitives.WriteUInt64BigEndian(Grow(8), v); return this; }
    public SshWriter Raw(ReadOnlySpan<byte> data) { data.CopyTo(Grow(data.Length)); return this; }
    public SshWriter Binary(ReadOnlySpan<byte> data) { UInt32((uint)data.Length); return Raw(data); }
    public SshWriter String(string s) => Binary(Encoding.UTF8.GetBytes(s));
    public SshWriter NameList(IEnumerable<string> names) => String(string.Join(',', names));

    public SshWriter MPInt(BigInteger v) => Binary(v.IsZero ? [] : v.ToByteArray(isUnsigned: false, isBigEndian: true));

    /// <summary>Unsigned big-endian bytes as mpint (leading zeros stripped, 0x00 prepended if needed).</summary>
    public SshWriter MPIntFromUnsigned(ReadOnlySpan<byte> bigEndian)
    {
        var i = 0;
        while (i < bigEndian.Length && bigEndian[i] == 0) i++;
        var v = bigEndian[i..];
        if (v.IsEmpty) return UInt32(0);
        if ((v[0] & 0x80) != 0)
        {
            UInt32((uint)v.Length + 1);
            Byte((byte)0);
            return Raw(v);
        }
        return Binary(v);
    }
}

internal sealed class SshProtocolException(string message, SshDisconnectReason reason = SshDisconnectReason.ProtocolError)
    : Exception(message)
{
    public SshDisconnectReason Reason { get; } = reason;
}

internal enum SshMessage : byte
{
    Disconnect = 1, Ignore = 2, Unimplemented = 3, Debug = 4, ServiceRequest = 5, ServiceAccept = 6, ExtInfo = 7,
    KexInit = 20, NewKeys = 21, KexEcdhInit = 30, KexEcdhReply = 31,
    UserAuthRequest = 50, UserAuthFailure = 51, UserAuthSuccess = 52, UserAuthBanner = 53, UserAuthPkOk = 60,
    GlobalRequest = 80, RequestSuccess = 81, RequestFailure = 82,
    ChannelOpen = 90, ChannelOpenConfirmation = 91, ChannelOpenFailure = 92, ChannelWindowAdjust = 93,
    ChannelData = 94, ChannelExtendedData = 95, ChannelEof = 96, ChannelClose = 97,
    ChannelRequest = 98, ChannelSuccess = 99, ChannelFailure = 100,
}
