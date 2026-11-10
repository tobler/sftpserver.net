using System.Threading.Channels;

namespace Rst.Ssh.Internal;

/// <summary>
/// A session channel with flow control in both directions:
/// - Inbound: the client may only send as much as we have granted window for. Window is only released
///   once the application has read the data -> real backpressure all the way to the client.
/// - Outbound: writes wait when the client's window is exhausted.
/// </summary>
internal sealed class SshChannel : ISshChannel
{
    private readonly SshSession _session;
    private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly CancellationTokenSource _closed = new();
    private readonly SemaphoreSlim _windowAvailable = new(0, int.MaxValue);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly uint _localWindowSize;
    private readonly uint _localMaxPacket;

    private long _remoteWindow;
    private readonly uint _remoteMaxPacket;
    private long _localWindowRemaining;
    private long _consumedSinceAdjust;
    private byte[]? _current;
    private int _currentOffset;
    private bool _eofSent, _closeSent, _remoteClosed;

    public SshChannel(SshSession session, uint id, uint remoteId, uint remoteWindow, uint remoteMaxPacket, uint localWindow, uint localMaxPacket)
    {
        _session = session;
        Id = id;
        RemoteId = remoteId;
        _remoteWindow = remoteWindow;
        _remoteMaxPacket = Math.Max(remoteMaxPacket, 1024);
        _localWindowSize = localWindow;
        _localWindowRemaining = localWindow;
        _localMaxPacket = localMaxPacket;
        Stream = new ChannelStream(this);
    }

    public uint Id { get; }
    public uint RemoteId { get; }
    public ISshSession Session => _session;
    public Stream Stream { get; }
    public CancellationToken Closed => _closed.Token;
    public bool HasHandler { get; set; }

    // ------------------------------------------------------------------ called by the session reader

    public void OnData(byte[] data)
    {
        if (_remoteClosed) return;
        if (data.Length > _localMaxPacket + 1024 || data.Length > Interlocked.Read(ref _localWindowRemaining))
            throw new SshProtocolException("Client exceeded the channel window");
        Interlocked.Add(ref _localWindowRemaining, -data.Length);
        if (data.Length > 0) _incoming.Writer.TryWrite(data);
    }

    public void OnEof() => _incoming.Writer.TryComplete();

    public void OnWindowAdjust(uint bytes)
    {
        var updated = Interlocked.Add(ref _remoteWindow, bytes);
        if (updated > uint.MaxValue) throw new SshProtocolException("Channel window overflow");
        _windowAvailable.Release();
    }

    public async Task OnRemoteCloseAsync()
    {
        _remoteClosed = true;
        _incoming.Writer.TryComplete();
        _closed.Cancel();
        _windowAvailable.Release();
        if (!_closeSent)
        {
            _closeSent = true;
            await _session.SendAsync(new SshWriter().Byte(SshMessage.ChannelClose).UInt32(RemoteId), CancellationToken.None);
        }
        _session.RemoveChannel(Id);
    }

    public void Abort()
    {
        _remoteClosed = true;
        _incoming.Writer.TryComplete();
        _closed.Cancel();
        _windowAvailable.Release();
    }

    // ------------------------------------------------------------------ Application

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct)
    {
        if (buffer.IsEmpty) return 0;
        while (_current is null || _currentOffset >= _current.Length)
        {
            _current = null;
            if (!await _incoming.Reader.WaitToReadAsync(ct)) return 0;   // EOF
            _incoming.Reader.TryRead(out _current);
            _currentOffset = 0;
        }

        var n = Math.Min(buffer.Length, _current.Length - _currentOffset);
        _current.AsMemory(_currentOffset, n).CopyTo(buffer);
        _currentOffset += n;

        // Replenish the window once half of it has been consumed.
        _consumedSinceAdjust += n;
        if (_consumedSinceAdjust >= _localWindowSize / 2 && !_remoteClosed)
        {
            var adjust = (uint)_consumedSinceAdjust;
            _consumedSinceAdjust = 0;
            Interlocked.Add(ref _localWindowRemaining, adjust);
            await _session.SendAsync(new SshWriter().Byte(SshMessage.ChannelWindowAdjust).UInt32(RemoteId).UInt32(adjust), ct);
        }
        return n;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            while (!data.IsEmpty)
            {
                if (_remoteClosed || _closeSent) throw new IOException("Channel is closed");

                var window = Interlocked.Read(ref _remoteWindow);
                if (window <= 0)
                {
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _closed.Token);
                    try { await _windowAvailable.WaitAsync(linked.Token); }
                    catch (OperationCanceledException) when (_closed.IsCancellationRequested) { throw new IOException("Channel is closed"); }
                    continue;
                }

                var chunk = (int)Math.Min(Math.Min(window, _remoteMaxPacket), data.Length);
                Interlocked.Add(ref _remoteWindow, -chunk);
                await _session.SendAsync(new SshWriter(chunk + 16).Byte(SshMessage.ChannelData).UInt32(RemoteId).Binary(data.Span[..chunk]), ct);
                data = data[chunk..];
            }
        }
        finally { _writeLock.Release(); }
    }

    public async ValueTask CloseAsync(uint? exitStatus = null)
    {
        if (_closeSent) return;
        var ct = CancellationToken.None;
        if (!_remoteClosed)
        {
            if (exitStatus is uint status)
                await _session.SendAsync(new SshWriter().Byte(SshMessage.ChannelRequest).UInt32(RemoteId).String("exit-status").Boolean(false).UInt32(status), ct);
            if (!_eofSent)
            {
                _eofSent = true;
                await _session.SendAsync(new SshWriter().Byte(SshMessage.ChannelEof).UInt32(RemoteId), ct);
            }
        }
        _closeSent = true;
        if (!_remoteClosed)
            await _session.SendAsync(new SshWriter().Byte(SshMessage.ChannelClose).UInt32(RemoteId), ct);
        else
            _session.RemoveChannel(Id);
    }

    private sealed class ChannelStream(SshChannel channel) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => channel.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => channel.ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override int Read(byte[] buffer, int offset, int count) => channel.ReadAsync(buffer.AsMemory(offset, count), default).AsTask().GetAwaiter().GetResult();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => channel.WriteAsync(buffer, ct);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => channel.WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override void Write(byte[] buffer, int offset, int count) => channel.WriteAsync(buffer.AsMemory(offset, count), default).AsTask().GetAwaiter().GetResult();

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
