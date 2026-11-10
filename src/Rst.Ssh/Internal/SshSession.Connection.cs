using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Rst.Ssh.Internal;

/// <summary>Connection protocol (RFC 4254): global requests, channels, subsystems, exec.</summary>
internal sealed partial class SshSession
{
    private readonly ConcurrentDictionary<uint, SshChannel> _channels = new();
    private uint _nextChannelId;

    private async Task OnConnectionMessageAsync(SshMessage type, byte[] payload, CancellationToken ct)
    {
        var r = new SshReader(payload.AsMemory(1));
        switch (type)
        {
            case SshMessage.GlobalRequest:
            {
                var name = r.ReadAscii();
                var wantReply = r.ReadBoolean();
                _log.LogDebug("[{Id}] Global request {Name}", Id, name);
                if (wantReply) await SendAsync(new SshWriter().Byte(SshMessage.RequestFailure), ct);
                return;
            }

            case SshMessage.ChannelOpen:
            {
                var channelType = r.ReadAscii();
                var remoteId = r.ReadUInt32();
                var remoteWindow = r.ReadUInt32();
                var remoteMaxPacket = r.ReadUInt32();

                if (channelType != "session")
                {
                    await SendOpenFailureAsync(remoteId, 1, $"Channel type {channelType} not allowed", ct);   // ADMINISTRATIVELY_PROHIBITED
                    return;
                }
                if (_channels.Count >= _options.Limits.MaxChannelsPerSession)
                {
                    await SendOpenFailureAsync(remoteId, 4, "Too many channels", ct);                     // RESOURCE_SHORTAGE
                    return;
                }

                var id = _nextChannelId++;
                var channel = new SshChannel(this, id, remoteId, remoteWindow, Math.Min(remoteMaxPacket, 256 * 1024),
                    _options.Limits.ChannelWindowSize, _options.Limits.ChannelMaxPacketSize);
                _channels[id] = channel;

                await SendAsync(new SshWriter().Byte(SshMessage.ChannelOpenConfirmation)
                    .UInt32(remoteId).UInt32(id)
                    .UInt32(_options.Limits.ChannelWindowSize).UInt32(_options.Limits.ChannelMaxPacketSize), ct);
                return;
            }

            case SshMessage.ChannelWindowAdjust:
                GetChannel(r.ReadUInt32()).OnWindowAdjust(r.ReadUInt32());
                return;

            case SshMessage.ChannelData:
            {
                var channel = GetChannel(r.ReadUInt32());
                channel.OnData(r.ReadBinaryArray());
                return;
            }

            case SshMessage.ChannelExtendedData:
                GetChannel(r.ReadUInt32());                  // stderr from the client – ignore
                return;

            case SshMessage.ChannelEof:
                GetChannel(r.ReadUInt32()).OnEof();
                return;

            case SshMessage.ChannelClose:
            {
                var channel = GetChannel(r.ReadUInt32());
                await channel.OnRemoteCloseAsync();
                return;
            }

            case SshMessage.ChannelRequest:
                await OnChannelRequestAsync(r, ct);
                return;

            case SshMessage.ChannelSuccess:
            case SshMessage.ChannelFailure:
            case SshMessage.RequestSuccess:
            case SshMessage.RequestFailure:
                return;                                     // replies to our own requests (currently none with want_reply)

            case SshMessage.ChannelOpenConfirmation:
            case SshMessage.ChannelOpenFailure:
                throw new SshProtocolException("Server does not open channels");
        }
    }

    private Task OnChannelRequestAsync(SshReader r, CancellationToken ct)
    {
        var channel = GetChannel(r.ReadUInt32());
        var request = r.ReadAscii();
        var wantReply = r.ReadBoolean();

        switch (request)
        {
            case "subsystem":
            {
                var name = r.ReadAscii();
                if (channel.HasHandler || !_server.Subsystems.TryGetValue(name, out var factory))
                {
                    _log.LogDebug("[{Id}] Subsystem {Name} abgelehnt", Id, name);
                    return ReplyAsync(channel, wantReply, false, ct);
                }
                _log.LogDebug("[{Id}] Subsystem {Name} on channel {Channel}", Id, name, channel.Id);
                return StartHandlerAsync(channel, wantReply, async c =>
                {
                    var handler = factory(this);
                    await handler.RunAsync(c, c.Closed);
                    return null;
                }, ct);
            }

            case "exec" when _server.ExecHandler is { } exec:
            {
                var command = r.ReadString();
                if (channel.HasHandler) return ReplyAsync(channel, wantReply, false, ct);
                return StartHandlerAsync(channel, wantReply, async c => (uint)await exec.ExecuteAsync(c, command, c.Closed), ct);
            }

            default:
                // pty-req, env, shell, x11-req, window-change, keepalive@openssh.com …
                _log.LogDebug("[{Id}] Channel request {Request} rejected", Id, request);
                return ReplyAsync(channel, wantReply, false, ct);
        }
    }

    private async Task StartHandlerAsync(SshChannel channel, bool wantReply, Func<SshChannel, Task<uint?>> run, CancellationToken ct)
    {
        channel.HasHandler = true;
        await ReplyAsync(channel, wantReply, true, ct);

        // Separate task: the session's read loop must keep running (data, window adjusts).
        _ = Task.Run(async () =>
        {
            uint? exitStatus = null;
            try { exitStatus = await run(channel); }
            catch (OperationCanceledException) when (channel.Closed.IsCancellationRequested) { }
            catch (Exception e)
            {
                _log.LogError(e, "[{Id}] Handler on channel {Channel} failed", Id, channel.Id);
                exitStatus = 1;
            }
            try { await channel.CloseAsync(exitStatus); }
            catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException) { }
        }, CancellationToken.None);
    }

    private Task ReplyAsync(SshChannel channel, bool wantReply, bool success, CancellationToken ct)
    {
        if (!wantReply) return Task.CompletedTask;
        return SendAsync(new SshWriter().Byte(success ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure).UInt32(channel.RemoteId), ct).AsTask();
    }

    private ValueTask SendOpenFailureAsync(uint remoteId, uint reason, string message, CancellationToken ct) =>
        SendAsync(new SshWriter().Byte(SshMessage.ChannelOpenFailure).UInt32(remoteId).UInt32(reason).String(message).String(""), ct);

    private SshChannel GetChannel(uint id) =>
        _channels.TryGetValue(id, out var c) ? c : throw new SshProtocolException($"Unknown channel {id}");

    internal void RemoveChannel(uint id) => _channels.TryRemove(id, out _);

    private async Task CloseAllChannelsAsync()
    {
        foreach (var c in _channels.Values) c.Abort();
        _channels.Clear();
        await Task.CompletedTask;
    }
}
