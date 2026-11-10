using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using Rst.Ssh.Internal;

namespace Rst.Ssh.Sftp;

/// <summary>SFTP Version 3 (draft-ietf-secsh-filexfer-02) plus the usual OpenSSH extensions.</summary>
internal sealed class SftpSubsystem(SftpOptions options) : ISshSubsystemHandler
{
    private const int MaxPacketLength = 512 * 1024;
    private const int ReadDirBatch = 100;

    private enum Msg : byte
    {
        Init = 1, Version = 2, Open = 3, Close = 4, Read = 5, Write = 6, Lstat = 7, Fstat = 8, Setstat = 9, Fsetstat = 10,
        Opendir = 11, Readdir = 12, Remove = 13, Mkdir = 14, Rmdir = 15, Realpath = 16, Stat = 17, Rename = 18,
        Readlink = 19, Symlink = 20, Status = 101, Handle = 102, Data = 103, Name = 104, Attrs = 105,
        Extended = 200, ExtendedReply = 201,
    }

    [Flags]
    private enum AttrFlags : uint { Size = 1, UidGid = 2, Permissions = 4, AcModTime = 8, Extended = 0x80000000 }

    private sealed class FileHandle(ISftpFileHandle file, SftpPath path, bool upload)
    {
        public ISftpFileHandle File { get; } = file;
        public SftpPath Path { get; } = path;
        public bool Upload { get; } = upload;
        public long Bytes;
        public readonly Stopwatch Elapsed = Stopwatch.StartNew();
    }

    private sealed class DirHandle(SftpPath path, IAsyncEnumerator<SftpDirectoryEntry> entries)
    {
        public SftpPath Path { get; } = path;
        public IAsyncEnumerator<SftpDirectoryEntry> Entries { get; } = entries;
        public SftpDirectoryEntry? Pending;
        public bool Done;
        public int Count;
    }

    private readonly Dictionary<string, object> _handles = new(StringComparer.Ordinal);
    private uint _nextHandle;
    private ISshChannel _channel = null!;
    private ISftpFileSystem _fs = null!;
    private ClaimsPrincipal _user = null!;
    private string _userName = "user";
    private SftpEvents Events => options.Events;

    public async Task RunAsync(ISshChannel channel, CancellationToken ct)
    {
        _channel = channel;
        _user = channel.Session.User!;
        _userName = _user.Identity?.Name ?? "user";
        _fs = await options.FileSystemFactory!(channel.Session);

        try
        {
            await RaiseAsync(Events.OnSessionStarted, new SftpSessionContext(channel.Session, _user, _fs));

            while (!ct.IsCancellationRequested)
            {
                var packet = await ReadPacketAsync(ct);
                if (packet is null) break;
                await HandleAsync(packet, ct);
            }
        }
        catch (IOException) { /* channel gone */ }
        finally
        {
            foreach (var h in _handles.Values) await CloseHandleAsync(h, aborted: true);
            _handles.Clear();
            await RaiseAsync(Events.OnSessionEnded, new SftpSessionContext(channel.Session, _user, _fs));
            await _fs.DisposeAsync();
        }
    }

    // ------------------------------------------------------------------ Packet I/O

    private async Task<byte[]?> ReadPacketAsync(CancellationToken ct)
    {
        var len = new byte[4];
        if (!await ReadExactAsync(len, ct)) return null;
        var length = BinaryPrimitives.ReadUInt32BigEndian(len);
        if (length < 1 || length > MaxPacketLength) throw new IOException($"Invalid SFTP packet length {length}");
        var body = new byte[length];
        if (!await ReadExactAsync(body, ct)) return null;
        return body;
    }

    private async Task<bool> ReadExactAsync(byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await _channel.Stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    private async Task SendAsync(SshWriter body, CancellationToken ct)
    {
        var packet = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)body.Length);
        body.Span.CopyTo(packet.AsSpan(4));
        await _channel.Stream.WriteAsync(packet, ct);
    }

    private Task SendStatusAsync(uint id, SftpStatus status, string? message, CancellationToken ct) =>
        SendAsync(new SshWriter().Byte((byte)Msg.Status).UInt32(id).UInt32((uint)status)
            .String(message ?? DefaultMessage(status)).String("en"), ct);

    private static string DefaultMessage(SftpStatus s) => s switch
    {
        SftpStatus.Ok => "Success",
        SftpStatus.Eof => "End of file",
        SftpStatus.NoSuchFile => "No such file",
        SftpStatus.PermissionDenied => "Permission denied",
        SftpStatus.BadMessage => "Bad message",
        SftpStatus.OpUnsupported => "Operation unsupported",
        _ => "Failure",
    };

    // ------------------------------------------------------------------ Dispatch

    private async Task HandleAsync(byte[] packet, CancellationToken ct)
    {
        var type = (Msg)packet[0];
        var r = new SshReader(packet.AsMemory(1));

        if (type == Msg.Init)
        {
            var w = new SshWriter().Byte((byte)Msg.Version).UInt32(3);
            foreach (var (name, version) in new[]
                     {
                         ("posix-rename@openssh.com", "1"), ("statvfs@openssh.com", "2"),
                         ("fsync@openssh.com", "1"), ("limits@openssh.com", "1"),
                     })
                w.String(name).String(version);
            await SendAsync(w, ct);
            return;
        }

        uint id = 0;
        try
        {
            id = r.ReadUInt32();
            await DispatchAsync(type, id, r, ct);
        }
        catch (SshProtocolException e)
        {
            await SendStatusAsync(id, SftpStatus.BadMessage, e.Message, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException && !_channel.Closed.IsCancellationRequested)
        {
            // File system errors -> SFTP status. If the channel is gone, let the exception propagate.
            var s = LocalFileSystem.Translate(e);
            await SendStatusAsync(id, s.Status, s.Message, ct);
        }
    }

    private async Task DispatchAsync(Msg type, uint id, SshReader r, CancellationToken ct)
    {
        switch (type)
        {
            case Msg.Realpath:
            {
                var path = SftpPath.Parse(r.ReadString());
                await RunAsync(SftpOperation.RealPath, path, null, ct, () => SendNameAsync(id, [(path.Value, path.Value, new SftpAttributes())], ct));
                return;
            }

            case Msg.Stat:
            case Msg.Lstat:
            {
                var path = SftpPath.Parse(r.ReadString());
                await RunAsync(SftpOperation.Stat, path, null, ct, async () =>
                {
                    var a = await _fs.GetAttributesAsync(path, followLinks: type == Msg.Stat, ct);
                    await SendAttrsAsync(id, a, ct);
                });
                return;
            }

            case Msg.Fstat:
            {
                var h = GetFile(r);
                await RunAsync(SftpOperation.Stat, h.Path, null, ct, async () => await SendAttrsAsync(id, await h.File.GetAttributesAsync(ct), ct));
                return;
            }

            case Msg.Setstat:
            {
                var path = SftpPath.Parse(r.ReadString());
                var attrs = ReadAttrs(r);
                await RunAsync(SftpOperation.SetStat, path, null, ct, async () =>
                {
                    await _fs.SetAttributesAsync(path, attrs, ct);
                    await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                });
                return;
            }

            case Msg.Fsetstat:
            {
                var h = GetFile(r);
                var attrs = ReadAttrs(r);
                await RunAsync(SftpOperation.SetStat, h.Path, null, ct, async () =>
                {
                    await h.File.SetAttributesAsync(attrs, ct);
                    await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                });
                return;
            }

            case Msg.Open:
                await OpenAsync(id, SftpPath.Parse(r.ReadString()), (SftpOpenMode)r.ReadUInt32(), ReadAttrs(r), ct);
                return;

            case Msg.Read:
            {
                var h = GetFile(r);
                var offset = r.ReadUInt64();
                var length = (int)Math.Min(r.ReadUInt32(), (uint)options.MaxReadSize);
                await RunAsync(SftpOperation.Read, h.Path, null, ct, async () =>
                {
                    var buffer = new byte[length];
                    var n = await h.File.ReadAsync((long)offset, buffer, ct);
                    if (n == 0) { await SendStatusAsync(id, SftpStatus.Eof, null, ct); return; }
                    h.Bytes += n;
                    await SendAsync(new SshWriter(n + 16).Byte((byte)Msg.Data).UInt32(id).Binary(buffer.AsSpan(0, n)), ct);
                });
                return;
            }

            case Msg.Write:
            {
                var h = GetFile(r);
                var offset = r.ReadUInt64();
                var data = r.ReadBinaryArray();
                await RunAsync(SftpOperation.Write, h.Path, null, ct, async () =>
                {
                    await h.File.WriteAsync((long)offset, data, ct);
                    h.Bytes += data.Length;
                    await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                });
                return;
            }

            case Msg.Close:
            {
                var key = r.ReadString();
                if (!_handles.Remove(key, out var handle)) throw new SftpException(SftpStatus.Failure, "Invalid handle");
                await CloseHandleAsync(handle, aborted: false);
                await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                return;
            }

            case Msg.Opendir:
                await OpenDirAsync(id, SftpPath.Parse(r.ReadString()), ct);
                return;

            case Msg.Readdir:
                await ReadDirAsync(id, r.ReadString(), ct);
                return;

            case Msg.Remove:
            {
                var path = SftpPath.Parse(r.ReadString());
                await ChangeAsync(id, SftpOperation.Remove, path, null, Events.OnDeleting, Events.OnDeleted, () => _fs.DeleteFileAsync(path, ct), ct);
                return;
            }

            case Msg.Rmdir:
            {
                var path = SftpPath.Parse(r.ReadString());
                await ChangeAsync(id, SftpOperation.RmDir, path, null, Events.OnDeleting, Events.OnDeleted, () => _fs.DeleteDirectoryAsync(path, ct), ct);
                return;
            }

            case Msg.Mkdir:
            {
                var path = SftpPath.Parse(r.ReadString());
                var attrs = ReadAttrs(r);
                await ChangeAsync(id, SftpOperation.MkDir, path, null, Events.OnDirectoryCreating, Events.OnDirectoryCreated,
                    () => _fs.CreateDirectoryAsync(path, attrs.Permissions is null ? null : attrs, ct), ct);
                return;
            }

            case Msg.Rename:
            {
                var from = SftpPath.Parse(r.ReadString());
                var to = SftpPath.Parse(r.ReadString());
                await ChangeAsync(id, SftpOperation.Rename, from, to, Events.OnRenaming, Events.OnRenamed,
                    () => _fs.RenameAsync(from, to, overwrite: false, ct), ct);
                return;
            }

            case Msg.Readlink:
            {
                var path = SftpPath.Parse(r.ReadString());
                await RunAsync(SftpOperation.ReadLink, path, null, ct, async () =>
                {
                    var target = await _fs.ReadLinkAsync(path, ct);
                    await SendNameAsync(id, [(target.Value, target.Value, new SftpAttributes())], ct);
                });
                return;
            }

            case Msg.Symlink:
            {
                // OpenSSH swaps the arguments relative to the draft (target first) – all common clients follow OpenSSH.
                var target = SftpPath.Parse(r.ReadString());
                var link = SftpPath.Parse(r.ReadString());
                await RunAsync(SftpOperation.SymLink, link, target, ct, async () =>
                {
                    await _fs.CreateSymbolicLinkAsync(link, target, ct);
                    await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                });
                return;
            }

            case Msg.Extended:
                await ExtendedAsync(id, r.ReadAscii(), r, ct);
                return;

            default:
                await SendStatusAsync(id, SftpStatus.OpUnsupported, $"Message {type} not supported", ct);
                return;
        }
    }

    private async Task ExtendedAsync(uint id, string name, SshReader r, CancellationToken ct)
    {
        switch (name)
        {
            case "posix-rename@openssh.com":
            {
                var from = SftpPath.Parse(r.ReadString());
                var to = SftpPath.Parse(r.ReadString());
                await ChangeAsync(id, SftpOperation.Rename, from, to, Events.OnRenaming, Events.OnRenamed,
                    () => _fs.RenameAsync(from, to, overwrite: true, ct), ct);
                return;
            }

            case "statvfs@openssh.com":
            {
                var path = SftpPath.Parse(r.ReadString());
                await RunAsync(SftpOperation.StatVfs, path, null, ct, async () =>
                {
                    var s = await _fs.GetStatsAsync(path, ct);
                    await SendAsync(new SshWriter().Byte((byte)Msg.ExtendedReply).UInt32(id)
                        .UInt64((ulong)s.BlockSize).UInt64((ulong)s.BlockSize)
                        .UInt64((ulong)s.TotalBlocks).UInt64((ulong)s.FreeBlocks).UInt64((ulong)s.AvailableBlocks)
                        .UInt64((ulong)s.TotalFiles).UInt64((ulong)s.FreeFiles).UInt64((ulong)s.FreeFiles)
                        .UInt64(0).UInt64(0).UInt64(255), ct);
                });
                return;
            }

            case "fsync@openssh.com":
            {
                var h = GetFile(r);
                await RunAsync(SftpOperation.Fsync, h.Path, null, ct, async () =>
                {
                    await h.File.FlushAsync(ct);
                    await SendStatusAsync(id, SftpStatus.Ok, null, ct);
                });
                return;
            }

            case "limits@openssh.com":
                await SendAsync(new SshWriter().Byte((byte)Msg.ExtendedReply).UInt32(id)
                    .UInt64(MaxPacketLength).UInt64((ulong)options.MaxReadSize).UInt64((ulong)options.MaxReadSize)
                    .UInt64((ulong)options.MaxOpenHandles), ct);
                return;

            default:
                await SendStatusAsync(id, SftpStatus.OpUnsupported, $"Extension {name} not supported", ct);
                return;
        }
    }

    // ------------------------------------------------------------------ Files & directories

    private async Task OpenAsync(uint id, SftpPath path, SftpOpenMode mode, SftpAttributes attrs, CancellationToken ct)
    {
        EnsureHandleCapacity();
        var upload = mode.HasFlag(SftpOpenMode.Write) || mode.HasFlag(SftpOpenMode.Append);

        long? existingSize = null;
        try { existingSize = (await _fs.GetAttributesAsync(path, true, ct)).Size; }
        catch (SftpException) { }

        var starting = new TransferStartingContext(_channel.Session, _user, path, mode, existingSize);
        await RaiseAsync(upload ? Events.OnUploadStarting : Events.OnDownloadStarting, starting);
        if (starting.DeniedStatus is { } denied)
        {
            await SendStatusAsync(id, denied, starting.DeniedMessage, ct);
            return;
        }

        await RunAsync(SftpOperation.Open, path, null, ct, async () =>
        {
            var file = await _fs.OpenFileAsync(path, mode, attrs.Permissions is null ? null : attrs, ct);
            await SendHandleAsync(id, new FileHandle(file, path, upload), ct);
        });
    }

    private async Task OpenDirAsync(uint id, SftpPath path, CancellationToken ct)
    {
        EnsureHandleCapacity();
        var listing = new SftpOperationContext(_channel.Session, _user, path);
        await RaiseAsync(Events.OnDirectoryListing, listing);
        if (listing.DeniedStatus is { } denied)
        {
            await SendStatusAsync(id, denied, listing.DeniedMessage, ct);
            return;
        }

        await RunAsync(SftpOperation.OpenDir, path, null, ct, async () =>
        {
            var enumerator = _fs.EnumerateDirectoryAsync(path, ct).GetAsyncEnumerator(ct);
            var dir = new DirHandle(path, enumerator);
            // Fetch the first entry right away so "does not exist" is already reported on OPENDIR.
            try
            {
                if (await enumerator.MoveNextAsync()) dir.Pending = enumerator.Current;
                else dir.Done = true;
            }
            catch
            {
                await enumerator.DisposeAsync();
                throw;
            }
            await SendHandleAsync(id, dir, ct);
        });
    }

    private async Task ReadDirAsync(uint id, string key, CancellationToken ct)
    {
        if (!_handles.TryGetValue(key, out var h) || h is not DirHandle dir)
            throw new SftpException(SftpStatus.Failure, "Invalid handle");

        var batch = new List<(string, string, SftpAttributes)>(ReadDirBatch);
        if (dir.Pending is { } first) { batch.Add(Entry(first)); dir.Pending = null; }
        while (!dir.Done && batch.Count < ReadDirBatch)
        {
            if (await dir.Entries.MoveNextAsync()) batch.Add(Entry(dir.Entries.Current));
            else dir.Done = true;
        }

        if (batch.Count == 0) { await SendStatusAsync(id, SftpStatus.Eof, null, ct); return; }
        dir.Count += batch.Count;
        await SendNameAsync(id, batch, ct);

        (string, string, SftpAttributes) Entry(SftpDirectoryEntry e) => (e.Name, e.LongName ?? LongName(e.Name, e.Attributes), e.Attributes);
    }

    private async Task CloseHandleAsync(object handle, bool aborted)
    {
        switch (handle)
        {
            case FileHandle f:
            {
                long? size = null;
                try { size = (await f.File.GetAttributesAsync(CancellationToken.None)).Size; } catch { }
                await f.File.DisposeAsync();
                var done = new TransferCompletedContext(_channel.Session, _user, f.Path, f.Bytes, size, f.Elapsed.Elapsed, aborted, null);
                await RaiseAsync(f.Upload ? Events.OnUploadCompleted : Events.OnDownloadCompleted, done);
                break;
            }
            case DirHandle d:
                await d.Entries.DisposeAsync();
                await RaiseAsync(Events.OnDirectoryListed, new DirectoryListedContext(_channel.Session, _user, d.Path, d.Count));
                break;
        }
    }

    private async Task ChangeAsync(uint id, SftpOperation op, SftpPath path, SftpPath? target,
        Func<SftpOperationContext, ValueTask>? before, Func<SftpOperationContext, ValueTask>? after,
        Func<ValueTask> action, CancellationToken ct)
    {
        var ctx = new SftpOperationContext(_channel.Session, _user, path, target);
        await RaiseAsync(before, ctx);
        if (ctx.DeniedStatus is { } denied)
        {
            await SendStatusAsync(id, denied, ctx.DeniedMessage, ct);
            return;
        }

        await RunAsync(op, path, target, ct, async () =>
        {
            await action();
            await SendStatusAsync(id, SftpStatus.Ok, null, ct);
        });
        await RaiseAsync(after, ctx);
    }

    // ------------------------------------------------------------------ Middleware

    private async Task RunAsync(SftpOperation op, SftpPath path, SftpPath? target, CancellationToken ct, Func<Task> core)
    {
        if (options.Middlewares.Count == 0) { await core(); return; }
        var ctx = new SftpRequestContext(_channel.Session, op, path, target, _user);
        Func<ValueTask> next = () => new ValueTask(core());
        for (var i = options.Middlewares.Count - 1; i >= 0; i--)
        {
            var middleware = options.Middlewares[i];
            var inner = next;
            next = () => middleware(ctx, inner);
        }
        await next();
    }

    private static async ValueTask RaiseAsync<T>(Func<T, ValueTask>? handler, T arg)
    {
        if (handler is not null) await handler(arg);
    }

    // ------------------------------------------------------------------ Helpers

    private FileHandle GetFile(SshReader r)
    {
        var key = r.ReadString();
        return _handles.TryGetValue(key, out var h) && h is FileHandle f ? f : throw new SftpException(SftpStatus.Failure, "Invalid handle");
    }

    private void EnsureHandleCapacity()
    {
        if (_handles.Count >= options.MaxOpenHandles)
            throw new SftpException(SftpStatus.Failure, "Too many open handles");
    }

    private Task SendHandleAsync(uint id, object handle, CancellationToken ct)
    {
        var key = (_nextHandle++).ToString("x8", CultureInfo.InvariantCulture);
        _handles[key] = handle;
        return SendAsync(new SshWriter().Byte((byte)Msg.Handle).UInt32(id).String(key), ct);
    }

    private Task SendAttrsAsync(uint id, SftpAttributes a, CancellationToken ct)
    {
        var w = new SshWriter().Byte((byte)Msg.Attrs).UInt32(id);
        WriteAttrs(w, a);
        return SendAsync(w, ct);
    }

    private Task SendNameAsync(uint id, IReadOnlyList<(string Name, string LongName, SftpAttributes Attrs)> entries, CancellationToken ct)
    {
        var w = new SshWriter(4096).Byte((byte)Msg.Name).UInt32(id).UInt32((uint)entries.Count);
        foreach (var (name, longName, attrs) in entries)
        {
            w.String(name).String(longName);
            WriteAttrs(w, attrs);
        }
        return SendAsync(w, ct);
    }

    internal static SftpAttributes ReadAttrs(SshReader r)    // internal (not private) so the fuzz harness can target it
    {
        var flags = (AttrFlags)r.ReadUInt32();
        long? size = flags.HasFlag(AttrFlags.Size) ? (long)r.ReadUInt64() : null;
        uint? uid = null, gid = null;
        if (flags.HasFlag(AttrFlags.UidGid)) { uid = r.ReadUInt32(); gid = r.ReadUInt32(); }
        UnixFileMode? perms = flags.HasFlag(AttrFlags.Permissions) ? (UnixFileMode)(r.ReadUInt32() & 0xFFF) : null;
        DateTimeOffset? atime = null, mtime = null;
        if (flags.HasFlag(AttrFlags.AcModTime))
        {
            atime = DateTimeOffset.FromUnixTimeSeconds(r.ReadUInt32());
            mtime = DateTimeOffset.FromUnixTimeSeconds(r.ReadUInt32());
        }
        if (flags.HasFlag(AttrFlags.Extended))
        {
            var count = r.ReadUInt32();
            for (var i = 0; i < count; i++) { r.ReadBinary(); r.ReadBinary(); }
        }
        return new SftpAttributes { Size = size, Uid = uid, Gid = gid, Permissions = perms, LastAccessTime = atime, LastWriteTime = mtime };
    }

    private static void WriteAttrs(SshWriter w, SftpAttributes a)
    {
        AttrFlags flags = 0;
        if (a.Size is not null) flags |= AttrFlags.Size;
        if (a.Uid is not null && a.Gid is not null) flags |= AttrFlags.UidGid;
        if (a.Permissions is not null || a.Type is not null) flags |= AttrFlags.Permissions;
        if (a.LastWriteTime is not null || a.LastAccessTime is not null) flags |= AttrFlags.AcModTime;

        w.UInt32((uint)flags);
        if (a.Size is long size) w.UInt64((ulong)size);
        if (flags.HasFlag(AttrFlags.UidGid)) w.UInt32(a.Uid!.Value).UInt32(a.Gid!.Value);
        if (flags.HasFlag(AttrFlags.Permissions)) w.UInt32(ModeBits(a));
        if (flags.HasFlag(AttrFlags.AcModTime))
        {
            var m = a.LastWriteTime ?? a.LastAccessTime!.Value;
            var at = a.LastAccessTime ?? m;
            w.UInt32((uint)Math.Clamp(at.ToUnixTimeSeconds(), 0, uint.MaxValue)).UInt32((uint)Math.Clamp(m.ToUnixTimeSeconds(), 0, uint.MaxValue));
        }
    }

    /// <summary>Permissions plus file type bits (S_IFREG/S_IFDIR/S_IFLNK) – clients derive the type from them.</summary>
    private static uint ModeBits(SftpAttributes a)
    {
        var type = a.Type switch
        {
            SftpFileType.Directory => 0x4000u,
            SftpFileType.SymbolicLink => 0xA000u,
            SftpFileType.Regular => 0x8000u,
            _ => 0u,
        };
        return type | (uint)(a.Permissions ?? 0) & 0xFFF;
    }

    /// <summary>"ls -l" line as displayed by OpenSSH clients.</summary>
    private string LongName(string name, SftpAttributes a)
    {
        var mode = ModeBits(a);
        var sb = new StringBuilder(80);
        sb.Append((mode & 0xF000) switch { 0x4000 => 'd', 0xA000 => 'l', _ => '-' });
        const string rwx = "rwxrwxrwx";
        for (var i = 0; i < 9; i++) sb.Append((mode & (1u << (8 - i))) != 0 ? rwx[i] : '-');

        var mtime = (a.LastWriteTime ?? DateTimeOffset.UnixEpoch).ToLocalTime();
        var date = Math.Abs((DateTimeOffset.Now - mtime).TotalDays) < 180
            ? mtime.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture)
            : mtime.ToString("MMM dd  yyyy", CultureInfo.InvariantCulture);
        var user = _userName.Length > 8 ? _userName[..8] : _userName;

        sb.Append(CultureInfo.InvariantCulture, $"    1 {user,-8} {user,-8} {a.Size ?? 0,12} {date} {name}");
        return sb.ToString();
    }
}
