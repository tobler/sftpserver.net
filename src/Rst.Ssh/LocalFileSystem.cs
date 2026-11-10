using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;

namespace Rst.Ssh.Sftp;

public enum SymlinkPolicy
{
    /// <summary>Symbolic links and junctions are not followed (access -> PERMISSION_DENIED).
    /// Deleting, renaming and lstat of the link itself are allowed.</summary>
    Deny,
    /// <summary>Links are followed as long as the target lies within the root.</summary>
    AllowWithinRoot,
}

public sealed class LocalFileSystemOptions
{
    public bool ReadOnly { get; set; }
    public SymlinkPolicy Symlinks { get; set; } = SymlinkPolicy.Deny;
    public bool CreateRootIfMissing { get; set; }

    /// <summary>Unix permissions for new files when the client sends none (the umask applies on top).</summary>
    public UnixFileMode DefaultFileMode { get; set; } =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public UnixFileMode DefaultDirectoryMode { get; set; } =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
}

/// <summary>
/// Exposes a local directory as an SFTP file system (chroot-like).
/// Runs on Windows, Linux and macOS.
/// </summary>
/// <remarks>
/// Security: paths arrive as <see cref="SftpPath"/> (already normalized, no ".."). In addition,
/// every segment is validated per platform (Windows: "\", ":", reserved device names …),
/// every path segment is checked for links, and the result is verified against the root.
/// Known limitation: a local process could swap a link between the check and the access (TOCTOU).
/// Links cannot be created over SFTP itself; this only matters if other local
/// users have write access to the root.
/// </remarks>
public sealed class LocalFileSystem : ISftpFileSystem
{
    // Never accept setuid/setgid/sticky bits from clients.
    private const UnixFileMode PermissionMask =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static readonly EnumerationOptions DirectoryEnumeration = new()
    {
        AttributesToSkip = 0,          // The default would skip Hidden/System – i.e. all dotfiles on Unix!
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false,
    };

    private readonly string _root;
    private readonly string _rootWithSeparator;
    private readonly LocalFileSystemOptions _options;

    public LocalFileSystem(string root, LocalFileSystemOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        _options = options ?? new LocalFileSystemOptions();

        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full))
        {
            if (!_options.CreateRootIfMissing)
                throw new DirectoryNotFoundException($"Root directory does not exist: {full}");
            Directory.CreateDirectory(full);
        }

        // The root itself may be a link (e.g. /srv -> /data/srv) – it is resolved once.
        _root = Path.TrimEndingDirectorySeparator(RealPath(full));
        _rootWithSeparator = Path.EndsInDirectorySeparator(_root) ? _root : _root + Path.DirectorySeparatorChar;
    }

    public string RootPath => _root;

    public SftpCapabilities Capabilities =>
        SftpCapabilities.RandomAccessWrite | SftpCapabilities.AtomicRename |
        SftpCapabilities.Fsync | SftpCapabilities.Statistics;

    // ------------------------------------------------------------------ Attributes

    public ValueTask<SftpAttributes> GetAttributesAsync(SftpPath path, bool followLinks, CancellationToken ct)
    {
        try
        {
            var physical = Resolve(path, noFollowLast: !followLinks);
            var info = Lstat(physical) ?? throw NoSuchFile(path);
            if (info.LinkTarget is not null)            // only possible with followLinks=false
                return ValueTask.FromResult(ToAttributes(info, SftpFileType.SymbolicLink));
            return ValueTask.FromResult(ToAttributes(info, info is DirectoryInfo ? SftpFileType.Directory : SftpFileType.Regular));
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    public ValueTask SetAttributesAsync(SftpPath path, SftpAttributes attributes, CancellationToken ct)
    {
        try
        {
            EnsureWritable();
            var physical = Resolve(path, noFollowLast: false);
            var info = Lstat(physical) ?? throw NoSuchFile(path);
            var isDirectory = info is DirectoryInfo;

            if (attributes.Uid is not null || attributes.Gid is not null)
                throw new SftpException(SftpStatus.OpUnsupported, "Changing ownership is not supported");

            if (attributes.Size is long size)
            {
                if (isDirectory) throw new SftpException(SftpStatus.Failure, "Is a directory");
                using var fs = new FileStream(physical, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                fs.SetLength(size);
            }

            if (attributes.Permissions is UnixFileMode mode)
                SetPermissions(physical, isDirectory, mode);

            if (attributes.LastWriteTime is DateTimeOffset mtime)
            {
                if (isDirectory) Directory.SetLastWriteTimeUtc(physical, mtime.UtcDateTime);
                else File.SetLastWriteTimeUtc(physical, mtime.UtcDateTime);
            }

            if (attributes.LastAccessTime is DateTimeOffset atime)
            {
                if (isDirectory) Directory.SetLastAccessTimeUtc(physical, atime.UtcDateTime);
                else File.SetLastAccessTimeUtc(physical, atime.UtcDateTime);
            }

            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    // ------------------------------------------------------------------ Files

    public ValueTask<ISftpFileHandle> OpenFileAsync(SftpPath path, SftpOpenMode mode, SftpAttributes? createAttributes, CancellationToken ct)
    {
        try
        {
            var append = mode.HasFlag(SftpOpenMode.Append);
            var write = mode.HasFlag(SftpOpenMode.Write) || append;
            var read = mode.HasFlag(SftpOpenMode.Read) || !write;
            var create = mode.HasFlag(SftpOpenMode.Create);
            var truncate = mode.HasFlag(SftpOpenMode.Truncate);
            var exclusive = mode.HasFlag(SftpOpenMode.Exclusive);

            if ((create || truncate) && !write)
                throw new SftpException(SftpStatus.Failure, "CREATE/TRUNCATE require write access");
            if (write) EnsureWritable();

            var physical = Resolve(path, noFollowLast: false);
            if (Directory.Exists(physical))
                throw new SftpException(SftpStatus.Failure, "Is a directory");

            var fileMode = (create, truncate, exclusive) switch
            {
                (true, _, true) => FileMode.CreateNew,
                (true, true, false) => FileMode.Create,
                (true, false, false) => FileMode.OpenOrCreate,
                (false, true, _) => FileMode.Truncate,
                _ => FileMode.Open,
            };

            var options = new FileStreamOptions
            {
                Mode = fileMode,
                Access = read && write ? FileAccess.ReadWrite : write ? FileAccess.Write : FileAccess.Read,
                Share = FileShare.ReadWrite | FileShare.Delete,   // Unix semantics: renaming/deleting open files is allowed
                Options = FileOptions.Asynchronous,
                BufferSize = 0,                                   // no FileStream buffer, we write via RandomAccess
            };

            if (!OperatingSystem.IsWindows() && fileMode is FileMode.CreateNew or FileMode.Create or FileMode.OpenOrCreate)
                options.UnixCreateMode = (createAttributes?.Permissions ?? _options.DefaultFileMode) & PermissionMask;

            var stream = new FileStream(physical, options);
            return ValueTask.FromResult<ISftpFileHandle>(new LocalFileHandle(stream, append));
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    public ValueTask DeleteFileAsync(SftpPath path, CancellationToken ct)
    {
        try
        {
            EnsureWritable();
            var physical = Resolve(path, noFollowLast: true);
            var info = Lstat(physical) ?? throw NoSuchFile(path);

            if (info.LinkTarget is not null)
            {
                // Remove only the link, never the target.
                if (info.Attributes.HasFlag(FileAttributes.Directory)) Directory.Delete(physical);
                else File.Delete(physical);
            }
            else if (info is DirectoryInfo)
            {
                throw new SftpException(SftpStatus.Failure, "Is a directory");
            }
            else
            {
                File.Delete(physical);
            }
            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    // ------------------------------------------------------------------ Directories

    public async IAsyncEnumerable<SftpDirectoryEntry> EnumerateDirectoryAsync(SftpPath path, [EnumeratorCancellation] CancellationToken ct)
    {
        IEnumerator<FileSystemInfo> enumerator;
        try
        {
            var physical = Resolve(path, noFollowLast: false);
            var info = Lstat(physical) ?? throw NoSuchFile(path);
            if (info is not DirectoryInfo dir)
                throw new SftpException(SftpStatus.Failure, "Not a directory");
            enumerator = dir.EnumerateFileSystemInfos("*", DirectoryEnumeration).GetEnumerator();
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }

        using (enumerator)
        {
            var count = 0;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                FileSystemInfo item;
                try
                {
                    if (!enumerator.MoveNext()) break;
                    item = enumerator.Current;
                }
                catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }

                var type = item.LinkTarget is not null ? SftpFileType.SymbolicLink
                         : item is DirectoryInfo ? SftpFileType.Directory
                         : SftpFileType.Regular;

                SftpAttributes attributes;
                try { attributes = ToAttributes(item, type); }
                catch (IOException) { continue; }                 // deleted in the meantime
                catch (UnauthorizedAccessException) { continue; }

                yield return new SftpDirectoryEntry(item.Name, attributes);

                // Large directories: yield the thread occasionally.
                if (++count % 512 == 0) await Task.Yield();
            }
        }
    }

    public ValueTask CreateDirectoryAsync(SftpPath path, SftpAttributes? attributes, CancellationToken ct)
    {
        try
        {
            EnsureWritable();
            if (path.IsRoot) throw new SftpException(SftpStatus.Failure, "File exists");

            var physical = Resolve(path, noFollowLast: true);
            if (Lstat(physical) is not null)
                throw new SftpException(SftpStatus.Failure, "File exists");
            if (!Directory.Exists(Path.GetDirectoryName(physical)))
                throw NoSuchFile(path.Parent);

            // Directory.CreateDirectory would silently create missing parents – SFTP semantics are mkdir, not mkdir -p.
            if (OperatingSystem.IsWindows())
                Directory.CreateDirectory(physical);
            else
                Directory.CreateDirectory(physical, (attributes?.Permissions ?? _options.DefaultDirectoryMode) & PermissionMask);

            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    public ValueTask DeleteDirectoryAsync(SftpPath path, CancellationToken ct)
    {
        try
        {
            EnsureWritable();
            if (path.IsRoot) throw new SftpException(SftpStatus.PermissionDenied, "Cannot remove the root directory");

            var physical = Resolve(path, noFollowLast: true);
            var info = Lstat(physical) ?? throw NoSuchFile(path);
            if (info.LinkTarget is not null || info is not DirectoryInfo)
                throw new SftpException(SftpStatus.Failure, "Not a directory");

            if (Directory.EnumerateFileSystemEntries(physical, "*", DirectoryEnumeration).Any())
                throw new SftpException(SftpStatus.Failure, "Directory not empty");

            Directory.Delete(physical, recursive: false);
            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    public ValueTask RenameAsync(SftpPath from, SftpPath to, bool overwrite, CancellationToken ct)
    {
        try
        {
            EnsureWritable();
            if (from.IsRoot || to.IsRoot)
                throw new SftpException(SftpStatus.PermissionDenied, "Cannot rename the root directory");

            var source = Resolve(from, noFollowLast: true);
            var target = Resolve(to, noFollowLast: true);
            var sourceInfo = Lstat(source) ?? throw NoSuchFile(from);

            if (!Directory.Exists(Path.GetDirectoryName(target)))
                throw NoSuchFile(to.Parent);

            // Case-only rename (Windows/macOS): "target exists" would be wrong here.
            var caseOnlyRename = !string.Equals(source, target, StringComparison.Ordinal) &&
                                 string.Equals(source, target, PathComparison);

            var targetInfo = caseOnlyRename ? null : Lstat(target);
            if (targetInfo is not null)
            {
                // SFTP v3 RENAME: the target must not exist; posix-rename@openssh.com: the target is replaced.
                if (!overwrite) throw new SftpException(SftpStatus.Failure, "Target already exists");
                if (targetInfo is DirectoryInfo || sourceInfo is DirectoryInfo)
                    throw new SftpException(SftpStatus.Failure, "Directories cannot be replaced");
            }

            var isDirectory = sourceInfo.Attributes.HasFlag(FileAttributes.Directory);
            if (isDirectory) Directory.Move(source, target);
            else File.Move(source, target, overwrite: targetInfo is not null);

            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (IsTranslatable(e)) { throw Translate(e); }
    }

    public ValueTask<SftpFileSystemStats> GetStatsAsync(SftpPath path, CancellationToken ct)
    {
        try
        {
            const long blockSize = 4096;
            var drive = new DriveInfo(_root);
            return ValueTask.FromResult(new SftpFileSystemStats(
                BlockSize: blockSize,
                TotalBlocks: drive.TotalSize / blockSize,
                FreeBlocks: drive.TotalFreeSpace / blockSize,
                AvailableBlocks: drive.AvailableFreeSpace / blockSize,
                TotalFiles: 0,
                FreeFiles: 0));
        }
        catch (Exception e) when (e is not SftpException)
        {
            throw new SftpException(SftpStatus.OpUnsupported, e.Message);
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    // ------------------------------------------------------------------ Path resolution

    /// <summary>
    /// SftpPath -> physical path. Checks every segment and every link along the way.
    /// noFollowLast: do not resolve the last segment (lstat, deleting/renaming the link itself, mkdir).
    /// </summary>
    private string Resolve(SftpPath path, bool noFollowLast)
    {
        var current = _root;
        var segments = path.Segments;

        for (var i = 0; i < segments.Count; i++)
        {
            var segment = segments[i];
            if (!IsValidSegment(segment, OperatingSystem.IsWindows()))
                throw new SftpException(SftpStatus.Failure, $"Invalid file name: '{segment}'");

            current = Path.Join(current, segment);
            if (i == segments.Count - 1 && noFollowLast) break;

            var info = new FileInfo(current);
            if (info.LinkTarget is null) continue;              // not a link (or does not exist)

            if (_options.Symlinks == SymlinkPolicy.Deny)
                throw new SftpException(SftpStatus.PermissionDenied, "Symbolic links are not allowed");

            var resolved = info.ResolveLinkTarget(returnFinalTarget: true);
            if (resolved is null || !IsWithinRoot(Path.GetFullPath(resolved.FullName)))
                throw new SftpException(SftpStatus.PermissionDenied, "Link points outside the shared directory");

            current = Path.GetFullPath(resolved.FullName);
        }

        current = Path.GetFullPath(current);
        if (!IsWithinRoot(current))                              // second line of defense
            throw new SftpException(SftpStatus.PermissionDenied, "Permission denied");
        return current;
    }

    private bool IsWithinRoot(string fullPath) =>
        string.Equals(fullPath, _root, PathComparison) ||
        fullPath.StartsWith(_rootWithSeparator, PathComparison);

    private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>Validates a single name segment. Public so it can be tested on every platform.</summary>
    public static bool IsValidSegment(string segment, bool windows)
    {
        if (string.IsNullOrEmpty(segment) || segment is "." or ".." || segment.Contains('/') || segment.Contains('\0'))
            return false;
        if (!windows) return true;

        foreach (var c in segment)
            if (c < 32 || c is '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|')
                return false;                                    // "\" = separator, ":" = drive / alternate data stream

        if (segment.EndsWith('.') || segment.EndsWith(' '))
            return false;                                        // Windows strips these -> a different name than displayed

        var stem = segment.Split('.')[0].TrimEnd(' ');
        return !WindowsReservedNames.Contains(stem);             // "NUL.txt" is a device, too
    }

    private static string RealPath(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath)!;
        var current = root;
        foreach (var segment in fullPath[root.Length..].Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Join(current, segment);
            var target = new FileInfo(current).ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null) current = Path.GetFullPath(target.FullName);
        }
        return current;
    }

    // ------------------------------------------------------------------ Helpers

    /// <summary>lstat: information about the entry itself (links are not followed); null if it does not exist.</summary>
    private static FileSystemInfo? Lstat(string physical)
    {
        var file = new FileInfo(physical);
        if (file.LinkTarget is not null) return file;            // link (also to a directory or dangling)
        if (file.Exists) return file;
        var dir = new DirectoryInfo(physical);
        return dir.Exists ? dir : null;
    }

    private static SftpAttributes ToAttributes(FileSystemInfo info, SftpFileType type)
    {
        UnixFileMode permissions;
        if (OperatingSystem.IsWindows())
        {
            permissions = type == SftpFileType.Directory
                ? (UnixFileMode)0b111_101_101                    // 0755
                : info.Attributes.HasFlag(FileAttributes.ReadOnly)
                    ? (UnixFileMode)0b100_100_100                // 0444
                    : (UnixFileMode)0b110_100_100;               // 0644
        }
        else
        {
            permissions = info.UnixFileMode;
        }

        return new SftpAttributes
        {
            Type = type,
            Size = type == SftpFileType.Regular && info is FileInfo f ? f.Length : 0,
            Permissions = permissions,
            LastWriteTime = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
            LastAccessTime = new DateTimeOffset(info.LastAccessTimeUtc, TimeSpan.Zero),
        };
    }

    private static void SetPermissions(string physical, bool isDirectory, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows only knows "read-only" – map the owner write bit onto it.
            if (isDirectory) return;
            var attributes = File.GetAttributes(physical);
            attributes = mode.HasFlag(UnixFileMode.UserWrite)
                ? attributes & ~FileAttributes.ReadOnly
                : attributes | FileAttributes.ReadOnly;
            File.SetAttributes(physical, attributes);
        }
        else
        {
            File.SetUnixFileMode(physical, mode & PermissionMask);
        }
    }

    private void EnsureWritable()
    {
        if (_options.ReadOnly)
            throw new SftpException(SftpStatus.PermissionDenied, "Read-only file system");
    }

    private static SftpException NoSuchFile(SftpPath path) => new(SftpStatus.NoSuchFile, $"No such file: {path}");

    internal static bool IsTranslatable(Exception e) => e is not OperationCanceledException;

    internal static SftpException Translate(Exception e) => e switch
    {
        SftpException s => s,
        FileNotFoundException or DirectoryNotFoundException => new SftpException(SftpStatus.NoSuchFile, e.Message),
        UnauthorizedAccessException => new SftpException(SftpStatus.PermissionDenied, e.Message),
        ArgumentException => new SftpException(SftpStatus.BadMessage, e.Message),
        _ => new SftpException(SftpStatus.Failure, e.Message),
    };
}

/// <summary>Offset-based access via RandomAccess – concurrent reads/writes on the same handle are safe.</summary>
internal sealed class LocalFileHandle(FileStream stream, bool append) : ISftpFileHandle
{
    private readonly SemaphoreSlim _appendLock = new(1, 1);
    private SafeFileHandle Handle => stream.SafeFileHandle;

    public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
    {
        if (!stream.CanRead) throw new SftpException(SftpStatus.PermissionDenied, "Not opened for reading");
        try
        {
            return await RandomAccess.ReadAsync(Handle, buffer, offset, ct);   // 0 = EOF
        }
        catch (Exception e) when (LocalFileSystem.IsTranslatable(e)) { throw LocalFileSystem.Translate(e); }
    }

    public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        if (!stream.CanWrite) throw new SftpException(SftpStatus.PermissionDenied, "Not opened for writing");
        try
        {
            if (!append)
            {
                await RandomAccess.WriteAsync(Handle, data, offset, ct);
                return;
            }

            // APPEND: ignore the client's offset, always write at the end (like O_APPEND in OpenSSH).
            await _appendLock.WaitAsync(ct);
            try { await RandomAccess.WriteAsync(Handle, data, RandomAccess.GetLength(Handle), ct); }
            finally { _appendLock.Release(); }
        }
        catch (Exception e) when (LocalFileSystem.IsTranslatable(e)) { throw LocalFileSystem.Translate(e); }
    }

    public ValueTask<SftpAttributes> GetAttributesAsync(CancellationToken ct)
    {
        try
        {
            // Via the handle, not the path: the file may have been renamed or deleted in the meantime.
            var attributes = new SftpAttributes
            {
                Type = SftpFileType.Regular,
                Size = RandomAccess.GetLength(Handle),
                LastWriteTime = new DateTimeOffset(File.GetLastWriteTimeUtc(Handle), TimeSpan.Zero),
                LastAccessTime = new DateTimeOffset(File.GetLastAccessTimeUtc(Handle), TimeSpan.Zero),
                Permissions = OperatingSystem.IsWindows()
                    ? (File.GetAttributes(Handle).HasFlag(FileAttributes.ReadOnly) ? (UnixFileMode)0b100_100_100 : (UnixFileMode)0b110_100_100)
                    : File.GetUnixFileMode(Handle),
            };
            return ValueTask.FromResult(attributes);
        }
        catch (Exception e) when (LocalFileSystem.IsTranslatable(e)) { throw LocalFileSystem.Translate(e); }
    }

    public ValueTask SetAttributesAsync(SftpAttributes attributes, CancellationToken ct)
    {
        try
        {
            if (attributes.Uid is not null || attributes.Gid is not null)
                throw new SftpException(SftpStatus.OpUnsupported, "Changing ownership is not supported");

            if (attributes.Size is long size)
            {
                if (!stream.CanWrite) throw new SftpException(SftpStatus.PermissionDenied, "Not opened for writing");
                stream.SetLength(size);
            }

            if (attributes.Permissions is UnixFileMode mode && !OperatingSystem.IsWindows())
                File.SetUnixFileMode(Handle, mode & (UnixFileMode)0b111_111_111);

            if (attributes.LastWriteTime is DateTimeOffset mtime)
                File.SetLastWriteTimeUtc(Handle, mtime.UtcDateTime);
            if (attributes.LastAccessTime is DateTimeOffset atime)
                File.SetLastAccessTimeUtc(Handle, atime.UtcDateTime);

            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (LocalFileSystem.IsTranslatable(e)) { throw LocalFileSystem.Translate(e); }
    }

    public ValueTask FlushAsync(CancellationToken ct)
    {
        try
        {
            stream.Flush(flushToDisk: true);                     // fsync / FlushFileBuffers
            return ValueTask.CompletedTask;
        }
        catch (Exception e) when (LocalFileSystem.IsTranslatable(e)) { throw LocalFileSystem.Translate(e); }
    }

    public async ValueTask DisposeAsync()
    {
        await stream.DisposeAsync();
        _appendLock.Dispose();
    }
}
