// ============================================================================
//  Rst.Ssh.Sftp – public API
//  Package: Rst.Ssh.Sftp  (SFTP v3 + OpenSSH extensions, VFS, middleware)
// ============================================================================
using System.Security.Claims;

namespace Rst.Ssh.Sftp;

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

public static class SftpServerBuilderExtensions
{
    public static SshServerBuilder AddSftp(this SshServerBuilder builder, Action<SftpOptions> configure)
    {
        var options = new SftpOptions();
        configure(options);
        if (options.FileSystemFactory is null)
            throw new InvalidOperationException("SftpOptions.FileSystemFactory must be set.");
        return builder.AddSubsystem("sftp", _ => new SftpSubsystem(options));
    }
}

public sealed class SftpOptions
{
    /// <summary>One file system per session – typically depending on the authenticated user.</summary>
    public Func<ISshSession, ValueTask<ISftpFileSystem>>? FileSystemFactory { get; set; }

    public int MaxOpenHandles { get; set; } = 256;
    public int MaxReadSize { get; set; } = 256 * 1024;               // advertised via limits@openssh.com

    /// <summary>Middleware pipeline in the style of ASP.NET Core – auditing, quotas, virus scanning, permissions …</summary>
    public SftpOptions Use(SftpMiddleware middleware) { Middlewares.Add(middleware); return this; }

    internal List<SftpMiddleware> Middlewares { get; } = [];

    /// <summary>Convenience events for simple scenarios.</summary>
    public SftpEvents Events { get; } = new();
}

public delegate ValueTask SftpMiddleware(SftpRequestContext ctx, Func<ValueTask> next);

/// <summary>
/// Convenience events. "…ing" events run BEFORE the operation and can reject it with ctx.Deny(...)
/// (the client receives the status and message). "…ed" events run afterwards.
/// For anything more fine-grained (every single READ/WRITE packet) use middleware.
/// </summary>
public sealed class SftpEvents
{
    // Session
    public Func<SftpSessionContext, ValueTask>? OnSessionStarted { get; set; }   // SFTP subsystem opened, file system created
    public Func<SftpSessionContext, ValueTask>? OnSessionEnded { get; set; }

    // Directories
    public Func<SftpOperationContext, ValueTask>? OnDirectoryListing { get; set; }
    public Func<DirectoryListedContext, ValueTask>? OnDirectoryListed { get; set; }
    public Func<SftpOperationContext, ValueTask>? OnDirectoryCreating { get; set; }
    public Func<SftpOperationContext, ValueTask>? OnDirectoryCreated { get; set; }

    // Files: download = open for reading, upload = open for writing
    public Func<TransferStartingContext, ValueTask>? OnDownloadStarting { get; set; }
    public Func<TransferCompletedContext, ValueTask>? OnDownloadCompleted { get; set; }
    public Func<TransferStartingContext, ValueTask>? OnUploadStarting { get; set; }
    public Func<TransferCompletedContext, ValueTask>? OnUploadCompleted { get; set; }

    // Modifications
    public Func<SftpOperationContext, ValueTask>? OnDeleting { get; set; }
    public Func<SftpOperationContext, ValueTask>? OnDeleted { get; set; }
    public Func<SftpOperationContext, ValueTask>? OnRenaming { get; set; }
    public Func<SftpOperationContext, ValueTask>? OnRenamed { get; set; }
}

public sealed record SftpSessionContext(ISshSession Session, ClaimsPrincipal User, ISftpFileSystem FileSystem);

public class SftpOperationContext(ISshSession session, ClaimsPrincipal user, SftpPath path, SftpPath? targetPath = null)
{
    public ISshSession Session { get; } = session;
    public ClaimsPrincipal User { get; } = user;
    public SftpPath Path { get; } = path;
    public SftpPath? TargetPath { get; } = targetPath;                // for rename

    public SftpStatus? DeniedStatus { get; private set; }
    public string? DeniedMessage { get; private set; }
    /// <summary>Only effective in "…ing" events.</summary>
    public void Deny(SftpStatus status = SftpStatus.PermissionDenied, string? message = null) => (DeniedStatus, DeniedMessage) = (status, message);
}

public sealed class TransferStartingContext(ISshSession session, ClaimsPrincipal user, SftpPath path, SftpOpenMode mode, long? existingSize)
    : SftpOperationContext(session, user, path)
{
    public SftpOpenMode Mode { get; } = mode;
    public long? ExistingSize { get; } = existingSize;                // download: file size; upload: null for a new file
}

public sealed record DirectoryListedContext(ISshSession Session, ClaimsPrincipal User, SftpPath Path, int EntryCount);

/// <summary>
/// Raised when the handle is closed – also when the transfer is aborted (disconnect), then with Aborted = true.
/// "Completed" does not mean "complete": clients may stop midway or read only parts of a file.
/// </summary>
public sealed record TransferCompletedContext(
    ISshSession Session,
    ClaimsPrincipal User,
    SftpPath Path,
    long BytesTransferred,
    long? FileSize,
    TimeSpan Duration,
    bool Aborted,
    string? ContentId);                                              // e.g. the IPFS CID of an upload (MetadataBlobFileSystem)

public sealed record SftpRequestContext(
    ISshSession Session,
    SftpOperation Operation,
    SftpPath Path,
    SftpPath? TargetPath,                                            // for rename/link
    ClaimsPrincipal User);


public enum SftpOperation
{
    Open, Read, Write, Close, Stat, SetStat, OpenDir, ReadDir, Remove, MkDir, RmDir,
    Rename, RealPath, ReadLink, SymLink, HardLink, StatVfs, Fsync, CopyData
}

// ---------------------------------------------------------------------------
// Virtual file system
// ---------------------------------------------------------------------------

/// <summary>
/// One instance per session. Report errors by throwing SftpException – or standard exceptions,
/// which are mapped (FileNotFound -> NO_SUCH_FILE, UnauthorizedAccess -> PERMISSION_DENIED,
/// IOException -> FAILURE). Optional features are declared via Capabilities instead of guessing from NotSupportedException.
/// </summary>
public interface ISftpFileSystem : IAsyncDisposable
{
    SftpCapabilities Capabilities { get; }

    ValueTask<SftpAttributes> GetAttributesAsync(SftpPath path, bool followLinks, CancellationToken ct);
    ValueTask SetAttributesAsync(SftpPath path, SftpAttributes attributes, CancellationToken ct);

    ValueTask<ISftpFileHandle> OpenFileAsync(SftpPath path, SftpOpenMode mode, SftpAttributes? createAttributes, CancellationToken ct);

    /// <summary>Streamed rather than a list: large directories are delivered in READDIR batches.</summary>
    IAsyncEnumerable<SftpDirectoryEntry> EnumerateDirectoryAsync(SftpPath path, CancellationToken ct);

    ValueTask CreateDirectoryAsync(SftpPath path, SftpAttributes? attributes, CancellationToken ct);
    ValueTask DeleteDirectoryAsync(SftpPath path, CancellationToken ct);
    ValueTask DeleteFileAsync(SftpPath path, CancellationToken ct);

    /// <summary>overwrite=true corresponds to posix-rename@openssh.com (atomic replace).</summary>
    ValueTask RenameAsync(SftpPath from, SftpPath to, bool overwrite, CancellationToken ct);

    // Optional – only called when declared in Capabilities:
    ValueTask<SftpPath> ReadLinkAsync(SftpPath path, CancellationToken ct) => throw new SftpException(SftpStatus.OpUnsupported);
    ValueTask CreateSymbolicLinkAsync(SftpPath link, SftpPath target, CancellationToken ct) => throw new SftpException(SftpStatus.OpUnsupported);
    ValueTask CreateHardLinkAsync(SftpPath link, SftpPath target, CancellationToken ct) => throw new SftpException(SftpStatus.OpUnsupported);
    ValueTask<SftpFileSystemStats> GetStatsAsync(SftpPath path, CancellationToken ct) => throw new SftpException(SftpStatus.OpUnsupported);
}

[Flags]
public enum SftpCapabilities
{
    None = 0,
    RandomAccessWrite = 1,     // missing for S3/IPFS & co. -> the library spools uploads and commits on close
    SymbolicLinks = 2,
    HardLinks = 4,
    AtomicRename = 8,
    Statistics = 16,           // statvfs@openssh.com (quota display in the client)
    Fsync = 32,
}

public interface ISftpFileHandle : IAsyncDisposable
{
    /// <summary>Offset-based, because clients pipeline reads/writes and responses may arrive out of order.</summary>
    ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct);
    ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct);

    ValueTask<SftpAttributes> GetAttributesAsync(CancellationToken ct);
    ValueTask SetAttributesAsync(SftpAttributes attributes, CancellationToken ct);   // includes truncate via Size
    ValueTask FlushAsync(CancellationToken ct);                                      // fsync@openssh.com
}

[Flags]
public enum SftpOpenMode { Read = 1, Write = 2, Append = 4, Create = 8, Truncate = 16, Exclusive = 32 }

public sealed record SftpAttributes
{
    public long? Size { get; init; }
    public uint? Uid { get; init; }
    public uint? Gid { get; init; }
    public UnixFileMode? Permissions { get; init; }
    public SftpFileType? Type { get; init; }
    public DateTimeOffset? LastAccessTime { get; init; }
    public DateTimeOffset? LastWriteTime { get; init; }
    public IReadOnlyDictionary<string, ReadOnlyMemory<byte>>? Extended { get; init; }
}

public enum SftpFileType { Regular, Directory, SymbolicLink, Special, Unknown }

public sealed record SftpDirectoryEntry(string Name, SftpAttributes Attributes)
{
    /// <summary>"ls -l" line; generated when null (OpenSSH clients display it).</summary>
    public string? LongName { get; init; }
}

public sealed record SftpFileSystemStats(long BlockSize, long TotalBlocks, long FreeBlocks, long AvailableBlocks, long TotalFiles, long FreeFiles);

public enum SftpStatus { Ok = 0, Eof = 1, NoSuchFile = 2, PermissionDenied = 3, Failure = 4, BadMessage = 5, OpUnsupported = 8 }

public sealed class SftpException(SftpStatus status, string? message = null) : Exception(message ?? status.ToString())
{
    public SftpStatus Status { get; } = status;
}

// ---------------------------------------------------------------------------
// Built-in building blocks (LocalFileSystem: see LocalFileSystem.cs)
// ---------------------------------------------------------------------------

/// <summary>Several file systems under mount points: "/" = home, "/shared" = team folder, "/backup" = read-only.</summary>
public sealed class MountFileSystem
{
    public MountFileSystem Mount(string mountPoint, ISftpFileSystem fileSystem) => this;
    public ISftpFileSystem Build() => throw new NotImplementedException();
}
