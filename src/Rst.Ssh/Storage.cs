// ============================================================================
//  Rst.Ssh.Sftp.Storage – compose a file system from "metadata + blob storage"
//
//  Two extension points:
//    1) ISftpFileSystem (Sftp.cs)  – full control, implement everything yourself
//    2) IFileMetadataStore + IBlobStore (here) – for the common case
//       "directory tree in a database, contents in S3 / IPFS / Azure Blob / …".
//       The library builds an ISftpFileSystem from these and handles the hard parts:
//       upload spooling, out-of-order writes, read-ahead, commit on close, blob release.
// ============================================================================
using System.Net.Http.Json;
using System.Runtime.CompilerServices;

namespace Rst.Ssh.Sftp.Storage;

// ---------------------------------------------------------------------------
// Metadata: the source of "ls", "stat", rename, mkdir (e.g. an SQL database)
// ---------------------------------------------------------------------------

public sealed record FileEntry(
    SftpPath Path,
    SftpFileType Type,
    long Size,
    DateTimeOffset LastWriteTime,
    string? BlobId,                                                  // IPFS CID, S3 key, … (null for directories)
    UnixFileMode? Permissions = null);

public interface IFileMetadataStore
{
    ValueTask<FileEntry?> GetAsync(SftpPath path, CancellationToken ct);

    /// <summary>Streamed (keyset paging in the database) – directories with 100,000 entries must not be loaded into memory.</summary>
    IAsyncEnumerable<FileEntry> ListAsync(SftpPath directory, CancellationToken ct);

    ValueTask CreateDirectoryAsync(SftpPath path, CancellationToken ct);
    ValueTask DeleteDirectoryAsync(SftpPath path, CancellationToken ct);            // only if empty -> otherwise SftpException(Failure)

    /// <summary>
    /// Called when an upload is closed, AFTER the blob has been stored.
    /// Creates or replaces the entry. Returns the BlobId of the replaced content (or null)
    /// so the library can release it according to the BlobReleasePolicy.
    /// </summary>
    ValueTask<string?> CommitFileAsync(SftpPath path, BlobInfo blob, CancellationToken ct);

    /// <summary>Returns the deleted entry (used for blob release).</summary>
    ValueTask<FileEntry> DeleteFileAsync(SftpPath path, CancellationToken ct);

    /// <summary>Pure database operation – cheap and atomic even for whole directory trees.</summary>
    ValueTask MoveAsync(SftpPath from, SftpPath to, bool overwrite, CancellationToken ct);

    /// <summary>For deduplication: the same blob can be referenced by several paths.</summary>
    ValueTask<bool> IsBlobReferencedAsync(string blobId, CancellationToken ct);
}

// ---------------------------------------------------------------------------
// Contents: immutable blobs (IPFS is content-addressed -> a perfect fit)
// ---------------------------------------------------------------------------

public sealed record BlobInfo(string BlobId, long Size, IReadOnlyDictionary<string, string>? Properties = null);

public sealed record BlobPutContext(SftpPath Path, ISshSession Session, long? ExpectedSize);

public interface IBlobStore
{
    /// <summary>Stores complete content and returns its ID (for IPFS: the CID).</summary>
    ValueTask<BlobInfo> PutAsync(Stream content, BlobPutContext context, CancellationToken ct);

    /// <summary>
    /// Opens a read stream at the given offset. The library keeps it open per handle and
    /// reuses it for consecutive SFTP reads – it is only reopened after a seek.
    /// (Otherwise every 32 KB read from a client would become its own HTTP request to Kubo.)
    /// </summary>
    ValueTask<Stream> OpenReadAsync(string blobId, long offset, CancellationToken ct);

    /// <summary>Content is no longer referenced (unpin, delete …). Only called depending on the policy.</summary>
    ValueTask ReleaseAsync(string blobId, CancellationToken ct) => ValueTask.CompletedTask;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

public enum BlobReleasePolicy
{
    Never,               // nothing is ever released (e.g. content that must stay pinned permanently)
    WhenUnreferenced,    // ReleaseAsync as soon as no path references the blob any more
}

public enum UploadMode
{
    /// <summary>Upload into a temp file, then a single PutAsync on close. Robust, supports any write order.</summary>
    Spool,
    /// <summary>Pipe directly into PutAsync while writes arrive without gaps (the normal case); small reorder window,
    /// automatically falls back to Spool on larger jumps. Saves disk I/O for large files.</summary>
    StreamWhenSequential,
}

public sealed class MetadataBlobFileSystemOptions
{
    public UploadMode UploadMode { get; set; } = UploadMode.Spool;
    public string SpoolDirectory { get; set; } = Path.GetTempPath();
    public long MaxUploadSize { get; set; } = 10L * 1024 * 1024 * 1024;
    public int ReorderWindowBytes { get; set; } = 8 * 1024 * 1024;
    public int ReadAheadBytes { get; set; } = 1024 * 1024;
    public BlobReleasePolicy ReleasePolicy { get; set; } = BlobReleasePolicy.Never;

    /// <summary>
    /// Immutable blobs cannot be modified "in the middle". Append/resume means:
    /// copy the old content into the spool and store it again. Can be disabled for very large files.
    /// </summary>
    public bool AllowAppendByCopy { get; set; } = true;
}

/// <summary>Ready-made ISftpFileSystem built from a metadata store and a blob store.</summary>
public sealed class MetadataBlobFileSystem(
    IFileMetadataStore metadata,
    IBlobStore blobs,
    MetadataBlobFileSystemOptions? options = null) : ISftpFileSystem
{
    // Upload flow:
    //   OPEN(Create|Truncate)  -> only create the handle, nothing in the database yet (file is invisible to "ls")
    //   WRITE(offset, data)*   -> spool / reorder buffer
    //   CLOSE                  -> blobs.PutAsync(...)  => CID
    //                          -> metadata.CommitFileAsync(path, blob) => previous CID, if any
    //                          -> apply the release policy to the previous CID
    //                          -> Events.OnUploadCompleted(ContentId = CID)
    //   Abort (disconnect)     -> delete the spool, nothing is committed
    // WinSCP & co. upload to "file.filepart" and rename afterwards -> MoveAsync, a pure database operation.

    public SftpCapabilities Capabilities => SftpCapabilities.AtomicRename;
    public ValueTask<SftpAttributes> GetAttributesAsync(SftpPath path, bool followLinks, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask SetAttributesAsync(SftpPath path, SftpAttributes attributes, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask<ISftpFileHandle> OpenFileAsync(SftpPath path, SftpOpenMode mode, SftpAttributes? createAttributes, CancellationToken ct) => throw new NotImplementedException();
    public IAsyncEnumerable<SftpDirectoryEntry> EnumerateDirectoryAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask CreateDirectoryAsync(SftpPath path, SftpAttributes? attributes, CancellationToken ct) => metadata.CreateDirectoryAsync(path, ct);
    public ValueTask DeleteDirectoryAsync(SftpPath path, CancellationToken ct) => metadata.DeleteDirectoryAsync(path, ct);
    public ValueTask DeleteFileAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask RenameAsync(SftpPath from, SftpPath to, bool overwrite, CancellationToken ct) => metadata.MoveAsync(from, to, overwrite, ct);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

// ============================================================================
//  Example adapters (these do NOT belong in the library but in the consuming project)
// ============================================================================

/// <summary>IPFS via the Kubo RPC API (internal access only, never the public gateway).</summary>
public sealed class KuboBlobStore(HttpClient kubo) : IBlobStore    // BaseAddress e.g. http://127.0.0.1:5001/
{
    public async ValueTask<BlobInfo> PutAsync(Stream content, BlobPutContext context, CancellationToken ct)
    {
        // POST /api/v0/add?cid-version=1&raw-leaves=true&pin=true   (multipart, file streamed)
        using var form = new MultipartFormDataContent { { new StreamContent(content), "file", context.Path.Name } };
        using var resp = await kubo.PostAsync("api/v0/add?cid-version=1&raw-leaves=true&pin=true&quieter=true", form, ct);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadFromJsonAsync<AddResponse>(ct);
        return new BlobInfo(json!.Hash, long.Parse(json.Size));
    }

    public async ValueTask<Stream> OpenReadAsync(string cid, long offset, CancellationToken ct)
    {
        // POST /api/v0/cat?arg=<cid>&offset=<n>  – response as a stream, no buffering
        var req = new HttpRequestMessage(HttpMethod.Post, $"api/v0/cat?arg={Uri.EscapeDataString(cid)}&offset={offset}");
        var resp = await kubo.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStreamAsync(ct);
    }

    // ReleaseAsync is intentionally not overridden: with BlobReleasePolicy.Never nothing is ever unpinned.

    sealed record AddResponse(string Name, string Hash, string Size);
}

/// <summary>Directory tree from the database – schema sketch, implement with Dapper/EF.</summary>
public sealed class DatabaseMetadataStore(string connectionString, Guid tenantId) : IFileMetadataStore
{
    // CREATE TABLE sftp_entries (
    //   tenant_id   uuid        NOT NULL,
    //   parent_path text        NOT NULL,          -- "/images"
    //   name        text        NOT NULL,          -- "1.png"
    //   is_dir      boolean     NOT NULL,
    //   size        bigint      NOT NULL DEFAULT 0,
    //   cid         text        NULL,
    //   modified    timestamptz NOT NULL,
    //   PRIMARY KEY (tenant_id, parent_path, name)  -- = index for listing with keyset paging
    // );
    // CREATE INDEX ON sftp_entries (cid);          -- for IsBlobReferencedAsync
    //
    // Note on moving directories: rewrite every parent_path with that prefix (a single UPDATE statement)
    // – or model the tree via parent_id instead of paths, then a move is a single row.

    public ValueTask<FileEntry?> GetAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();

    public async IAsyncEnumerable<FileEntry> ListAsync(SftpPath directory, [EnumeratorCancellation] CancellationToken ct)
    {
        // SELECT … WHERE tenant_id=@t AND parent_path=@p AND name > @last ORDER BY name LIMIT 1000   (repeat)
        await Task.CompletedTask;
        yield break;
    }

    public ValueTask CreateDirectoryAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask DeleteDirectoryAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask<string?> CommitFileAsync(SftpPath path, BlobInfo blob, CancellationToken ct) => throw new NotImplementedException(); // UPSERT … RETURNING old cid
    public ValueTask<FileEntry> DeleteFileAsync(SftpPath path, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask MoveAsync(SftpPath from, SftpPath to, bool overwrite, CancellationToken ct) => throw new NotImplementedException();
    public ValueTask<bool> IsBlobReferencedAsync(string blobId, CancellationToken ct) => throw new NotImplementedException();
}

// Wiring in the consuming project:
//
//   .AddSftp(sftp =>
//   {
//       sftp.FileSystemFactory = session => ValueTask.FromResult<ISftpFileSystem>(
//           new MetadataBlobFileSystem(
//               new DatabaseMetadataStore(connStr, TenantOf(session.User!)),
//               new KuboBlobStore(kuboHttpClient),
//               new() { UploadMode = UploadMode.StreamWhenSequential,
//                       SpoolDirectory = @"D:\sftp-spool",           // SSD, not the IPFS HDDs
//                       ReleasePolicy = BlobReleasePolicy.Never }));
//
//       sftp.Events.OnUploadCompleted = e => Notify(e.Path, e.ContentId);   // pass the CID straight on
//   })
