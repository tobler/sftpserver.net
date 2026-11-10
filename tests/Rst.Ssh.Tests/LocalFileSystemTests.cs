using System.Text;
using Rst.Ssh.Sftp;
using Xunit;

namespace Rst.Ssh.Tests;

public sealed class LocalFileSystemTests : IDisposable
{
    private readonly string _base = Path.Combine(Path.GetTempPath(), "rstssh-tests-" + Guid.NewGuid().ToString("N"));
    private readonly string _root;
    private readonly string _outside;
    private static readonly CancellationToken Ct = CancellationToken.None;

    public LocalFileSystemTests()
    {
        _root = Path.Combine(_base, "root");
        _outside = Path.Combine(_base, "outside");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "secret.txt"), "secret");
    }

    public void Dispose()
    {
        try { Directory.Delete(_base, recursive: true); } catch { /* ignore */ }
    }

    private LocalFileSystem Fs(LocalFileSystemOptions? o = null) => new(_root, o);
    private static SftpPath P(string path) => SftpPath.Parse(path);

    private static async Task<SftpStatus> StatusOf(Func<Task> action)
    {
        var ex = await Assert.ThrowsAsync<SftpException>(action);
        return ex.Status;
    }

    private static async Task WriteAll(ISftpFileSystem fs, string path, string content, SftpOpenMode mode = SftpOpenMode.Write | SftpOpenMode.Create | SftpOpenMode.Truncate)
    {
        await using var h = await fs.OpenFileAsync(P(path), mode, null, Ct);
        await h.WriteAsync(0, Encoding.UTF8.GetBytes(content), Ct);
    }

    private static async Task<string> ReadAll(ISftpFileSystem fs, string path)
    {
        await using var h = await fs.OpenFileAsync(P(path), SftpOpenMode.Read, null, Ct);
        var result = new MemoryStream();
        var buffer = new byte[7];                                  // deliberately small: multiple reads
        long offset = 0;
        int n;
        while ((n = await h.ReadAsync(offset, buffer, Ct)) > 0) { result.Write(buffer, 0, n); offset += n; }
        return Encoding.UTF8.GetString(result.ToArray());
    }

    // ------------------------------------------------------------------ SftpPath

    [Theory]
    [InlineData("/a/./b//c/../d", "/a/b/d")]
    [InlineData("../../etc/passwd", "/etc/passwd")]
    [InlineData("/../../..", "/")]
    [InlineData("", "/")]
    [InlineData("x/y", "/home/x/y")]
    public void SftpPath_normalizes_and_stays_inside_root(string input, string expected)
    {
        var relativeTo = input == "x/y" ? SftpPath.Parse("/home") : SftpPath.Root;
        Assert.Equal(expected, SftpPath.Parse(input, relativeTo).Value);
    }

    [Fact]
    public void SftpPath_Parent_Name_Combine()
    {
        var p = SftpPath.Parse("/a/b/c.txt");
        Assert.Equal("c.txt", p.Name);
        Assert.Equal("/a/b", p.Parent.Value);
        Assert.Equal("/", SftpPath.Root.Parent.Value);
        Assert.Equal("/a/b/c.txt/d", p.Combine("d").Value);
        Assert.Throws<ArgumentException>(() => p.Combine(".."));
        Assert.Throws<ArgumentException>(() => p.Combine("x/y"));
        Assert.Equal(default, SftpPath.Root);
    }

    // ------------------------------------------------------------------ Read / write

    [Fact]
    public async Task Write_and_read()
    {
        var fs = Fs();
        await WriteAll(fs, "/hello.txt", "Hello SFTP world, more than seven bytes!");
        Assert.Equal("Hello SFTP world, more than seven bytes!", await ReadAll(fs, "/hello.txt"));
    }

    [Fact]
    public async Task Out_of_order_writes_produce_correct_file()
    {
        var fs = Fs();
        await using (var h = await fs.OpenFileAsync(P("/x.bin"), SftpOpenMode.Write | SftpOpenMode.Create, null, Ct))
        {
            // Like pipelining clients: the second block arrives first, written in parallel.
            await Task.WhenAll(
                h.WriteAsync(5, "WORLD"u8.ToArray(), Ct).AsTask(),
                h.WriteAsync(0, "HELLO"u8.ToArray(), Ct).AsTask());
        }
        Assert.Equal("HELLOWORLD", await ReadAll(fs, "/x.bin"));
    }

    [Fact]
    public async Task Append_ignores_the_offset()
    {
        var fs = Fs();
        await WriteAll(fs, "/log.txt", "one");
        await using (var h = await fs.OpenFileAsync(P("/log.txt"), SftpOpenMode.Write | SftpOpenMode.Append, null, Ct))
            await h.WriteAsync(0, "two"u8.ToArray(), Ct);
        Assert.Equal("onetwo", await ReadAll(fs, "/log.txt"));
    }

    [Fact]
    public async Task Exclusive_create_fails_if_file_exists()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "x");
        Assert.Equal(SftpStatus.Failure, await StatusOf(() =>
            fs.OpenFileAsync(P("/a.txt"), SftpOpenMode.Write | SftpOpenMode.Create | SftpOpenMode.Exclusive, null, Ct).AsTask()));
    }

    [Fact]
    public async Task Missing_file_returns_NoSuchFile()
    {
        var fs = Fs();
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.OpenFileAsync(P("/doesnotexist"), SftpOpenMode.Read, null, Ct).AsTask()));
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.OpenFileAsync(P("/missing/new.txt"), SftpOpenMode.Write | SftpOpenMode.Create, null, Ct).AsTask()));
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.GetAttributesAsync(P("/doesnotexist"), true, Ct).AsTask()));
    }

    [Fact]
    public async Task Opening_directory_as_file_fails()
    {
        var fs = Fs();
        await fs.CreateDirectoryAsync(P("/d"), null, Ct);
        Assert.Equal(SftpStatus.Failure, await StatusOf(() => fs.OpenFileAsync(P("/d"), SftpOpenMode.Read, null, Ct).AsTask()));
    }

    [Fact]
    public async Task Handle_keeps_working_after_rename()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "12345");
        await using var h = await fs.OpenFileAsync(P("/a.txt"), SftpOpenMode.Read, null, Ct);
        await fs.RenameAsync(P("/a.txt"), P("/b.txt"), false, Ct);
        Assert.Equal(5, (await h.GetAttributesAsync(Ct)).Size);
    }

    // ------------------------------------------------------------------ Attributes

    [Fact]
    public async Task Attributes_size_type_time()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "12345");
        var a = await fs.GetAttributesAsync(P("/a.txt"), true, Ct);
        Assert.Equal(SftpFileType.Regular, a.Type);
        Assert.Equal(5, a.Size);

        var t = new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero);
        await fs.SetAttributesAsync(P("/a.txt"), new SftpAttributes { Size = 2, LastWriteTime = t }, Ct);
        a = await fs.GetAttributesAsync(P("/a.txt"), true, Ct);
        Assert.Equal(2, a.Size);
        Assert.Equal(t, a.LastWriteTime);

        Assert.Equal(SftpFileType.Directory, (await fs.GetAttributesAsync(SftpPath.Root, true, Ct)).Type);
    }

    [Fact]
    public async Task Permissions_on_create_and_no_setuid()
    {
        if (OperatingSystem.IsWindows()) return;
        var fs = Fs();
        var mode0600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (await fs.OpenFileAsync(P("/p.txt"), SftpOpenMode.Write | SftpOpenMode.Create, new SftpAttributes { Permissions = mode0600 }, Ct)) { }
        Assert.Equal(mode0600, File.GetUnixFileMode(Path.Combine(_root, "p.txt")));

        await fs.SetAttributesAsync(P("/p.txt"), new SftpAttributes { Permissions = mode0600 | UnixFileMode.SetUser | UnixFileMode.UserExecute }, Ct);
        var actual = File.GetUnixFileMode(Path.Combine(_root, "p.txt"));
        Assert.False(actual.HasFlag(UnixFileMode.SetUser));
        Assert.True(actual.HasFlag(UnixFileMode.UserExecute));
    }

    [Fact]
    public async Task Changing_owner_is_rejected()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "x");
        Assert.Equal(SftpStatus.OpUnsupported, await StatusOf(() => fs.SetAttributesAsync(P("/a.txt"), new SftpAttributes { Uid = 0 }, Ct).AsTask()));
    }

    // ------------------------------------------------------------------ Directories

    [Fact]
    public async Task Listing_includes_dotfiles_and_types()
    {
        var fs = Fs();
        await WriteAll(fs, "/.hidden", "x");
        await WriteAll(fs, "/file.txt", "123");
        await fs.CreateDirectoryAsync(P("/folder"), null, Ct);

        var entries = new Dictionary<string, SftpAttributes>();
        await foreach (var e in fs.EnumerateDirectoryAsync(SftpPath.Root, Ct)) entries[e.Name] = e.Attributes;

        Assert.Equal(new[] { ".hidden", "file.txt", "folder" }, entries.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(SftpFileType.Directory, entries["folder"].Type);
        Assert.Equal(3, entries["file.txt"].Size);
    }

    [Fact]
    public async Task Listing_a_file_fails()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "x");
        Assert.Equal(SftpStatus.Failure, await StatusOf(async () => { await foreach (var _ in fs.EnumerateDirectoryAsync(P("/a.txt"), Ct)) { } }));
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(async () => { await foreach (var _ in fs.EnumerateDirectoryAsync(P("/missing"), Ct)) { } }));
    }

    [Fact]
    public async Task Mkdir_is_not_mkdir_p_and_not_twice()
    {
        var fs = Fs();
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.CreateDirectoryAsync(P("/a/b"), null, Ct).AsTask()));
        await fs.CreateDirectoryAsync(P("/a"), null, Ct);
        Assert.Equal(SftpStatus.Failure, await StatusOf(() => fs.CreateDirectoryAsync(P("/a"), null, Ct).AsTask()));
    }

    [Fact]
    public async Task Rmdir_only_empty_and_never_root()
    {
        var fs = Fs();
        await fs.CreateDirectoryAsync(P("/d"), null, Ct);
        await WriteAll(fs, "/d/.x", "x");                         // a hidden file counts too
        Assert.Equal(SftpStatus.Failure, await StatusOf(() => fs.DeleteDirectoryAsync(P("/d"), Ct).AsTask()));
        await fs.DeleteFileAsync(P("/d/.x"), Ct);
        await fs.DeleteDirectoryAsync(P("/d"), Ct);
        Assert.False(Directory.Exists(Path.Combine(_root, "d")));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.DeleteDirectoryAsync(SftpPath.Root, Ct).AsTask()));
    }

    [Fact]
    public async Task Remove_semantics()
    {
        var fs = Fs();
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.DeleteFileAsync(P("/missing"), Ct).AsTask()));
        await fs.CreateDirectoryAsync(P("/d"), null, Ct);
        Assert.Equal(SftpStatus.Failure, await StatusOf(() => fs.DeleteFileAsync(P("/d"), Ct).AsTask()));
    }

    [Fact]
    public async Task Rename_without_and_with_overwrite()
    {
        var fs = Fs();
        await WriteAll(fs, "/a.txt", "A");
        await WriteAll(fs, "/b.txt", "B");
        Assert.Equal(SftpStatus.Failure, await StatusOf(() => fs.RenameAsync(P("/a.txt"), P("/b.txt"), false, Ct).AsTask()));
        await fs.RenameAsync(P("/a.txt"), P("/b.txt"), overwrite: true, Ct);
        Assert.Equal("A", await ReadAll(fs, "/b.txt"));
        Assert.False(File.Exists(Path.Combine(_root, "a.txt")));

        await fs.CreateDirectoryAsync(P("/d"), null, Ct);
        await fs.RenameAsync(P("/d"), P("/e"), false, Ct);
        Assert.True(Directory.Exists(Path.Combine(_root, "e")));
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.RenameAsync(P("/missing"), P("/x"), false, Ct).AsTask()));
    }

    // ------------------------------------------------------------------ Security

    [Fact]
    public async Task Path_traversal_stays_inside_root()
    {
        var fs = Fs();
        var path = SftpPath.Parse("../../outside/secret.txt");      // ends up as /outside/secret.txt inside the root
        Assert.Equal(SftpStatus.NoSuchFile, await StatusOf(() => fs.OpenFileAsync(path, SftpOpenMode.Read, null, Ct).AsTask()));
    }

    [Fact]
    public async Task ReadOnly_forbids_every_change()
    {
        await WriteAll(Fs(), "/a.txt", "x");
        var fs = Fs(new() { ReadOnly = true });
        Assert.Equal("x", await ReadAll(fs, "/a.txt"));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.OpenFileAsync(P("/a.txt"), SftpOpenMode.Write, null, Ct).AsTask()));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.DeleteFileAsync(P("/a.txt"), Ct).AsTask()));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.CreateDirectoryAsync(P("/d"), null, Ct).AsTask()));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.RenameAsync(P("/a.txt"), P("/b.txt"), false, Ct).AsTask()));
        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.SetAttributesAsync(P("/a.txt"), new SftpAttributes { Size = 0 }, Ct).AsTask()));
    }

    [Fact]
    public async Task Symlink_pointing_outside_is_always_blocked()
    {
        File.CreateSymbolicLink(Path.Combine(_root, "link.txt"), Path.Combine(_outside, "secret.txt"));
        Directory.CreateSymbolicLink(Path.Combine(_root, "linkdir"), _outside);

        foreach (var policy in new[] { SymlinkPolicy.Deny, SymlinkPolicy.AllowWithinRoot })
        {
            var fs = Fs(new() { Symlinks = policy });
            Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.OpenFileAsync(P("/link.txt"), SftpOpenMode.Read, null, Ct).AsTask()));
            Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.OpenFileAsync(P("/linkdir/secret.txt"), SftpOpenMode.Read, null, Ct).AsTask()));
            Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => fs.OpenFileAsync(P("/linkdir/new.txt"), SftpOpenMode.Write | SftpOpenMode.Create, null, Ct).AsTask()));
            Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(async () => { await foreach (var _ in fs.EnumerateDirectoryAsync(P("/linkdir"), Ct)) { } }));
        }
        Assert.False(File.Exists(Path.Combine(_outside, "new.txt")));
    }

    [Fact]
    public async Task Symlink_inside_root_only_with_AllowWithinRoot()
    {
        await WriteAll(Fs(), "/target.txt", "inside");
        File.CreateSymbolicLink(Path.Combine(_root, "short.txt"), Path.Combine(_root, "target.txt"));

        Assert.Equal(SftpStatus.PermissionDenied, await StatusOf(() => ReadAll(Fs(), "/short.txt")));
        Assert.Equal("inside", await ReadAll(Fs(new() { Symlinks = SymlinkPolicy.AllowWithinRoot }), "/short.txt"));
    }

    [Fact]
    public async Task Link_itself_visible_and_deletable_target_remains()
    {
        File.CreateSymbolicLink(Path.Combine(_root, "link.txt"), Path.Combine(_outside, "secret.txt"));
        var fs = Fs();

        Assert.Equal(SftpFileType.SymbolicLink, (await fs.GetAttributesAsync(P("/link.txt"), followLinks: false, Ct)).Type);

        var listed = new List<SftpDirectoryEntry>();
        await foreach (var e in fs.EnumerateDirectoryAsync(SftpPath.Root, Ct)) listed.Add(e);
        Assert.Equal(SftpFileType.SymbolicLink, listed.Single(e => e.Name == "link.txt").Attributes.Type);

        await fs.DeleteFileAsync(P("/link.txt"), Ct);
        Assert.False(File.Exists(Path.Combine(_root, "link.txt")));
        Assert.True(File.Exists(Path.Combine(_outside, "secret.txt")));
    }

    [Fact]
    public async Task Root_itself_may_be_a_link()
    {
        var linkedRoot = Path.Combine(_base, "rootlink");
        Directory.CreateSymbolicLink(linkedRoot, _root);
        var fs = new LocalFileSystem(linkedRoot);
        await WriteAll(fs, "/a.txt", "ok");
        Assert.Equal("ok", await ReadAll(fs, "/a.txt"));
    }

    [Theory]
    [InlineData("normal.txt", true)]
    [InlineData("..\\..\\boot.ini", false)]
    [InlineData("file.txt:stream", false)]
    [InlineData("C:", false)]
    [InlineData("CON", false)]
    [InlineData("nul.txt", false)]
    [InlineData("com1", false)]
    [InlineData("console.txt", true)]
    [InlineData("ends-with-dot.", false)]
    [InlineData("ends-with-space ", false)]
    [InlineData("question?", false)]
    public void Windows_file_names_are_validated(string segment, bool valid)
    {
        Assert.Equal(valid, LocalFileSystem.IsValidSegment(segment, windows: true));
    }

    [Fact]
    public void On_Linux_backslash_and_colon_are_normal_characters()
    {
        Assert.True(LocalFileSystem.IsValidSegment("a\\b:c", windows: false));
        Assert.False(LocalFileSystem.IsValidSegment("..", windows: false));
    }

    [Fact]
    public async Task Statistics_return_values()
    {
        var stats = await Fs().GetStatsAsync(SftpPath.Root, Ct);
        Assert.True(stats.TotalBlocks > 0);
        Assert.True(stats.AvailableBlocks <= stats.TotalBlocks);
    }

    [Fact]
    public void Missing_root_only_with_CreateRootIfMissing()
    {
        var missing = Path.Combine(_base, "new", "user1");
        Assert.Throws<DirectoryNotFoundException>(() => new LocalFileSystem(missing));
        _ = new LocalFileSystem(missing, new() { CreateRootIfMissing = true });
        Assert.True(Directory.Exists(missing));
    }
}
