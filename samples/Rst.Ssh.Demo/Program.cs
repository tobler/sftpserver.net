// ============================================================================
//  Rst.Ssh demo – SFTP server on the local file system
//
//  Start:   dotnet run --project samples/Rst.Ssh.Demo
//  Try it:  sftp -P 2222 demo@localhost      (password: demo)
//           or WinSCP / FileZilla: SFTP, localhost, port 2222
// ============================================================================
using System.Net;
using Rst.Ssh;
using Rst.Ssh.Sftp;

// --- Configuration ------------------------------------------------------------

const int Port = 2222;
var dataRoot = Path.Combine(AppContext.BaseDirectory, "sftp-data");   // one subfolder per user
var hostKeyFile = Path.Combine(AppContext.BaseDirectory, "ssh_host_ecdsa_key.pem");

// Users simply kept in a variable (in real life: database, LDAP, API …)
var users = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["demo"] = "demo",
    ["alice"] = "secret123",
    ["guest"] = "guest",
};
var readOnlyUsers = new HashSet<string> { "guest" };

// Generate and persist the host key on first start – otherwise every client warns after each restart.
var hostKey = File.Exists(hostKeyFile) ? HostKey.Load(hostKeyFile) : HostKey.GenerateEcdsa();
if (!File.Exists(hostKeyFile)) hostKey.Save(hostKeyFile);

// --- Server -------------------------------------------------------------------

var server = SshServer.CreateBuilder()
    .Listen(new IPEndPoint(IPAddress.Any, Port))
    .Configure(o =>
    {
        o.HostKeys.Add(hostKey);

        o.Events.OnConnecting = ctx =>
        {
            Log($"Connection from {ctx.RemoteEndPoint}");
            return ValueTask.CompletedTask;
        };
        o.Events.OnConnected = session =>
        {
            Log($"[{session.Id}] Handshake ok, client: {session.ClientVersion}, cipher: {session.Algorithms?.EncryptionCs}");
            return ValueTask.CompletedTask;
        };
        o.Events.OnAuthenticationFailed = f =>
        {
            Log($"[{f.Session.Id}] Login failed: '{f.UserName}' ({f.Method}, attempt {f.Attempt})");
            return ValueTask.CompletedTask;
        };
        o.Events.OnDisconnected = d =>
        {
            Log($"[{d.Session.Id}] Disconnected ({d.Initiator}) after {d.Duration:hh\\:mm\\:ss}, " +
                $"received {d.BytesReceived:N0} / sent {d.BytesSent:N0} bytes");
            return ValueTask.CompletedTask;
        };
    })

    // Authentication: the application checks user name/password and returns true/false.
    .UsePasswordAuthentication((userName, password) =>
    {
        var ok = users.TryGetValue(userName, out var expected) && expected == password;
        Log(ok ? $"Login ok: {userName}" : $"Login rejected: {userName}");
        return ok;
    })

    .AddSftp(sftp =>
    {
        // Every user ends up in their own folder and cannot get out of it.
        sftp.FileSystemFactory = session =>
        {
            var userName = session.User!.Identity!.Name!;
            ISftpFileSystem fs = new LocalFileSystem(
                Path.Combine(dataRoot, userName),
                new LocalFileSystemOptions
                {
                    CreateRootIfMissing = true,
                    ReadOnly = readOnlyUsers.Contains(userName),
                });
            return ValueTask.FromResult(fs);
        };

        sftp.Events.OnSessionStarted = s =>
        {
            Log($"[{s.Session.Id}] SFTP started for {s.User.Identity!.Name}");
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnDirectoryListed = e =>
        {
            Log($"[{e.Session.Id}] ls {e.Path} ({e.EntryCount} entries)");
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnDownloadStarting = e =>
        {
            Log($"[{e.Session.Id}] Download starting: {e.Path} ({e.ExistingSize:N0} bytes)");
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnDownloadCompleted = e =>
        {
            Log($"[{e.Session.Id}] Download {(e.Aborted ? "ABORTED" : "completed")}: {e.Path}, {e.BytesTransferred:N0} bytes in {e.Duration.TotalSeconds:F1} s");
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnUploadStarting = e =>
        {
            // Example of a rule: do not accept executables.
            if (e.Path.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                e.Deny(SftpStatus.PermissionDenied, "EXE files are not allowed");
                Log($"[{e.Session.Id}] Upload rejected: {e.Path}");
            }
            else
            {
                Log($"[{e.Session.Id}] Upload starting: {e.Path}");
            }
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnUploadCompleted = e =>
        {
            Log($"[{e.Session.Id}] Upload {(e.Aborted ? "ABORTED" : "completed")}: {e.Path}, {e.BytesTransferred:N0} bytes");
            return ValueTask.CompletedTask;
        };
        sftp.Events.OnDeleted = e => { Log($"[{e.Session.Id}] Deleted: {e.Path}"); return ValueTask.CompletedTask; };
        sftp.Events.OnRenamed = e => { Log($"[{e.Session.Id}] Renamed: {e.Path} -> {e.TargetPath}"); return ValueTask.CompletedTask; };
    })
    .Build();

await server.StartAsync();

Log($"SFTP server listening on port {Port}, data in {dataRoot}");
Log($"Host key: {hostKey.Fingerprint}");
Log($"Users: {string.Join(", ", users.Keys)}   –   press Ctrl+C to stop");

var stop = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.TrySetResult(); };
await stop.Task;

Log("Shutting down …");
await server.StopAsync();

// --- Helpers ------------------------------------------------------------------

static void Log(string message) => Console.WriteLine($"{DateTime.Now:HH:mm:ss} {message}");
