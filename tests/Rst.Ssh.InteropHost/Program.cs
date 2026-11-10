// Test host for interop tests against OpenSSH: starts a server with an exec handler and SFTP.
//   dotnet run -- <port> <data-directory> [debug]
using System.Text;
using Microsoft.Extensions.Logging;
using Rst.Ssh;
using Rst.Ssh.Sftp;

var port = args.Length > 0 ? int.Parse(args[0]) : 2222;
var dataDir = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "rstssh-interop");
var level = args.Contains("debug") ? LogLevel.Debug : LogLevel.Information;
Directory.CreateDirectory(dataDir);

using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss.fff "; }).SetMinimumLevel(level));

var keyFile = Path.Combine(dataDir, "..", "interop_host_key.pem");
var hostKey = File.Exists(keyFile) ? HostKey.Load(keyFile) : HostKey.GenerateEcdsa();
if (!File.Exists(keyFile)) hostKey.Save(keyFile);
var rsaFile = Path.Combine(dataDir, "..", "interop_host_rsa.pem");
var rsaKey = File.Exists(rsaFile) ? HostKey.Load(rsaFile) : HostKey.GenerateRsa();
if (!File.Exists(rsaFile)) rsaKey.Save(rsaFile);

var users = new Dictionary<string, string> { ["demo"] = "demo", ["test"] = "test123" };

// Authorized public keys (OpenSSH authorized_keys format: "<type> <base64 blob> [comment]").
var authorizedKeysFile = Path.Combine(dataDir, "..", "authorized_keys");
var authorizedBlobs = new HashSet<string>(StringComparer.Ordinal);
if (File.Exists(authorizedKeysFile))
    foreach (var line in File.ReadAllLines(authorizedKeysFile))
    {
        var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (fields.Length >= 2) authorizedBlobs.Add(fields[1]);   // the base64 key blob
    }

var builder = SshServer.CreateBuilder()
    .Listen(port)
    .Configure(o =>
    {
        o.HostKeys.Add(hostKey);
        o.HostKeys.Add(rsaKey);
        o.Logger = loggerFactory.CreateLogger("rstssh");
        o.FailedAuthenticationDelay = TimeSpan.FromMilliseconds(50);
        if (Environment.GetEnvironmentVariable("REKEY_BYTES") is { } rk) o.RekeyAfterBytes = long.Parse(rk);
    })
    .UsePasswordAuthentication((u, p) => users.TryGetValue(u, out var pw) && pw == p)
    .UsePublicKeyAuthentication((user, key) => authorizedBlobs.Contains(Convert.ToBase64String(key.Blob.Span)))
    .UseExecHandler(new TestExec());

if (Environment.GetEnvironmentVariable("NO_SFTP") is null)
    builder.AddSftp(sftp => sftp.FileSystemFactory = s =>
        ValueTask.FromResult<ISftpFileSystem>(new LocalFileSystem(Path.Combine(dataDir, s.User!.Identity!.Name!), new() { CreateRootIfMissing = true })));

await using var server = builder.Build();
await server.StartAsync();
Console.WriteLine($"READY {server.LocalEndPoints[0]}");
await Task.Delay(Timeout.Infinite);

sealed class TestExec : ISshExecHandler
{
    public async Task<int> ExecuteAsync(ISshChannel channel, string command, CancellationToken ct)
    {
        var parts = command.Split(' ', 2);
        switch (parts[0])
        {
            case "echo":
                await channel.Stream.WriteAsync(Encoding.UTF8.GetBytes((parts.Length > 1 ? parts[1] : "") + "\n"), ct);
                return 0;
            case "cat":          // echoes stdin back – tests flow control in both directions
                await channel.Stream.CopyToAsync(channel.Stream, 64 * 1024, ct);
                return 0;
            case "count":        // counts stdin bytes
                long total = 0; var buf = new byte[65536]; int n;
                while ((n = await channel.Stream.ReadAsync(buf, ct)) > 0) total += n;
                await channel.Stream.WriteAsync(Encoding.UTF8.GetBytes(total + "\n"), ct);
                return 0;
            case "big":          // sends N MB
                var mb = int.Parse(parts[1]); var block = new byte[1024 * 1024];
                for (var i = 0; i < mb; i++) await channel.Stream.WriteAsync(block, ct);
                return 0;
            case "whoami":
                await channel.Stream.WriteAsync(Encoding.UTF8.GetBytes(channel.Session.User!.Identity!.Name + " " + channel.Session.Algorithms + "\n"), ct);
                return 0;
            case "exit":
                return int.Parse(parts[1]);
            default:
                await channel.Stream.WriteAsync(Encoding.UTF8.GetBytes($"unknown: {command}\n"), ct);
                return 127;
        }
    }
}
