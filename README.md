# rstsftp – SSH / SFTP server library for .NET

A self-contained SSH-2 server with an SFTP subsystem, written from scratch in C# for .NET 8+.
No native libraries and no third-party crypto: it uses the .NET base class library where it provides
the primitive (AES, SHA-2, ECDH/ECDSA, RSA) and implements the rest from scratch (X25519, Ed25519,
ChaCha20/Poly1305, ML-KEM-768 and the SHA-3/SHAKE it needs). The only package dependency is
`Microsoft.Extensions.Logging.Abstractions`.

The goal is an embeddable component with a few lines of code to
host an SFTP server, with your own authentication and your own storage behind it.

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Minimal server](#minimal-server)
  - [Authentication](#authentication)
  - [Events](#events)
  - [Middleware](#middleware)
  - [File systems](#file-systems)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Performance](#performance)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Repository layout](#repository-layout)

---

## Features

| Area | Implemented |
|---|---|
| Transport | Binary packet protocol, strict KEX (Terrapin mitigation), client- and server-initiated rekey, packet size limits |
| Key exchange | `mlkem768x25519-sha256` (post-quantum hybrid, FIPS 203 / RFC 10042), `curve25519-sha256` (+ `@libssh.org`), `ecdh-sha2-nistp256/384/521` |
| Host keys | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-256`, `rsa-sha2-512` (PEM files) |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `aes128/192/256-ctr` |
| MACs | `hmac-sha2-256`, `hmac-sha2-512`, and their `-etm@openssh.com` variants |
| Authentication | Password and public-key (`ssh-ed25519`, `rsa-sha2-256/512`, `ecdsa-sha2-nistp256/384/521`) via callback or `ISshAuthenticator`, attempt limit, failure delay, login timeout, partial (multi-factor) results |
| Connection | Session channels with flow control in both directions, `subsystem`, optional `exec` |
| SFTP | Version 3 plus `posix-rename`, `statvfs`, `fsync` and `limits` (`@openssh.com`) |
| Extensibility | Connection events, SFTP events (with veto), ASP.NET-style middleware pipeline |
| Storage | `ISftpFileSystem` abstraction, `LocalFileSystem`, design for metadata + blob stores (e.g. IPFS) |

Tested against **OpenSSH 9.6** (`ssh` and `sftp`) on Linux with every combination of the algorithms above.

---

## Quick start

Requirements: .NET 8 SDK.

```bash
dotnet test                                   # unit tests
dotnet run --project samples/Rst.Ssh.Demo     # demo server on port 2222
```

Then connect with any SFTP client:

```bash
sftp -P 2222 demo@localhost                   # password: demo
```

Demo users (defined in a dictionary in `samples/Rst.Ssh.Demo/Program.cs`):

| User | Password | Access |
|---|---|---|
| `demo` | `demo` | read/write |
| `alice` | `secret123` | read/write |
| `guest` | `guest` | read-only |

Each user gets a private directory under `sftp-data/<user>` next to the demo binary and cannot leave it.
The demo prints every connection, login and file event to the console and rejects uploads of `.exe` files
to show how events can veto operations.

---

## Usage

### Minimal server

```csharp
using Rst.Ssh;
using Rst.Ssh.Sftp;

var hostKey = File.Exists("host_key.pem") ? HostKey.Load("host_key.pem") : HostKey.GenerateEcdsa();
hostKey.Save("host_key.pem");   // keep the key stable, otherwise clients warn after every restart

await using var server = SshServer.CreateBuilder()
    .Listen(2222)
    .Configure(o => o.HostKeys.Add(hostKey))
    .UsePasswordAuthentication((user, password) => user == "demo" && password == "demo")
    .AddSftp(sftp => sftp.FileSystemFactory = session =>
        ValueTask.FromResult<ISftpFileSystem>(
            new LocalFileSystem($"/srv/sftp/{session.User!.Identity!.Name}",
                                new LocalFileSystemOptions { CreateRootIfMissing = true })))
    .Build();

await server.StartAsync();
```

### Authentication

The library handles the protocol and the cryptography (signature checks, attempt counting, delays,
timeouts). Your application only answers *"is this allowed?"*.

```csharp
// Simple: return true or false
.UsePasswordAuthentication((user, password) => users.TryGetValue(user, out var pw) && pw == password)

// Async, with context (remote IP, client version, session) – e.g. for a database lookup
.UsePasswordAuthentication(async ctx => await db.CheckPasswordAsync(ctx.UserName, ctx.Password, ctx.RemoteEndPoint))

// Public key: the library verifies the signature, you only decide whether the key belongs to the user
.UsePublicKeyAuthentication((user, key) => authorizedKeys.Contains((user, key.Fingerprint)))

// Full control: implement ISshAuthenticator (methods per user, multi-factor via AuthResult.Partial, custom claims)
.UseAuthenticator(new MyAuthenticator())
```

For public-key auth the library validates the signature itself (`ssh-ed25519`, `rsa-sha2-256/512`,
`ecdsa-sha2-nistp256/384/521`); your callback receives the key's `Algorithm`, raw `Blob` and
SHA-256 `Fingerprint` and just decides whether that key is authorized for the user. Password and
public key can be offered together.

A successful login yields a `ClaimsPrincipal` (`session.User`) that you can use to pick the user's file system.

Relevant options: `MaxAuthenticationAttempts` (default 6), `FailedAuthenticationDelay` (500 ms),
`AuthenticationTimeout` (60 s).

### Events

Connection lifecycle (`SshServerOptions.Events`):

| Event | When |
|---|---|
| `OnConnecting` | TCP connection accepted, before the SSH handshake. Call `ctx.Reject()` to drop it (IP block lists, rate limits). |
| `OnConnected` | Handshake done; client version and negotiated algorithms are known. |
| `OnAuthenticated` | Login succeeded. |
| `OnAuthenticationFailed` | Every failed attempt (user name, method, attempt number) – feed this into fail2ban-style blocking. |
| `OnDisconnected` | Connection ended, with initiator (client, server, timeout, network error, protocol error), duration and byte counts. |

SFTP (`SftpOptions.Events`). Events ending in *-ing* run **before** the operation and can reject it with
`ctx.Deny(status, message)`; events ending in *-ed* run afterwards:

| Before (can veto) | After |
|---|---|
| `OnDirectoryListing` | `OnDirectoryListed` (entry count) |
| `OnDownloadStarting` | `OnDownloadCompleted` (bytes, duration, `Aborted`) |
| `OnUploadStarting` | `OnUploadCompleted` (bytes, duration, `Aborted`, `ContentId`) |
| `OnDirectoryCreating` | `OnDirectoryCreated` |
| `OnDeleting` | `OnDeleted` |
| `OnRenaming` | `OnRenamed` |

plus `OnSessionStarted` / `OnSessionEnded`.

```csharp
sftp.Events.OnUploadStarting = ctx =>
{
    if (ctx.Path.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        ctx.Deny(SftpStatus.PermissionDenied, "Executable files are not allowed");
    return ValueTask.CompletedTask;
};

sftp.Events.OnUploadCompleted = async e =>
{
    if (!e.Aborted) await webhook.NotifyAsync(e.Path, e.BytesTransferred);
};
```

`…Completed` events are also raised when a client disconnects mid-transfer (`Aborted = true`).
"Completed" does not mean "complete file" – clients may stop early or read only parts of a file.

### Middleware

For cross-cutting concerns on *every* SFTP request (including each individual read/write):

```csharp
sftp.Use(async (ctx, next) =>
{
    var sw = Stopwatch.StartNew();
    try { await next(); }
    finally { logger.LogInformation("{User} {Op} {Path} {Ms} ms", ctx.User.Identity!.Name, ctx.Operation, ctx.Path, sw.ElapsedMilliseconds); }
});

sftp.Use(async (ctx, next) =>
{
    if (ctx.Operation == SftpOperation.Open && await quota.IsExceededAsync(ctx.User))
        throw new SftpException(SftpStatus.Failure, "Quota exceeded");
    await next();
});
```

### File systems

Storage is pluggable at two levels.

**1. `ISftpFileSystem`** – full control. One instance per session, usually chosen by user.
Paths arrive as `SftpPath`: always absolute, normalized, without `.`/`..` – an implementation
cannot be tricked into path traversal as long as it only maps `SftpPath` to its own keys.
Reads and writes are offset-based because clients pipeline many requests and may complete them out of order.
Optional features (symlinks, statvfs, fsync, random-access writes …) are declared via `SftpCapabilities`.

**`LocalFileSystem`** (included) exposes a local directory, chroot-style:

- works on Windows, Linux and macOS
- blocks symlinks/junctions pointing outside the root (`SymlinkPolicy.Deny` or `AllowWithinRoot`)
- rejects dangerous Windows names (`\`, `:` / alternate data streams, `CON`, `NUL.txt` …)
- strips setuid/setgid/sticky bits sent by clients
- SFTP semantics: `mkdir` is not `mkdir -p`, `rename` only overwrites via `posix-rename`, hidden files are listed
- `ReadOnly` option for download-only users

**2. `IFileMetadataStore` + `IBlobStore`** (design in `Storage.cs`, not yet implemented) – for the common case
"directory tree in a database, contents in an object store". The library composes them into an
`ISftpFileSystem` and takes care of upload spooling, out-of-order writes, read-ahead and committing on close.
A sample adapter for IPFS (Kubo RPC API) and a database schema sketch are included.

---

## Architecture

```
Rst.Ssh.Sftp   SFTP v3 + extensions · handle table · events · middleware · ISftpFileSystem
──────────────────────────────────────────────────────────────────────────────────────────
Rst.Ssh        Connection layer   channels, window/flow control, subsystem & exec requests
               Auth layer         password, attempt limit, delays, timeout
               Transport          version exchange, KEX + strict KEX, rekey, cipher/MAC, framing
──────────────────────────────────────────────────────────────────────────────────────────
               Socket → NetworkStream
```

- One read loop per connection; handlers (SFTP, exec) run on their own tasks.
- Back-pressure all the way to the client: window space is only granted once the application has
  consumed the data, and writes wait when the client's window is exhausted.
- `async` throughout, no thread per connection.

---

## Security notes

- **Strict KEX** (`kex-strict-s-v00@openssh.com`) is always offered, mitigating the Terrapin attack (CVE-2023-48795).
- **X25519** is a constant-time port of the TweetNaCl field arithmetic (public domain): no branches or memory
  accesses depend on secret data. Verified against the RFC 7748 vectors (including the 1,000-iteration test)
  and 1,000 random inputs against an independent `BigInteger` reference.
- **ECDH** public keys are validated by the platform when imported; all-zero X25519 results are rejected.
- **Post-quantum** `mlkem768x25519-sha256` combines ML-KEM-768 (FIPS 203) with X25519 per RFC 10042, so a
  recorded session stays confidential against a future quantum "harvest-now, decrypt-later" attacker as long as
  one of the two primitives holds. ML-KEM-768, ChaCha20/Poly1305 and the required SHA-3/SHAKE (Keccak) are
  implemented from scratch (the platform ships no SHA-3 on macOS), validated against FIPS 202/203 and
  RFC 8439 vectors and end-to-end against OpenSSH. The encapsulation key is checked per FIPS 203 §7.2.
- **MACs** are compared in constant time; packet lengths, padding and channel windows are validated, and
  oversized packets close the connection.
- **SFTP paths** are normalized centrally (`SftpPath`), so `..` can never leave the user's root.
- **Parsers are fuzzed:** the SSH wire reader, SFTP attribute and path parsers and public-key
  verification run under SharpFuzz/libFuzzer, and a cross-platform robustness suite feeds tens of
  thousands of random and malformed inputs per parser on every test run (`tests/Rst.Ssh.Fuzz`).

Known gaps: no independent third-party security review yet, no idle timeout.
A local process could swap a symlink between check and use in `LocalFileSystem` (TOCTOU); this only
matters if other local users can write into the SFTP root – SFTP clients cannot create symlinks.

---

## Performance

Measured on a Linux container with OpenSSH 9.6 as client, 200 MB files:

| Cipher | SFTP upload | SFTP download |
|---|---|---|
| `aes256-gcm@openssh.com` | ~340 MB/s | ~340 MB/s |
| `aes128-ctr` + `hmac-sha2-256-etm` | ~250 MB/s | ~240 MB/s |

Raw primitives (`tests/Rst.Ssh.Bench`): AES-CTR ~1.6 GB/s, AES-GCM ~8 GB/s, X25519 ~1.2 ms per operation.

---

## Testing

```bash
dotnet test                                                    # unit tests (crypto vectors, file system, paths)
dotnet run -c Release --project tests/Rst.Ssh.Bench            # micro benchmarks
dotnet run -c Release --project tests/Rst.Ssh.Bench -- timing  # rough X25519 timing check
dotnet run --project tests/Rst.Ssh.InteropHost -- 2222 /tmp/rstssh-data   # server for interop tests
```

The interop host offers `exec` test commands (`echo`, `cat`, `count`, `big <MB>`, `exit <code>`, `whoami`)
plus SFTP, which makes it easy to test with OpenSSH, e.g.:

```bash
ssh -p 2222 -o KexAlgorithms=ecdh-sha2-nistp384 -o Ciphers=aes256-ctr demo@localhost whoami
ssh -p 2222 -o RekeyLimit=1M demo@localhost cat < big.bin | sha256sum
```

Covered so far: every KEX × cipher × MAC × host-key combination, wrong passwords, exit codes,
200 MB transfers in both directions with checksum verification, client- and server-initiated rekey,
20 parallel connections, malformed input (non-SSH clients, SSH-1, garbage packets, huge length fields),
and SFTP security cases (path traversal, symlink escapes, read-only users).

The parsers are fuzzed with SharpFuzz/libFuzzer and a cross-platform robustness suite runs on every
`dotnet test` — see [`tests/Rst.Ssh.Fuzz/README.md`](tests/Rst.Ssh.Fuzz/README.md).

---

## Roadmap

1. OpenSSH private key format, idle timeout, keepalive
2. Implementation of the metadata + blob file system (IPFS)
3. Interop with WinSCP, FileZilla, Cyberduck, SSH.NET, Paramiko; Windows server testing
4. Independent third-party security review
5. A NuGet.org release and multi-targeting `net8.0;net10.0` (the package builds via `dotnet pack`)

---

## Repository layout

```
src/Rst.Ssh/                 the library
  Ssh.cs, HostKey.cs         public SSH API (server, builder, options, events, auth)
  Sftp.cs, SftpPath.cs       public SFTP API (options, events, file system abstraction)
  LocalFileSystem.cs         local directory implementation
  Storage.cs                 metadata + blob store design (IPFS sample)
  Internal/                  transport, key exchange, crypto, session, channels
  Sftp/SftpSubsystem.cs      SFTP v3 protocol implementation
samples/Rst.Ssh.Demo/        demo server: local file system, users in a dictionary, all events
tests/Rst.Ssh.Tests/         unit tests
tests/Rst.Ssh.InteropHost/   test server for interop tests against real clients
tests/Rst.Ssh.Fuzz/          SharpFuzz harness + targets for the SSH/SFTP parsers
tests/Rst.Ssh.Bench/         micro benchmarks and timing check
```

## License

This project is **source-available** under a dual-licensing model:

- **Free for personal use and small businesses** under the
  [PolyForm Small Business License 1.0.0](https://polyformproject.org/licenses/small-business/1.0.0)
  (see [`LICENSE`](LICENSE)). In short, you may use the software free of charge — including
  commercially — as long as your organization stays under the license's size thresholds
  (roughly: a small business by headcount and annual revenue). The exact, binding thresholds
  and conditions are defined in the license text itself.

- **Commercial license required for larger organizations.** Organizations that exceed the
  PolyForm Small Business thresholds (e.g. annual revenue above USD 1,000,000) need a separate
  commercial license. See <https://sftp-server.net> for details and how to get in touch.

Note: PolyForm Small Business is a source-available license, not an OSI-approved open-source
license — this is by design, because the goal is to keep it free for small users while
requiring larger companies to contribute. This section is a summary for convenience; the
[`LICENSE`](LICENSE) file governs. It is not legal advice.
