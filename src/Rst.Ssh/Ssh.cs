// ============================================================================
//  Rst.Ssh – public API
// ============================================================================
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Rst.Ssh.Internal;

namespace Rst.Ssh;

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

public sealed class SshServer : IAsyncDisposable
{
    private readonly List<IPEndPoint> _endPoints;
    private readonly List<TcpListener> _listeners = [];
    private readonly ConcurrentDictionary<string, SshSession> _sessions = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Task> _acceptLoops = [];

    internal SshServerOptions Options { get; }
    internal ISshAuthenticator Authenticator { get; }
    internal IReadOnlyDictionary<string, Func<ISshSession, ISshSubsystemHandler>> Subsystems { get; }
    internal ISshExecHandler? ExecHandler { get; }
    internal ILogger Logger { get; }

    internal SshServer(SshServerBuilder b)
    {
        Options = b.Options;
        _endPoints = b.EndPoints.Count > 0 ? b.EndPoints : [new IPEndPoint(IPAddress.Any, 22)];
        Authenticator = b.BuildAuthenticator();
        Subsystems = new Dictionary<string, Func<ISshSession, ISshSubsystemHandler>>(b.SubsystemFactories);
        ExecHandler = b.ExecHandler;
        Logger = Options.Logger ?? NullLogger.Instance;

        if (Options.HostKeys.Count == 0)
            throw new InvalidOperationException("At least one host key must be configured (Options.HostKeys).");
    }

    public static SshServerBuilder CreateBuilder() => new();

    /// <summary>The endpoints actually bound (useful with port 0).</summary>
    public IReadOnlyList<IPEndPoint> LocalEndPoints => _listeners.Select(l => (IPEndPoint)l.LocalEndpoint).ToList();

    public IReadOnlyCollection<ISshSession> Sessions => _sessions.Values.ToList();

    public Task StartAsync(CancellationToken ct = default)
    {
        foreach (var ep in _endPoints)
        {
            var listener = new TcpListener(ep);
            if (ep.Address.Equals(IPAddress.IPv6Any)) listener.Server.DualMode = true;
            listener.Start(backlog: 128);
            _listeners.Add(listener);
            _acceptLoops.Add(AcceptLoopAsync(listener));
            Logger.LogInformation("SSH server listening on {EndPoint}", listener.LocalEndpoint);
        }
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(TcpListener listener)
    {
        while (!_stopping.IsCancellationRequested)
        {
            Socket socket;
            try { socket = await listener.AcceptSocketAsync(_stopping.Token); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException e) { Logger.LogWarning(e, "Accept failed"); continue; }

            _ = HandleConnectionAsync(socket);
        }
    }

    private async Task HandleConnectionAsync(Socket socket)
    {
        var remote = (IPEndPoint)socket.RemoteEndPoint!;
        var local = (IPEndPoint)socket.LocalEndPoint!;
        try
        {
            if (_sessions.Count >= Options.Limits.MaxConnections ||
                _sessions.Values.Count(s => s.RemoteEndPoint.Address.Equals(remote.Address)) >= Options.Limits.MaxConnectionsPerIp)
            {
                Logger.LogWarning("Connection from {Remote} rejected: limit reached", remote);
                socket.Dispose();
                return;
            }

            if (Options.Events.OnConnecting is { } onConnecting)
            {
                var ctx = new ConnectingContext(remote, local);
                await onConnecting(ctx);
                if (ctx.IsRejected)
                {
                    Logger.LogInformation("Connection from {Remote} rejected by the application", remote);
                    socket.Dispose();
                    return;
                }
            }

            socket.NoDelay = true;
            var session = new SshSession(this, new NetworkStream(socket, ownsSocket: true), remote, local);
            _sessions[session.Id] = session;
            try { await session.RunAsync(_stopping.Token); }
            finally { _sessions.TryRemove(session.Id, out _); }
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Unexpected error on connection from {Remote}", remote);
            socket.Dispose();
        }
    }

    /// <summary>Stops accepting new connections and disconnects existing ones.</summary>
    public async Task StopAsync(CancellationToken ct = default)
    {
        _stopping.Cancel();
        foreach (var l in _listeners) l.Stop();
        await Task.WhenAll(_sessions.Values.Select(s => s.DisconnectAsync(SshDisconnectReason.ByApplication, "Server is shutting down").AsTask()));
        await Task.WhenAll(_acceptLoops);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stopping.IsCancellationRequested) await StopAsync();
        _stopping.Dispose();
    }
}

public sealed class SshServerBuilder
{
    internal List<IPEndPoint> EndPoints { get; } = [];
    internal Dictionary<string, Func<ISshSession, ISshSubsystemHandler>> SubsystemFactories { get; } = new(StringComparer.Ordinal);
    internal ISshExecHandler? ExecHandler { get; private set; }

    private ISshAuthenticator? _authenticator;
    private Func<PasswordAuthenticationContext, ValueTask<bool>>? _passwordValidator;
    private Func<string, SshPublicKey, bool>? _publicKeyValidator;

    public SshServerOptions Options { get; } = new();

    public SshServerBuilder Listen(IPEndPoint endPoint) { EndPoints.Add(endPoint); return this; }
    public SshServerBuilder Listen(int port) => Listen(new IPEndPoint(IPAddress.Any, port));
    public SshServerBuilder Configure(Action<SshServerOptions> configure) { configure(Options); return this; }

    public SshServerBuilder UseAuthenticator(ISshAuthenticator authenticator) { _authenticator = authenticator; return this; }

    /// <summary>
    /// Simplest case: the application receives user name + password and says yes or no.
    /// On "no" the client gets "Permission denied" and may try again
    /// (up to MaxAuthenticationAttempts), after which the connection is closed.
    /// </summary>
    public SshServerBuilder UsePasswordAuthentication(Func<string, string, bool> validate)
        => UsePasswordAuthentication(ctx => ValueTask.FromResult(validate(ctx.UserName, ctx.Password)));

    /// <summary>Async variant with context (remote IP, client version, session) – e.g. for database lookups.</summary>
    public SshServerBuilder UsePasswordAuthentication(Func<PasswordAuthenticationContext, ValueTask<bool>> validate)
    {
        _passwordValidator = validate;
        return this;
    }

    /// <summary>Public key authentication: the library verifies the signature, the application only decides whether the key belongs to the user.</summary>
    /// <remarks>Not yet implemented in the core.</remarks>
    public SshServerBuilder UsePublicKeyAuthentication(Func<string, SshPublicKey, bool> isAuthorized)
    {
        _publicKeyValidator = isAuthorized;
        return this;
    }

    /// <summary>Registers a subsystem handler ("sftp", custom subsystems …).</summary>
    public SshServerBuilder AddSubsystem(string name, Func<ISshSession, ISshSubsystemHandler> factory)
    {
        SubsystemFactories[name] = factory;
        return this;
    }

    /// <summary>exec is deliberately optional – a pure SFTP server rejects exec/shell.</summary>
    public SshServerBuilder UseExecHandler(ISshExecHandler handler) { ExecHandler = handler; return this; }

    public SshServer Build() => new(this);

    internal ISshAuthenticator BuildAuthenticator()
    {
        if (_authenticator is not null) return _authenticator;
        if (_passwordValidator is null && _publicKeyValidator is null)
            throw new InvalidOperationException("No authentication configured (UsePasswordAuthentication / UseAuthenticator).");
        return new DelegateAuthenticator(_passwordValidator, _publicKeyValidator);
    }

    private sealed class DelegateAuthenticator(
        Func<PasswordAuthenticationContext, ValueTask<bool>>? password,
        Func<string, SshPublicKey, bool>? publicKey) : ISshAuthenticator
    {
        public ValueTask<SshAuthMethods> GetMethodsAsync(AuthContext ctx, CancellationToken ct) =>
            ValueTask.FromResult((password is null ? SshAuthMethods.None : SshAuthMethods.Password) |
                                 (publicKey is null ? SshAuthMethods.None : SshAuthMethods.PublicKey));

        public async ValueTask<AuthResult> AuthenticatePasswordAsync(AuthContext ctx, string pwd, CancellationToken ct)
        {
            if (password is null) return AuthResult.Failure;
            var ok = await password(new PasswordAuthenticationContext(ctx.UserName, pwd, ctx.RemoteEndPoint, ctx.ClientVersion, ctx.Session));
            return ok ? AuthResult.Success(DefaultPrincipal(ctx.UserName)) : AuthResult.Failure;
        }

        public ValueTask<AuthResult> AuthenticatePublicKeyAsync(AuthContext ctx, SshPublicKey key, CancellationToken ct) =>
            ValueTask.FromResult(publicKey is not null && publicKey(ctx.UserName, key)
                ? AuthResult.Success(DefaultPrincipal(ctx.UserName))
                : AuthResult.Failure);
    }

    internal static ClaimsPrincipal DefaultPrincipal(string userName) =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.Name, userName)], authenticationType: "ssh"));
}

public sealed class SshServerOptions
{
    public string SoftwareVersion { get; set; } = "RstSsh_0.1";       // -> "SSH-2.0-RstSsh_0.1"
    public HostKeyCollection HostKeys { get; } = new();
    public SshAlgorithmSet Algorithms { get; set; } = SshAlgorithmSet.Default;
    public SshLimits Limits { get; } = new();
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromSeconds(60);
    public int MaxAuthenticationAttempts { get; set; } = 6;

    /// <summary>Delay after a failed authentication attempt (slows down brute force).</summary>
    public TimeSpan FailedAuthenticationDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Rekey after this many bytes (RFC 4253 §9).</summary>
    public long RekeyAfterBytes { get; set; } = 1L << 30;

    /// <summary>
    /// After this much silence from the client, send a <c>keepalive@openssh.com</c> request to detect a
    /// dead connection (and keep NAT/firewall state alive). <see cref="TimeSpan.Zero"/> disables it.
    /// </summary>
    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.Zero;

    /// <summary>Disconnect once this many keepalive probes go unanswered in a row (OpenSSH ClientAliveCountMax).</summary>
    public int KeepAliveCountMax { get; set; } = 3;

    /// <summary>
    /// Disconnect an authenticated session with no channel data in either direction for this long.
    /// <see cref="TimeSpan.Zero"/> disables it. Independent of <see cref="KeepAliveInterval"/>: a client that
    /// faithfully answers keepalives is still dropped once it has been idle this long.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.Zero;

    public ILogger? Logger { get; set; }
    public SshServerEvents Events { get; } = new();
}

public sealed class SshLimits
{
    public int MaxConnections { get; set; } = 1000;
    public int MaxConnectionsPerIp { get; set; } = 20;
    public int MaxChannelsPerSession { get; set; } = 10;
    /// <summary>Maximum SSH packet length (protection against memory DoS). The RFC requires at least 35000.</summary>
    public int MaxPacketSize { get; set; } = 256 * 1024;
    public uint ChannelWindowSize { get; set; } = 2 * 1024 * 1024;
    public uint ChannelMaxPacketSize { get; set; } = 32 * 1024;
}

/// <summary>
/// Connection lifecycle. Exceptions in event handlers are logged;
/// in OnConnecting they cause the connection to be rejected.
/// </summary>
public sealed class SshServerEvents
{
    /// <summary>TCP connection accepted, before the SSH handshake. ctx.Reject() disconnects immediately.</summary>
    public Func<ConnectingContext, ValueTask>? OnConnecting { get; set; }

    /// <summary>Handshake completed: client version and negotiated algorithms are known, the user is not yet.</summary>
    public Func<ISshSession, ValueTask>? OnConnected { get; set; }

    public Func<ISshSession, ValueTask>? OnAuthenticated { get; set; }

    /// <summary>Every failed attempt – the basis for fail2ban-style blocking.</summary>
    public Func<AuthFailedContext, ValueTask>? OnAuthenticationFailed { get; set; }

    /// <summary>Connection ended – whether cleanly, by timeout, network error or server stop.</summary>
    public Func<DisconnectedContext, ValueTask>? OnDisconnected { get; set; }
}

public sealed class ConnectingContext(IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
{
    public IPEndPoint RemoteEndPoint { get; } = remoteEndPoint;
    public IPEndPoint LocalEndPoint { get; } = localEndPoint;
    public bool IsRejected { get; private set; }
    public void Reject() => IsRejected = true;
}

public sealed record AuthFailedContext(ISshSession Session, string UserName, SshAuthMethods Method, int Attempt);

public enum DisconnectInitiator { Client, Server, Timeout, NetworkError, ProtocolError }

public sealed record DisconnectedContext(
    ISshSession Session,
    DisconnectInitiator Initiator,
    string? Message,
    TimeSpan Duration,
    long BytesReceived,
    long BytesSent);

public sealed class HostKeyCollection : List<HostKey> { }

/// <summary>Algorithms in order of preference. Negotiation follows the client's order.</summary>
public sealed record SshAlgorithmSet(
    IReadOnlyList<string> KeyExchange,
    IReadOnlyList<string> Encryption,
    IReadOnlyList<string> Mac)
{
    /// <summary>Everything the core currently implements.</summary>
    /// <remarks>Planned: mlkem768x25519-sha256, sntrup761x25519, chacha20-poly1305, ssh-ed25519.</remarks>
    public static SshAlgorithmSet Default { get; } = new(Internal.Algorithms.KeyExchange, Internal.Algorithms.Encryption, Internal.Algorithms.Mac);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// <summary>
/// The library handles protocol and cryptography (signature verification, attempt counting, delays).
/// The application only decides: is this user/password/key allowed?
/// </summary>
public interface ISshAuthenticator
{
    ValueTask<SshAuthMethods> GetMethodsAsync(AuthContext ctx, CancellationToken ct)
        => ValueTask.FromResult(SshAuthMethods.Password);

    ValueTask<AuthResult> AuthenticatePasswordAsync(AuthContext ctx, string password, CancellationToken ct)
        => ValueTask.FromResult(AuthResult.Failure);

    ValueTask<AuthResult> AuthenticatePublicKeyAsync(AuthContext ctx, SshPublicKey key, CancellationToken ct)
        => ValueTask.FromResult(AuthResult.Failure);
}

[Flags]
public enum SshAuthMethods { None = 0, Password = 1, PublicKey = 2, KeyboardInteractive = 4 }

public sealed record PasswordAuthenticationContext(string UserName, string Password, IPEndPoint RemoteEndPoint, string ClientVersion, ISshSession Session);

public sealed record AuthContext(string UserName, IPEndPoint RemoteEndPoint, string ClientVersion, ISshSession Session);

public sealed record SshPublicKey(string Algorithm, ReadOnlyMemory<byte> Blob, string Fingerprint);

public abstract record AuthResult
{
    public static AuthResult Failure { get; } = new FailureResult();
    public static AuthResult Success(ClaimsPrincipal user) => new SuccessResult(user);
    /// <summary>Multi-factor: this method succeeded, but something else is still required.</summary>
    public static AuthResult Partial(SshAuthMethods stillRequired) => new PartialResult(stillRequired);

    public sealed record SuccessResult(ClaimsPrincipal User) : AuthResult;
    public sealed record FailureResult : AuthResult;
    public sealed record PartialResult(SshAuthMethods StillRequired) : AuthResult;
}

// ---------------------------------------------------------------------------
// Session, channels, subsystems
// ---------------------------------------------------------------------------

public interface ISshSession
{
    string Id { get; }
    IPEndPoint RemoteEndPoint { get; }
    string ClientVersion { get; }                                    // "SSH-2.0-OpenSSH_9.6"
    ClaimsPrincipal? User { get; }                                   // null until authenticated
    NegotiatedAlgorithms? Algorithms { get; }
    DateTimeOffset ConnectedAt { get; }
    IDictionary<string, object?> Items { get; }
    CancellationToken Closed { get; }
    ValueTask DisconnectAsync(SshDisconnectReason reason, string message = "");
}

public sealed record NegotiatedAlgorithms(string KeyExchange, string HostKey, string EncryptionCs, string EncryptionSc, string? MacCs, string? MacSc);

public enum SshDisconnectReason
{
    HostNotAllowedToConnect = 1, ProtocolError = 2, KeyExchangeFailed = 3, MacError = 5, ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8, ConnectionLost = 10, ByApplication = 11, TooManyConnections = 12,
    AuthCancelledByUser = 13, NoMoreAuthMethodsAvailable = 14,
}

/// <summary>A channel as a byte stream. The library handles flow control (window):
/// reading releases window, writing waits when the client has no window left.</summary>
public interface ISshChannel
{
    uint Id { get; }
    ISshSession Session { get; }
    Stream Stream { get; }
    /// <summary>Triggered when the client closes the channel or the connection ends.</summary>
    CancellationToken Closed { get; }
    ValueTask CloseAsync(uint? exitStatus = null);
}

public interface ISshSubsystemHandler
{
    Task RunAsync(ISshChannel channel, CancellationToken ct);
}

public interface ISshExecHandler
{
    /// <returns>Exit status for the client.</returns>
    Task<int> ExecuteAsync(ISshChannel channel, string command, CancellationToken ct);
}
