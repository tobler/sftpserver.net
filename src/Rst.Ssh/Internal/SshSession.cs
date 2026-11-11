using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Rst.Ssh.Internal;

/// <summary>One SSH connection: transport, key exchange, authentication, channels.</summary>
internal sealed partial class SshSession : ISshSession
{
    private const string StrictKexClient = "kex-strict-c-v00@openssh.com";
    private const string StrictKexServer = "kex-strict-s-v00@openssh.com";

    private readonly SshServer _server;
    private readonly SshServerOptions _options;
    private readonly ILogger _log;
    private readonly PacketTransport _transport;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _closed = new();
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly string _serverVersion;

    // Key exchange
    private byte[]? _sessionId;
    private byte[]? _serverKexInit, _clientKexInit;
    private KexNegotiation? _kex;
    private bool _outgoingKex;                       // between our own KEXINIT and our own NEWKEYS
    private TaskCompletionSource _outgoingKexDone = CompletedTcs();
    private DirectionKeys? _pendingIncomingKeys;
    private bool _strictKex;
    private bool _initialKexDone;
    private bool _clientWantsExtInfo;
    private bool _ignoreNextKexPacket;

    // Authentication
    private bool _userAuthServiceAccepted;
    private int _failedAuthAttempts;
    private CancellationTokenSource? _authTimeout;

    // Outcome
    private DisconnectInitiator _initiator = DisconnectInitiator.Client;
    private string? _disconnectMessage;

    public SshSession(SshServer server, Stream stream, IPEndPoint remote, IPEndPoint local)
    {
        _server = server;
        _options = server.Options;
        _log = server.Logger;
        _transport = new PacketTransport(stream, _options.Limits.MaxPacketSize + 1024);
        _serverVersion = "SSH-2.0-" + _options.SoftwareVersion;
        RemoteEndPoint = remote;
        LocalEndPoint = local;
        Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
    }

    // ------------------------------------------------------------------ ISshSession

    public string Id { get; }
    public IPEndPoint RemoteEndPoint { get; }
    public IPEndPoint LocalEndPoint { get; }
    public string ClientVersion { get; private set; } = "";
    public ClaimsPrincipal? User { get; private set; }
    public NegotiatedAlgorithms? Algorithms { get; private set; }
    public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;
    public IDictionary<string, object?> Items { get; } = new Dictionary<string, object?>();
    public CancellationToken Closed => _closed.Token;

    public async ValueTask DisconnectAsync(SshDisconnectReason reason, string message = "")
    {
        if (_closed.IsCancellationRequested) return;
        _initiator = DisconnectInitiator.Server;
        _disconnectMessage = message;
        try
        {
            var w = new SshWriter().Byte(SshMessage.Disconnect).UInt32((uint)reason).String(message).String("");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await SendAsync(w, timeout.Token, kexMessage: true);
        }
        catch { /* the connection is ending anyway */ }
        _closed.Cancel();
    }

    // ------------------------------------------------------------------ Main loop

    public async Task RunAsync(CancellationToken serverStopping)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(serverStopping, _closed.Token);
        _authTimeout = new CancellationTokenSource(_options.AuthenticationTimeout);
        using var authTimeoutRegistration = _authTimeout.Token.Register(() =>
        {
            if (User is null) _ = TimeoutAsync();
        });
        var ct = linked.Token;

        try
        {
            await _transport.SendVersionAsync(_serverVersion, ct);
            ClientVersion = await _transport.ReadVersionAsync(ct);
            _log.LogDebug("[{Id}] Client {Version} from {Remote}", Id, ClientVersion, RemoteEndPoint);

            await StartKexAsync(ct);

            while (!ct.IsCancellationRequested)
            {
                var payload = await _transport.ReadPacketAsync(ct);
                if (payload is null) { _initiator = DisconnectInitiator.Client; break; }
                await DispatchAsync(payload, ct);

                if (_initialKexDone && !_outgoingKex &&
                    (_transport.BytesSinceKexIn > _options.RekeyAfterBytes || _transport.BytesSinceKexOut > _options.RekeyAfterBytes))
                {
                    _log.LogDebug("[{Id}] Rekey after data volume limit", Id);
                    await StartKexAsync(ct);
                }
            }
        }
        catch (OperationCanceledException) when (_closed.IsCancellationRequested || serverStopping.IsCancellationRequested)
        {
            // Normal end (DisconnectAsync / server stop)
        }
        catch (SshProtocolException e)
        {
            _log.LogWarning("[{Id}] Protocol error: {Message}", Id, e.Message);
            await DisconnectAsync(e.Reason, e.Message);
            _initiator = DisconnectInitiator.ProtocolError;
            _disconnectMessage = e.Message;
        }
        catch (Exception e) when (e is IOException or EndOfStreamException or ObjectDisposedException)
        {
            _initiator = DisconnectInitiator.NetworkError;
            _disconnectMessage = e.Message;
            _log.LogDebug("[{Id}] Connection lost: {Message}", Id, e.Message);
        }
        catch (Exception e)
        {
            _log.LogError(e, "[{Id}] Internal error", Id);
            await DisconnectAsync(SshDisconnectReason.ByApplication, "Internal error");
        }
        finally
        {
            _closed.Cancel();
            await CloseAllChannelsAsync();
            await _transport.DisposeAsync();
            _authTimeout.Dispose();
            _log.LogInformation("[{Id}] Connection closed ({Initiator}) after {Duration}", Id, _initiator, _uptime.Elapsed);
            await RaiseAsync(_options.Events.OnDisconnected, new DisconnectedContext(
                this, _initiator, _disconnectMessage, _uptime.Elapsed, _transport.BytesReceived, _transport.BytesSent));
        }
    }

    private async Task TimeoutAsync()
    {
        _log.LogInformation("[{Id}] Authentication timeout", Id);
        await DisconnectAsync(SshDisconnectReason.ByApplication, "Authentication timed out");
        _initiator = DisconnectInitiator.Timeout;
    }

    private async ValueTask DispatchAsync(byte[] payload, CancellationToken ct)
    {
        var type = (SshMessage)payload[0];

        if (_ignoreNextKexPacket && type is >= SshMessage.KexEcdhInit and <= (SshMessage)49)
        {
            _ignoreNextKexPacket = false;
            return;
        }

        // Strict KEX (Terrapin protection): only KEX messages during the initial exchange.
        if (!_initialKexDone && _strictKex && type is not (SshMessage.KexInit or SshMessage.KexEcdhInit or SshMessage.NewKeys))
            throw new SshProtocolException($"Unexpected message {type} during key exchange (strict KEX)");

        switch (type)
        {
            case SshMessage.Disconnect:
                var r = new SshReader(payload.AsMemory(1));
                r.ReadUInt32();
                _disconnectMessage = r.ReadString();
                _initiator = DisconnectInitiator.Client;
                _closed.Cancel();
                return;
            case SshMessage.Ignore:
            case SshMessage.Debug:
            case SshMessage.Unimplemented:
                return;
            case SshMessage.KexInit:
                await OnKexInitAsync(payload, ct);
                return;
            case SshMessage.KexEcdhInit:
                await OnKexEcdhInitAsync(payload, ct);
                return;
            case SshMessage.NewKeys:
                OnNewKeys();
                return;
        }

        if (!_initialKexDone)
            throw new SshProtocolException($"Message {type} before key exchange completed");

        switch (type)
        {
            case SshMessage.ServiceRequest:
                await OnServiceRequestAsync(payload, ct);
                return;
            case SshMessage.UserAuthRequest:
                await OnUserAuthRequestAsync(payload, ct);
                return;
        }

        if (User is null)
            throw new SshProtocolException($"Message {type} before authentication");

        if (type is >= SshMessage.GlobalRequest and <= SshMessage.ChannelFailure)
        {
            await OnConnectionMessageAsync(type, payload, ct);
            return;
        }

        // Unknown: SSH_MSG_UNIMPLEMENTED with the packet's sequence number
        await SendAsync(new SshWriter().Byte(SshMessage.Unimplemented).UInt32(_transport.IncomingSequence - 1), ct);
    }

    // ------------------------------------------------------------------ Sending

    internal ValueTask SendAsync(SshWriter writer, CancellationToken ct) => SendAsync(writer, ct, kexMessage: false);

    private async ValueTask SendAsync(SshWriter writer, CancellationToken ct, bool kexMessage)
    {
        while (true)
        {
            if (!kexMessage && _outgoingKex)
                await _outgoingKexDone.Task.WaitAsync(ct);

            await _sendLock.WaitAsync(ct);
            try
            {
                if (!kexMessage && _outgoingKex) continue;   // wait again
                await _transport.WritePacketAsync(writer.Memory, ct);
                return;
            }
            finally { _sendLock.Release(); }
        }
    }

    private static async ValueTask RaiseAsync<T>(Func<T, ValueTask>? handler, T arg)
    {
        if (handler is null) return;
        try { await handler(arg); }
        catch { /* errors in application event handlers must not terminate the connection */ }
    }

    private static TaskCompletionSource CompletedTcs()
    {
        var t = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        t.SetResult();
        return t;
    }

    // ------------------------------------------------------------------ Key exchange

    private sealed record KexNegotiation(string Kex, string HostKeyAlgorithm, HostKey HostKey,
        string CipherCs, string CipherSc, string? MacCs, string? MacSc);

    private async Task StartKexAsync(CancellationToken ct)
    {
        if (_outgoingKex) return;

        var algorithms = _options.Algorithms;
        var kexList = algorithms.KeyExchange.Where(Internal.Algorithms.KeyExchange.Contains).ToList();
        if (!_initialKexDone) kexList.Add(StrictKexServer);

        var hostKeyAlgorithms = _options.HostKeys.SelectMany(k => k.SignatureAlgorithms).Distinct().ToList();
        var ciphers = algorithms.Encryption.Where(Internal.Algorithms.Encryption.Contains).ToList();
        var macs = algorithms.Mac.Where(Internal.Algorithms.Mac.Contains).ToList();

        var w = new SshWriter(512)
            .Byte(SshMessage.KexInit)
            .Raw(RandomNumberGenerator.GetBytes(16))
            .NameList(kexList)
            .NameList(hostKeyAlgorithms)
            .NameList(ciphers).NameList(ciphers)
            .NameList(macs).NameList(macs)
            .NameList(Internal.Algorithms.Compression).NameList(Internal.Algorithms.Compression)
            .NameList([]).NameList([])
            .Boolean(false)
            .UInt32(0);

        _serverKexInit = w.ToArray();
        _outgoingKex = true;
        _outgoingKexDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await SendAsync(w, ct, kexMessage: true);
    }

    private async Task OnKexInitAsync(byte[] payload, CancellationToken ct)
    {
        if (_clientKexInit is not null)
            throw new SshProtocolException("Duplicate KEXINIT");

        _clientKexInit = payload;
        if (!_outgoingKex) await StartKexAsync(ct);          // rekey initiated by the client

        var r = new SshReader(payload.AsMemory(17));
        var kex = r.ReadNameList();
        var hostKey = r.ReadNameList();
        var encCs = r.ReadNameList();
        var encSc = r.ReadNameList();
        var macCs = r.ReadNameList();
        var macSc = r.ReadNameList();
        var compCs = r.ReadNameList();
        var compSc = r.ReadNameList();
        r.ReadNameList(); r.ReadNameList();
        var firstKexFollows = r.ReadBoolean();

        if (!_initialKexDone)
        {
            _strictKex = kex.Contains(StrictKexClient);
            _clientWantsExtInfo = kex.Contains("ext-info-c");
            if (_strictKex && _transport.IncomingSequence != 1)
                throw new SshProtocolException("KEXINIT must be the first packet (strict KEX)");
        }

        var serverReader = new SshReader(_serverKexInit.AsMemory(17));
        var serverKex = serverReader.ReadNameList();
        var serverHostKey = serverReader.ReadNameList();
        var serverCiphers = serverReader.ReadNameList();
        serverReader.ReadNameList();
        var serverMacs = serverReader.ReadNameList();

        var chosenKex = Internal.Algorithms.Negotiate(kex, serverKex)
            ?? throw new SshProtocolException("No common key exchange algorithm", SshDisconnectReason.KeyExchangeFailed);
        var chosenHostKey = Internal.Algorithms.Negotiate(hostKey, serverHostKey)
            ?? throw new SshProtocolException("No common host key algorithm", SshDisconnectReason.KeyExchangeFailed);
        var chosenEncCs = Internal.Algorithms.Negotiate(encCs, serverCiphers)
            ?? throw new SshProtocolException("No common cipher (client→server)", SshDisconnectReason.KeyExchangeFailed);
        var chosenEncSc = Internal.Algorithms.Negotiate(encSc, serverCiphers)
            ?? throw new SshProtocolException("No common cipher (server→client)", SshDisconnectReason.KeyExchangeFailed);
        string? chosenMacCs = null, chosenMacSc = null;
        if (!Internal.Algorithms.HasImplicitMac(chosenEncCs))
            chosenMacCs = Internal.Algorithms.Negotiate(macCs, serverMacs)
                ?? throw new SshProtocolException("No common MAC (client→server)", SshDisconnectReason.KeyExchangeFailed);
        if (!Internal.Algorithms.HasImplicitMac(chosenEncSc))
            chosenMacSc = Internal.Algorithms.Negotiate(macSc, serverMacs)
                ?? throw new SshProtocolException("No common MAC (server→client)", SshDisconnectReason.KeyExchangeFailed);
        if (!compCs.Contains("none") || !compSc.Contains("none"))
            throw new SshProtocolException("Client requires compression", SshDisconnectReason.KeyExchangeFailed);

        var key = _options.HostKeys.First(k => k.SignatureAlgorithms.Contains(chosenHostKey));
        _kex = new KexNegotiation(chosenKex, chosenHostKey, key, chosenEncCs, chosenEncSc, chosenMacCs, chosenMacSc);

        // Client guessed and guessed wrong -> discard its next KEX packet (RFC 4253 §7)
        if (firstKexFollows && (kex.FirstOrDefault() != chosenKex || hostKey.FirstOrDefault() != chosenHostKey))
            _ignoreNextKexPacket = true;

        _log.LogDebug("[{Id}] KEX {Kex}, Host-Key {HostKey}, Cipher {Cipher}, MAC {Mac}, strict={Strict}",
            Id, chosenKex, chosenHostKey, chosenEncCs, chosenMacCs ?? "(AEAD)", _strictKex);
    }

    private async Task OnKexEcdhInitAsync(byte[] payload, CancellationToken ct)
    {
        var kex = _kex ?? throw new SshProtocolException("KEX_ECDH_INIT without prior KEXINIT");
        var r = new SshReader(payload.AsMemory(1));
        var clientPublic = r.ReadBinaryArray();

        byte[] serverPublic, sharedSecret;
        if (kex.Kex == "mlkem768x25519-sha256")
        {
            // RFC 10042: C_INIT = C_PK2 (ML-KEM-768 ek) ‖ C_PK1 (X25519 pub); S_REPLY = S_CT2 (ct) ‖ S_PK1.
            const int ekLen = MlKem768.EncapsKeyLength;
            if (clientPublic.Length != ekLen + 32)
                throw new SshProtocolException("Invalid mlkem768x25519 C_INIT length", SshDisconnectReason.KeyExchangeFailed);

            var (kPq, ciphertext) = MlKem768.Encapsulate(clientPublic.AsSpan(0, ekLen));   // also runs the FIPS 203 §7.2 key check
            var (xPriv, xPub) = X25519.GenerateKeyPair();
            var kCl = X25519.ScalarMult(xPriv, clientPublic.AsSpan(ekLen, 32));
            if (kCl.All(b => b == 0)) throw new SshProtocolException("Invalid X25519 result", SshDisconnectReason.KeyExchangeFailed);

            serverPublic = [.. ciphertext, .. xPub];
            sharedSecret = SHA256.HashData([.. kPq, .. kCl]);     // K = SHA256(K_PQ ‖ K_CL)
            CryptographicOperations.ZeroMemory(kPq);
            CryptographicOperations.ZeroMemory(kCl);
        }
        else if (kex.Kex.StartsWith("curve25519", StringComparison.Ordinal))
        {
            if (clientPublic.Length != 32) throw new SshProtocolException("Invalid Curve25519 key", SshDisconnectReason.KeyExchangeFailed);
            var (priv, pub) = X25519.GenerateKeyPair();
            serverPublic = pub;
            sharedSecret = X25519.ScalarMult(priv, clientPublic);
            if (sharedSecret.All(b => b == 0)) throw new SshProtocolException("Invalid Curve25519 result", SshDisconnectReason.KeyExchangeFailed);
        }
        else
        {
            var curve = kex.Kex switch
            {
                "ecdh-sha2-nistp256" => ECCurve.NamedCurves.nistP256,
                "ecdh-sha2-nistp384" => ECCurve.NamedCurves.nistP384,
                _ => ECCurve.NamedCurves.nistP521,
            };
            using var ecdh = ECDiffieHellman.Create(curve);
            var coordinateLength = (ecdh.KeySize + 7) / 8;
            if (clientPublic.Length != 1 + 2 * coordinateLength || clientPublic[0] != 4)
                throw new SshProtocolException("Invalid ECDH key", SshDisconnectReason.KeyExchangeFailed);

            using var peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = clientPublic[1..(1 + coordinateLength)], Y = clientPublic[(1 + coordinateLength)..] },
            });   // ImportParameters validates that the point lies on the curve
            sharedSecret = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

            var p = ecdh.ExportParameters(false);
            serverPublic = [4, .. p.Q.X!, .. p.Q.Y!];
        }

        var hashAlgorithm = Internal.Algorithms.KexHash(kex.Kex);
        var hostKeyBlob = kex.HostKey.PublicKeyBlob;
        // The PQ hybrid encodes K as an SSH string (RFC 10042 §2.4 – K is a hash output, not an integer);
        // the classical methods encode it as an mpint (RFC 4253).
        var k = kex.Kex == "mlkem768x25519-sha256"
            ? new SshWriter().Binary(sharedSecret).ToArray()
            : new SshWriter().MPIntFromUnsigned(sharedSecret).ToArray();

        var exchange = new SshWriter(1024)
            .String(ClientVersion).String(_serverVersion)
            .Binary(_clientKexInit).Binary(_serverKexInit)
            .Binary(hostKeyBlob)
            .Binary(clientPublic).Binary(serverPublic)
            .Raw(k);
        var h = Hash(hashAlgorithm, exchange.Span);
        _sessionId ??= h;

        var signature = kex.HostKey.Sign(kex.HostKeyAlgorithm, h);
        var reply = new SshWriter(1024)
            .Byte(SshMessage.KexEcdhReply)
            .Binary(hostKeyBlob)
            .Binary(serverPublic)
            .Binary(signature);

        var outgoing = BuildKeys(hashAlgorithm, k, h, kex.CipherSc, kex.MacSc, 'B', 'D', 'F');
        _pendingIncomingKeys = BuildKeys(hashAlgorithm, k, h, kex.CipherCs, kex.MacCs, 'A', 'C', 'E');
        CryptographicOperations.ZeroMemory(sharedSecret);

        await _sendLock.WaitAsync(ct);
        try
        {
            await _transport.WritePacketAsync(reply.Memory, ct);
            await _transport.WritePacketAsync(new SshWriter().Byte(SshMessage.NewKeys).Memory, ct);
            _transport.SetOutgoingKeys(outgoing);
            if (_strictKex) _transport.ResetOutgoingSequence();

            if (!_initialKexDone && _clientWantsExtInfo)
            {
                // Allowed signature algorithms for public key auth (RFC 8308)
                var ext = new SshWriter().Byte(SshMessage.ExtInfo).UInt32(1)
                    .String("server-sig-algs")
                    .NameList(["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"]);
                await _transport.WritePacketAsync(ext.Memory, ct);
            }

            _outgoingKex = false;
            _outgoingKexDone.TrySetResult();
        }
        finally { _sendLock.Release(); }
    }

    private void OnNewKeys()
    {
        var keys = _pendingIncomingKeys ?? throw new SshProtocolException("NEWKEYS without key exchange");
        _pendingIncomingKeys = null;
        _transport.SetIncomingKeys(keys);
        if (_strictKex) _transport.ResetIncomingSequence();

        var kex = _kex!;
        Algorithms = new NegotiatedAlgorithms(kex.Kex, kex.HostKeyAlgorithm, kex.CipherCs, kex.CipherSc, kex.MacCs, kex.MacSc);
        _clientKexInit = null;
        _kex = null;

        if (!_initialKexDone)
        {
            _initialKexDone = true;
            _log.LogInformation("[{Id}] Connected: {Client}, {Kex}, {Cipher}", Id, ClientVersion, kex.Kex, kex.CipherCs);
            _ = RaiseAsync(_options.Events.OnConnected, (ISshSession)this);
        }
    }

    private DirectionKeys BuildKeys(HashAlgorithmName hash, byte[] k, byte[] h, string cipher, string? mac, char ivLetter, char keyLetter, char macLetter)
    {
        var (keyLength, ivLength) = Internal.Algorithms.CipherSizes(cipher);
        var iv = DeriveKey(hash, k, h, ivLetter, ivLength);
        var key = DeriveKey(hash, k, h, keyLetter, keyLength);

        if (Internal.Algorithms.IsAead(cipher))
            return new DirectionKeys { Cipher = cipher, Gcm = new AesGcm(key, 16), GcmIv = iv };

        if (Internal.Algorithms.IsChaChaPoly(cipher))
            return new DirectionKeys { Cipher = cipher, ChaChaPoly = new ChaCha20Poly1305Cipher(key) };

        var (macHash, macLength, etm) = Internal.Algorithms.MacInfo(mac!);
        var macKey = DeriveKey(hash, k, h, macLetter, macLength);
        return new DirectionKeys
        {
            Cipher = cipher,
            Ctr = new AesCtr(key, iv),
            Mac = IncrementalHash.CreateHMAC(macHash, macKey),
            MacLength = macLength,
            Etm = etm,
        };
    }

    /// <summary>RFC 4253 §7.2: HASH(K || H || X || session_id), extended with HASH(K || H || K1 …).</summary>
    private byte[] DeriveKey(HashAlgorithmName hash, byte[] k, byte[] h, char letter, int length)
    {
        var result = new List<byte>(Hash(hash, new SshWriter().Raw(k).Raw(h).Byte((byte)letter).Raw(_sessionId).Span));
        while (result.Count < length)
            result.AddRange(Hash(hash, new SshWriter().Raw(k).Raw(h).Raw(result.ToArray()).Span));
        return result.Take(length).ToArray();
    }

    private static byte[] Hash(HashAlgorithmName name, ReadOnlySpan<byte> data) => name.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new NotSupportedException(name.Name),
    };

    // ------------------------------------------------------------------ Authentication

    private async Task OnServiceRequestAsync(byte[] payload, CancellationToken ct)
    {
        var service = new SshReader(payload.AsMemory(1)).ReadAscii();
        if (service != "ssh-userauth")
            throw new SshProtocolException($"Service {service} not available", SshDisconnectReason.ServiceNotAvailable);
        _userAuthServiceAccepted = true;
        await SendAsync(new SshWriter().Byte(SshMessage.ServiceAccept).String(service), ct);
    }

    private async Task OnUserAuthRequestAsync(byte[] payload, CancellationToken ct)
    {
        if (!_userAuthServiceAccepted)
            throw new SshProtocolException("USERAUTH without SERVICE_REQUEST", SshDisconnectReason.ServiceNotAvailable);
        if (User is not null) return;    // RFC 4252 §5.1: ignore requests after success

        var r = new SshReader(payload.AsMemory(1));
        var userName = r.ReadString();
        var service = r.ReadAscii();
        var method = r.ReadAscii();
        if (service != "ssh-connection")
            throw new SshProtocolException($"Service {service} not available", SshDisconnectReason.ServiceNotAvailable);

        var authenticator = _server.Authenticator;
        var ctx = new AuthContext(userName, RemoteEndPoint, ClientVersion, this);
        var allowed = await authenticator.GetMethodsAsync(ctx, ct);

        AuthResult result;
        SshAuthMethods attempted;
        switch (method)
        {
            case "password" when allowed.HasFlag(SshAuthMethods.Password):
                attempted = SshAuthMethods.Password;
                if (r.ReadBoolean())                         // password change – not supported
                {
                    result = AuthResult.Failure;
                    break;
                }
                var password = r.ReadString();
                try { result = await authenticator.AuthenticatePasswordAsync(ctx, password, ct); }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    _log.LogError(e, "[{Id}] Authenticator threw an exception", Id);
                    result = AuthResult.Failure;
                }
                break;

            case "publickey" when allowed.HasFlag(SshAuthMethods.PublicKey):
            {
                var hasSignature = r.ReadBoolean();
                var algorithm = r.ReadAscii();
                var keyBlob = r.ReadBinaryArray();

                if (!PublicKeyAuth.IsSupported(algorithm))
                {
                    // Unknown/unaccepted algorithm: tell the client to try another key, not a failed attempt.
                    await SendAuthFailureAsync(allowed, partial: false, ct);
                    return;
                }

                var publicKey = new SshPublicKey(algorithm, keyBlob, PublicKeyFingerprint(keyBlob));

                if (!hasSignature)
                {
                    // Query phase (RFC 4252 §7): would this key be accepted? If so, ask the client to sign.
                    var probe = await SafeAuthenticatePublicKeyAsync(authenticator, ctx, publicKey, ct);
                    if (probe is AuthResult.SuccessResult)
                        await SendAsync(new SshWriter().Byte(SshMessage.UserAuthPkOk).String(algorithm).Binary(keyBlob), ct);
                    else
                        await SendAuthFailureAsync(allowed, partial: false, ct);
                    return;
                }

                attempted = SshAuthMethods.PublicKey;
                var signature = r.ReadBinaryArray();
                var signedData = BuildPublicKeySignedData(userName, algorithm, keyBlob);
                if (!PublicKeyAuth.Verify(algorithm, keyBlob, signature, signedData))
                {
                    // A present-but-invalid signature is a genuine failed attempt.
                    result = AuthResult.Failure;
                    break;
                }
                result = await SafeAuthenticatePublicKeyAsync(authenticator, ctx, publicKey, ct);
                break;
            }

            case "none":
                // Client asks which methods exist – not a failed attempt.
                await SendAuthFailureAsync(allowed, partial: false, ct);
                return;

            default:
                // keyboard-interactive and unoffered methods: not counted as a failed attempt
                await SendAuthFailureAsync(allowed, partial: false, ct);
                return;
        }

        switch (result)
        {
            case AuthResult.SuccessResult success:
                User = success.User;
                await SendAsync(new SshWriter().Byte(SshMessage.UserAuthSuccess), ct);
                _log.LogInformation("[{Id}] Authenticated: {User} ({Method})", Id, userName, method);
                await RaiseAsync(_options.Events.OnAuthenticated, (ISshSession)this);
                return;

            case AuthResult.PartialResult partial:
                await SendAuthFailureAsync(partial.StillRequired, partial: true, ct);
                return;

            default:
                _failedAuthAttempts++;
                _log.LogInformation("[{Id}] Authentication failed: {User} ({Method}), attempt {Attempt}", Id, userName, method, _failedAuthAttempts);
                await RaiseAsync(_options.Events.OnAuthenticationFailed, new AuthFailedContext(this, userName, attempted, _failedAuthAttempts));
                await Task.Delay(_options.FailedAuthenticationDelay, ct);
                if (_failedAuthAttempts >= _options.MaxAuthenticationAttempts)
                    throw new SshProtocolException("Too many failed attempts", SshDisconnectReason.NoMoreAuthMethodsAvailable);
                await SendAuthFailureAsync(allowed, partial: false, ct);
                return;
        }
    }

    private async ValueTask<AuthResult> SafeAuthenticatePublicKeyAsync(ISshAuthenticator authenticator, AuthContext ctx, SshPublicKey key, CancellationToken ct)
    {
        try { return await authenticator.AuthenticatePublicKeyAsync(ctx, key, ct); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _log.LogError(e, "[{Id}] Authenticator threw an exception", Id);
            return AuthResult.Failure;
        }
    }

    /// <summary>The data the client signs for publickey auth (RFC 4252 §7).</summary>
    private byte[] BuildPublicKeySignedData(string userName, string algorithm, byte[] keyBlob) =>
        new SshWriter()
            .Binary(_sessionId!)
            .Byte(SshMessage.UserAuthRequest)
            .String(userName)
            .String("ssh-connection")
            .String("publickey")
            .Boolean(true)
            .String(algorithm)
            .Binary(keyBlob)
            .ToArray();

    private static string PublicKeyFingerprint(byte[] blob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

    private ValueTask SendAuthFailureAsync(SshAuthMethods methods, bool partial, CancellationToken ct)
    {
        var names = new List<string>();
        if (methods.HasFlag(SshAuthMethods.PublicKey)) names.Add("publickey");
        if (methods.HasFlag(SshAuthMethods.Password)) names.Add("password");
        if (methods.HasFlag(SshAuthMethods.KeyboardInteractive)) names.Add("keyboard-interactive");
        return SendAsync(new SshWriter().Byte(SshMessage.UserAuthFailure).NameList(names).Boolean(partial), ct);
    }
}
