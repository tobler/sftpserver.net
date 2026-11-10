using System.Diagnostics;
using System.Security.Cryptography;
using Rst.Ssh.Internal;
// "dotnet run -c Release -- timing": rough timing check for X25519
if (args.Contains("timing")) { TimingCheck.Run(); return; }

// AES-CTR throughput (packet size as in SFTP: 32 KB)
var key = RandomNumberGenerator.GetBytes(16); var iv = RandomNumberGenerator.GetBytes(16);
var data = new byte[32 * 1024];
using var ctr = new AesCtr(key, iv);
for (var i = 0; i < 200; i++) ctr.Transform(data);
var sw = Stopwatch.StartNew(); long total = 0;
while (sw.ElapsedMilliseconds < 2000) { ctr.Transform(data); total += data.Length; }
Console.WriteLine($"AES-CTR: {total / sw.Elapsed.TotalSeconds / 1e6:F0} MB/s");

// Reference: AES-GCM from the BCL
using var gcm = new AesGcm(key, 16); var tag = new byte[16]; var nonce = new byte[12];
sw.Restart(); total = 0;
while (sw.ElapsedMilliseconds < 2000) { gcm.Encrypt(nonce, data, data, tag); total += data.Length; }
Console.WriteLine($"AES-GCM: {total / sw.Elapsed.TotalSeconds / 1e6:F0} MB/s");

// X25519
var (priv, _) = X25519.GenerateKeyPair(); var (_, pub) = X25519.GenerateKeyPair();
for (var i = 0; i < 20; i++) X25519.ScalarMult(priv, pub);
sw.Restart(); var n = 0;
while (sw.ElapsedMilliseconds < 2000) { X25519.ScalarMult(priv, pub); n++; }
Console.WriteLine($"X25519: {sw.Elapsed.TotalMilliseconds / n:F3} ms per operation");
