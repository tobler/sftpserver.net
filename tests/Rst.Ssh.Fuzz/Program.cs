// SharpFuzz entry point. Instrument Rst.Ssh.dll with the `sharpfuzz` tool, then run this under
// libfuzzer-dotnet. Pick the target with the FUZZ_TARGET environment variable (default: ssh-reader).
//
//   FUZZ_TARGET=sftp-path libfuzzer-dotnet --target_path=Rst.Ssh.Fuzz corpus/sftp-path
//
// See README.md for the full, copy-pasteable workflow.
using Rst.Ssh.Fuzz;
using SharpFuzz;

var name = Environment.GetEnvironmentVariable("FUZZ_TARGET") ?? "ssh-reader";
if (!FuzzTargets.All.TryGetValue(name, out var target))
{
    Console.Error.WriteLine($"Unknown FUZZ_TARGET '{name}'. Known targets: {string.Join(", ", FuzzTargets.All.Keys)}");
    return 2;
}

Console.Error.WriteLine($"Fuzzing target: {name}");
Fuzzer.LibFuzzer.Run(span => target(span.ToArray()));
return 0;
