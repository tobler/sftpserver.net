# Fuzzing

Coverage-guided fuzzing of the library's untrusted-input parsers with
[SharpFuzz](https://github.com/Metalnem/sharpfuzz) + libFuzzer.

## Targets

Each target feeds the fuzzer's bytes straight into a real parser (`FuzzTargets.cs`). It swallows only
the exception that parser is allowed to raise on malformed input — any other exception is a bug.

| Target | Parser under test |
|---|---|
| `ssh-reader` | `SshReader` — the core SSH wire reader (strings, name-lists, mpints, …) |
| `sftp-attrs` | `SftpSubsystem.ReadAttrs` — the SFTP attribute parser |
| `sftp-path` | `SftpPath.Parse` — path normalization / traversal / NUL handling |
| `pubkey-verify` | `PublicKeyAuth.Verify` — public-key signature verification (contract: never throws) |

## Run it with Docker (any OS)

libFuzzer needs Linux, so the easiest way to run it — including on macOS and Windows — is the
bundled container. It installs SharpFuzz, builds the `libfuzzer-dotnet` loader, publishes the
harness and instruments the parser assembly.

```bash
# from the repository root
docker build -f tests/Rst.Ssh.Fuzz/Dockerfile -t rstssh-fuzz .
docker run --rm rstssh-fuzz sftp-path 60      # target + seconds
#   target ∈ ssh-reader | sftp-attrs | sftp-path | pubkey-verify
```

A quick run over all four targets (~20 s each) does ~1.9 M executions at ~19 k exec/s and finds no
crashes. A crashing input is printed and written under `/fuzz/findings/`; mount a volume
(`-v "$PWD/findings:/fuzz/findings"`) to keep it.

## Run it natively (Linux)

If you already have a Linux toolchain:

```bash
dotnet tool install --global SharpFuzz.CommandLine
# Build the libfuzzer-dotnet loader once and put it on PATH:
#   https://github.com/Metalnem/sharpfuzz/blob/master/docs/libFuzzer.md
./fuzz.sh sftp-path        # or ssh-reader | sftp-attrs | pubkey-verify
```

Crashing inputs (if any) are written to `findings/<target>/`. Reproduce a finding by feeding the
file back to the robustness test or by running the target binary against it.

## Everyday coverage: the robustness tests

The same targets are exercised cross-platform, with no external tooling, by
`FuzzRobustnessTests` in `Rst.Ssh.Tests`: tens of thousands of random, edge-case and mutated
inputs per target on every `dotnet test` run. That is what guards the parsers in CI; the libFuzzer
harness above is for deeper, coverage-guided campaigns.
