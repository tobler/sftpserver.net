# Coverage-guided fuzzing of the SSH/SFTP parsers with SharpFuzz + libFuzzer.
# libFuzzer needs Linux, so this runs the fuzzer in a container (also handy on macOS/Windows).
#
# Build (from the repository root):
#   docker build -f tests/Rst.Ssh.Fuzz/Dockerfile -t rstssh-fuzz .
# Run one target (target = ssh-reader | sftp-attrs | sftp-path | pubkey-verify; seconds optional):
#   docker run --rm rstssh-fuzz sftp-path 60
FROM mcr.microsoft.com/dotnet/sdk:8.0

# clang + the compiler-rt libFuzzer runtime (libclang-rt-*-dev ships it, incl. arm64) to build the loader.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-rt-14-dev curl \
 && rm -rf /var/lib/apt/lists/*

# SharpFuzz instrumentation tool.
RUN dotnet tool install --global SharpFuzz.CommandLine
ENV PATH="${PATH}:/root/.dotnet/tools"

# Build the libfuzzer-dotnet loader from the upstream source.
RUN curl -sSL https://raw.githubusercontent.com/Metalnem/libfuzzer-dotnet/master/libfuzzer-dotnet.cc -o /tmp/libfuzzer-dotnet.cc \
 && clang -fsanitize=fuzzer /tmp/libfuzzer-dotnet.cc -o /usr/local/bin/libfuzzer-dotnet

WORKDIR /src
COPY . .

# Publish the harness, then instrument the parser assembly (not the harness itself).
RUN dotnet publish tests/Rst.Ssh.Fuzz -c Release -o /fuzz/bin \
 && sharpfuzz /fuzz/bin/Rst.Ssh.dll

COPY tests/Rst.Ssh.Fuzz/docker-entrypoint.sh /usr/local/bin/fuzz-entrypoint.sh
RUN chmod +x /usr/local/bin/fuzz-entrypoint.sh

WORKDIR /fuzz
ENTRYPOINT ["/usr/local/bin/fuzz-entrypoint.sh"]
