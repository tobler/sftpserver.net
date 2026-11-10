namespace Rst.Ssh.Sftp;

/// <summary>
/// Platform-neutral SFTP path: always absolute, "/"-separated, without ".", "..", empty segments or NUL.
/// ".." above the root is clamped at the root (like chroot) – so by construction an SftpPath
/// can never leave the root of the virtual file system.
/// default(SftpPath) is the root "/".
/// </summary>
public readonly struct SftpPath : IEquatable<SftpPath>
{
    private readonly string? _value;

    private SftpPath(string normalized) => _value = normalized;

    public static SftpPath Root => default;

    public string Value => _value ?? "/";
    public bool IsRoot => _value is null or "/";

    /// <summary>Last segment; "" for the root.</summary>
    public string Name => IsRoot ? "" : Value[(Value.LastIndexOf('/') + 1)..];

    /// <summary>Parent directory; the root is its own parent.</summary>
    public SftpPath Parent
    {
        get
        {
            if (IsRoot) return Root;
            var i = Value.LastIndexOf('/');
            return i == 0 ? Root : new SftpPath(Value[..i]);
        }
    }

    public IReadOnlyList<string> Segments => IsRoot ? [] : Value[1..].Split('/');

    /// <summary>
    /// Normalizes a path supplied by the client. Relative paths are resolved against
    /// <paramref name="relativeTo"/> (SFTP v3: the user's home directory).
    /// </summary>
    public static SftpPath Parse(string path, SftpPath relativeTo = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (path.Contains('\0'))
            throw new SftpException(SftpStatus.BadMessage, "Path contains a NUL character");

        var stack = new List<string>();
        if (!path.StartsWith('/'))
            stack.AddRange(relativeTo.Segments);

        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            switch (segment)
            {
                case ".":
                    continue;
                case "..":
                    if (stack.Count > 0) stack.RemoveAt(stack.Count - 1);
                    continue;
                default:
                    stack.Add(segment);
                    break;
            }
        }

        return stack.Count == 0 ? Root : new SftpPath("/" + string.Join('/', stack));
    }

    /// <summary>Appends exactly one name (no "/", no "." or "..").</summary>
    public SftpPath Combine(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name is "." or ".." || name.Contains('/') || name.Contains('\0'))
            throw new ArgumentException($"Invalid name: '{name}'", nameof(name));
        return new SftpPath(IsRoot ? "/" + name : Value + "/" + name);
    }

    public bool Equals(SftpPath other) => string.Equals(Value, other.Value, StringComparison.Ordinal);
    public override bool Equals(object? obj) => obj is SftpPath p && Equals(p);
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);
    public static bool operator ==(SftpPath a, SftpPath b) => a.Equals(b);
    public static bool operator !=(SftpPath a, SftpPath b) => !a.Equals(b);
    public override string ToString() => Value;
}
