using Votport;

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static Exception BuildException()
{
    try
    {
        throw new ArgumentException("inner https://example.invalid/s/inner-capability inner-bare-token");
    }
    catch (Exception inner)
    {
        return new InvalidOperationException(
            "outer https://example.invalid/r/outer-capability outer-bare-token",
            inner);
    }
}

var root = Path.Combine(Path.GetTempPath(), $"votport-crashlog-{Guid.NewGuid():N}");
Directory.CreateDirectory(root);
try
{
    var exception = BuildException();
    CrashLog.Append(exception, root);
    var logPath = Path.Combine(root, "Votport", "votport-crash.log");
    var log = File.ReadAllText(logPath);

    foreach (var secret in new[]
    {
        "https://example.invalid/s/inner-capability",
        "https://example.invalid/r/outer-capability",
        "inner-bare-token",
        "outer-bare-token",
    })
        Check(!log.Contains(secret, StringComparison.Ordinal), $"log retained exception payload: {secret}");

    Check(log.Contains(nameof(InvalidOperationException), StringComparison.Ordinal),
        "log omitted the outer exception type");
    Check(log.Contains(nameof(ArgumentException), StringComparison.Ordinal),
        "log omitted the inner exception type");
    Check(log.Contains("hresult=0x80131509", StringComparison.Ordinal),
        "log omitted the exception HRESULT");
    Check(log.Contains(nameof(BuildException), StringComparison.Ordinal),
        "log omitted useful stack frames");

    // A missing LocalApplicationData value and an unwritable root are both
    // ordinary failure modes for best-effort crash reporting.
    CrashLog.Append(exception, null);
    var blocked = Path.Combine(root, "not-a-directory");
    File.WriteAllText(blocked, "fixture");
    CrashLog.Append(exception, blocked);
    Console.WriteLine("Crash log privacy and failure containment checks passed.");
}
finally
{
    Directory.Delete(root, recursive: true);
}
