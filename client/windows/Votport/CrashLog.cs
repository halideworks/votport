namespace Votport;

/// Appends an exception to votport-crash.log beside the executable, since a
/// failure in the XAML runtime or on a worker thread otherwise ends the
/// process with no message.
public static class CrashLog
{
    public static void Append(Exception? exception)
    {
        try
        {
            File.AppendAllText(
                Path.Combine(AppContext.BaseDirectory, "votport-crash.log"),
                $"{DateTime.Now:O} {exception?.Message}{Environment.NewLine}{exception}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Nowhere left to report to.
        }
    }
}
