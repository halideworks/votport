using System.Globalization;
using System.Text;

namespace Votport;

/// Appends managed crash metadata to the current user's local application data,
/// excluding exception messages that may contain access links or tokens.
public static class CrashLog
{
    public static void Append(Exception? exception)
    {
        try
        {
            Append(exception, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        }
        catch (Exception)
        {
            // Nowhere left to report to.
        }
    }

    // The console regression links this production source directly and supplies
    // an isolated root; app code always uses the overload above.
    internal static void Append(Exception? exception, string? localAppData)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(localAppData)) return;
            var directory = Path.Combine(localAppData, "Votport");
            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "votport-crash.log"),
                Format(exception),
                Encoding.UTF8);
        }
        catch (Exception)
        {
            // Crash reporting must never become another crash.
        }
    }

    private static string Format(Exception? exception)
    {
        var output = new StringBuilder();
        output.Append(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        if (exception is null)
        {
            output.AppendLine(" type=none hresult=none");
            return output.ToString();
        }

        for (var current = exception; current is not null; current = current.InnerException)
        {
            output.Append(" type=").Append(current.GetType().FullName ?? current.GetType().Name)
                .Append(" hresult=0x")
                .Append(unchecked((uint)current.HResult).ToString("X8", CultureInfo.InvariantCulture))
                .AppendLine();
            output.AppendLine("stack:");
            output.AppendLine(current.StackTrace ?? "none");
        }

        return output.ToString();
    }
}
