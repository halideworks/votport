using System.Diagnostics;
using Microsoft.Win32;

namespace Votport;

/// The votport: protocol. A packaged app registers it through the manifest;
/// an unpackaged build registers it for the current user at first launch.
public static class Protocol
{
    public static void RegisterIfUnpackaged()
    {
        try
        {
            if (IsPackaged() || Environment.ProcessPath is not string exe) return;
            // A claim an earlier build left through the SDK shadows the keys
            // below; its own try, so a throw here never skips them.
            try { Microsoft.Windows.AppLifecycle.ActivationRegistrationManager.UnregisterForProtocolActivation("votport", null); }
            catch (Exception) { }
            // The classic protocol keys, not the App SDK's
            // RegisterForProtocolActivation: on Windows 11 26200 the SDK's
            // RegisteredApplications claim never launched the app from the
            // shell and shadowed these keys while it existed. The
            // ----ms-protocol: marker is what the SDK's activation parser
            // looks for, so AppInstance still reports a Protocol activation
            // and redirects it to the running instance.
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\votport");
            key.SetValue("", "URL:votport");
            key.SetValue("URL Protocol", "");
            using var icon = key.CreateSubKey("DefaultIcon");
            icon.SetValue("", Path.Combine(AppContext.BaseDirectory, "Assets", "tray.ico"));
            using var command = key.CreateSubKey(@"shell\open\command");
            command.SetValue("", Command(exe));
        }
        catch (Exception)
        {
            // Registration is a convenience for the web pages' links; the
            // app works without it.
        }
    }

    /// The uninstall entry point. An unpackaged launch rewrites the protocol
    /// command, the Run value and the toast AUMID on every start, and
    /// nothing removed them, so a deleted folder left dead links, a failing
    /// Run entry and a stale AUMID. This removes all three.
    public static void UnregisterIfUnpackaged()
    {
        try
        {
            if (IsPackaged()) return;
            // Inline the Run-value removal: Protocol.cs compiles into the
            // activation test project, which does not carry Settings.cs.
            using (var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
            {
                // The value name and shape Settings writes; keep in sync.
                run.DeleteValue("Votport", throwOnMissingValue: false);
            }
            try { Microsoft.Windows.AppLifecycle.ActivationRegistrationManager.UnregisterForProtocolActivation("votport", null); }
            catch (Exception) { }
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\votport", throwOnMissingSubKey: false);
            // The toast AUMID key the App SDK's Register wrote. Unpackaged,
            // the SDK names the AUMID from the executable's FileDescription,
            // falling back to the file name; drift there leaves a cosmetic
            // key behind, nothing worse.
            if (Environment.ProcessPath is string exe)
            {
                var aumid = FileVersionInfo.GetVersionInfo(exe).FileDescription;
                if (string.IsNullOrEmpty(aumid)) aumid = Path.GetFileNameWithoutExtension(exe);
                Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\AppUserModelId\{aumid}", throwOnMissingSubKey: false);
            }
        }
        catch (Exception)
        {
            // The registrations are conveniences; a refused removal still
            // leaves the app working.
        }
    }

    internal static string Command(string executable) => $"\"{executable}\" \"----ms-protocol:%1\"";

    private static bool IsPackaged()
    {
        try { return Windows.ApplicationModel.Package.Current is not null; }
        catch (Exception) { return false; }
    }
}
