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
            command.SetValue("", $"\"{exe}\" ----ms-protocol:%1");
        }
        catch (Exception)
        {
            // Registration is a convenience for the web pages' links; the
            // app works without it.
        }
    }

    private static bool IsPackaged()
    {
        try { return Windows.ApplicationModel.Package.Current is not null; }
        catch (Exception) { return false; }
    }
}
