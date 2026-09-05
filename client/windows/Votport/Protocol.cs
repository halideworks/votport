using Microsoft.Windows.AppLifecycle;

namespace Votport;

/// The votport: protocol. A packaged app registers it through the manifest;
/// an unpackaged build registers it for the current user at first launch.
public static class Protocol
{
    public static void RegisterIfUnpackaged()
    {
        try
        {
            if (IsPackaged()) return;
            var logo = Path.Combine(AppContext.BaseDirectory, "Assets", "Square44x44Logo.png");
            ActivationRegistrationManager.RegisterForProtocolActivation("votport", logo, "votport link", null);
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
