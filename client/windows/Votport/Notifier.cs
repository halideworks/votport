using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using uniffi.votport_client_core;

namespace Votport;

/// Done and failed toasts through the app notification manager, when the
/// setting allows.
public static class Notifier
{
    private static bool registered;

    public static void TransferEnded(TransferItem item)
    {
        if (!Settings.Notify) return;
        // No view at all is the shell's Failed; a cancel is the user's own.
        if (item.View is { Phase: not (Phase.Done or Phase.Failed) }) return;
        try
        {
            if (!registered)
            {
                AppNotificationManager.Default.Register();
                registered = true;
            }
            var toast = new AppNotificationBuilder()
                .AddText(item.Subject)
                .AddText(Format.StatusLine(item))
                .BuildNotification();
            AppNotificationManager.Default.Show(toast);
        }
        catch (Exception)
        {
            // An unpackaged debug build without a registered AUMID cannot
            // toast; the transfer list still shows the outcome.
        }
    }
}
