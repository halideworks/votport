using System.Runtime.InteropServices;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using uniffi.votport_client_core;

namespace Votport;

/// Done and failed toasts through the app notification manager, when the
/// setting allows.
public static class Notifier
{
    private static bool registered;

#if VOTPORT_UNPACKAGED
    private const uint SndAsync = 0x00000001, SndNoDefault = 0x00000002,
        SndFilename = 0x00020000, SndSystem = 0x00200000;

    private static bool CanPlaySound(bool enabled, int queryResult, int state) =>
        enabled && queryResult == 0 && state == 5; // QUNS_ACCEPTS_NOTIFICATIONS

    [DllImport("shell32.dll")]
    private static extern int SHQueryUserNotificationState(out int state);

    [DllImport("winmm.dll", EntryPoint = "PlaySoundW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PlaySound(string file, IntPtr module, uint flags);
#endif

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
#if VOTPORT_UNPACKAGED
                .MuteAudio()
#else
                .SetAudioUri(new Uri("ms-appx:///Assets/completion.wav"))
#endif
                .BuildNotification();
            AppNotificationManager.Default.Show(toast);
#if VOTPORT_UNPACKAGED
            var queryResult = SHQueryUserNotificationState(out var state);
            if (CanPlaySound(AppNotificationManager.Default.Setting == AppNotificationSetting.Enabled,
                queryResult, state))
            {
                // Use the system notification audio session, without a default beep.
                PlaySound(System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "completion.wav"),
                    IntPtr.Zero, SndFilename | SndAsync | SndNoDefault | SndSystem);
            }
#endif
        }
        catch (Exception)
        {
            // An unpackaged debug build without a registered AUMID cannot
            // toast; the transfer list still shows the outcome.
        }
    }
}
