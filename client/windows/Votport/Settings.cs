using Microsoft.Win32;

namespace Votport;

/// The few things the user can set, kept in the registry under the app's key
/// so an unpackaged build has somewhere to write.
public static class Settings
{
    private const string Key = @"Software\Halideworks\Votport";

    public static string ReceiveFolder
    {
        get => Read("ReceiveFolder") ?? "";
        set => Write("ReceiveFolder", value);
    }

    public static bool Notify
    {
        get => Read("Notify") != "0";
        set => Write("Notify", value ? "1" : "0");
    }

    /// Closing the window hides it to the tray; Quit in the tray menu ends
    /// the app. On by default, so a transfer survives a reflexive close.
    public static bool CloseToTray
    {
        get => Read("CloseToTray") != "0";
        set => Write("CloseToTray", value ? "1" : "0");
    }

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// Start with Windows, through the per-user Run key (no elevation, no
    /// task scheduler); the value is the executable's current path.
    public static bool StartWithWindows
    {
        get => Registry.CurrentUser.OpenSubKey(RunKey)?.GetValue("Votport") is string;
        set
        {
            using var run = Registry.CurrentUser.CreateSubKey(RunKey);
            if (value && Environment.ProcessPath is string exe) run.SetValue("Votport", $"\"{exe}\" --minimized");
            else run.DeleteValue("Votport", throwOnMissingValue: false);
        }
    }

    private static string? Read(string name) =>
        Registry.CurrentUser.OpenSubKey(Key)?.GetValue(name) as string;

    private static void Write(string name, string value) =>
        Registry.CurrentUser.CreateSubKey(Key).SetValue(name, value);
}
