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

    private static string? Read(string name) =>
        Registry.CurrentUser.OpenSubKey(Key)?.GetValue(name) as string;

    private static void Write(string name, string value) =>
        Registry.CurrentUser.CreateSubKey(Key).SetValue(name, value);
}
