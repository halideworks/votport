using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using uniffi.votport_client_core;

namespace Votport;

public sealed partial class SettingsPage : Page
{
    public SettingsPage()
    {
        InitializeComponent();
        NotifySwitch.IsOn = Settings.Notify;
        CoreText.Text = $"Core {VotportClientCoreMethods.CoreVersion()}";
        Refresh();
    }

    private void Refresh()
    {
        var folder = Settings.ReceiveFolder;
        FolderText.Text = folder.Length == 0 ? "Ask each time" : folder;
        ClearButton.Visibility = folder.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void Choose_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.Downloads };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        var picked = await picker.PickSingleFolderAsync();
        if (picked is not null)
        {
            Settings.ReceiveFolder = picked.Path;
            Refresh();
        }
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        Settings.ReceiveFolder = "";
        Refresh();
    }

    private void Notify_Toggled(object sender, RoutedEventArgs e) => Settings.Notify = NotifySwitch.IsOn;
}
