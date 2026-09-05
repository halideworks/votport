using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;

namespace Votport;

/// The recipient page is the destination picker: a delivery link, a
/// folder, and one primary action. Progress lives in Transfers.
public sealed partial class ReceivePage : Page
{
    private string folder = "";

    public ReceivePage()
    {
        InitializeComponent();
        folder = Settings.ReceiveFolder;
        LinkBox.TextChanged += (_, _) => Refresh();
        if (TransferStore.Shared.PrefillReceive is string link)
        {
            LinkBox.Text = link;
            TransferStore.Shared.PrefillReceive = null;
        }
        Refresh();
    }

    private void Refresh()
    {
        FolderText.Text = folder.Length == 0 ? "No folder chosen" : folder;
        ReceiveButton.IsEnabled = folder.Length > 0 && LinkBox.Text.Length > 0;
    }

    private async void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.Downloads };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        var picked = await picker.PickSingleFolderAsync();
        if (picked is not null)
        {
            folder = picked.Path;
            Refresh();
        }
    }

    private void Receive_Click(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password.Length == 0 ? null : PasswordBox.Password;
        TransferStore.Shared.Receive(LinkBox.Text, password, folder);
        LinkBox.Text = "";
        PasswordBox.Password = "";
        App.Window?.Show("transfers");
    }
}
