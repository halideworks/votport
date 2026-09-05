using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Votport;

/// The sender page is the drop target: files and folders from Explorer or
/// the clipboard, a request link, and one primary action.
public sealed partial class SendPage : Page
{
    private readonly ObservableCollection<string> paths = new();
    private readonly LinkPreviewer previewer;

    public SendPage()
    {
        InitializeComponent();
        previewer = new LinkPreviewer(Refresh);
        Paths.ItemsSource = paths;
        paths.CollectionChanged += (_, _) => Refresh();
        LinkBox.TextChanged += (_, _) => previewer.Update(LinkBox.Text);
        if (TransferStore.Shared.PrefillSend is string link)
        {
            LinkBox.Text = link;
            TransferStore.Shared.PrefillSend = null;
        }
        Refresh();
    }

    private void Refresh()
    {
        var any = paths.Count > 0;
        Empty.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        Paths.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        ClearButton.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        var line = previewer.Line();
        PreviewText.Text = line ?? "";
        PreviewText.Visibility = line is null ? Visibility.Collapsed : Visibility.Visible;
        PreviewText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources[previewer.IsProblem ? "VotDangerBrush" : "VotMutedBrush"];
        PasswordBox.Visibility = previewer.NeedsPassword ? Visibility.Visible : Visibility.Collapsed;
        SendButton.IsEnabled = any && previewer.Ready;
    }

    private void Add(IEnumerable<IStorageItem> items)
    {
        foreach (var item in items)
        {
            if (item.Path.Length > 0 && !paths.Contains(item.Path)) paths.Add(item.Path);
        }
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.AcceptedOperation = e.DataView.Contains(StandardDataFormats.StorageItems)
            ? DataPackageOperation.Copy
            : DataPackageOperation.None;
    }

    private async void DropZone_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        Add(await e.DataView.GetStorageItemsAsync());
    }

    private async void Choose_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        Add(await picker.PickMultipleFilesAsync());
    }

    private async void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        var folder = await picker.PickSingleFolderAsync();
        if (folder is not null) Add(new[] { folder });
    }

    private async void Paste_Click(object sender, RoutedEventArgs e)
    {
        var data = Clipboard.GetContent();
        if (data.Contains(StandardDataFormats.StorageItems)) Add(await data.GetStorageItemsAsync());
    }

    private void Clear_Click(object sender, RoutedEventArgs e) => paths.Clear();

    private void Send_Click(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password.Length == 0 ? null : PasswordBox.Password;
        TransferStore.Shared.Send(LinkBox.Text, password, paths.ToArray());
        paths.Clear();
        PasswordBox.Password = "";
        App.Window?.Show("transfers");
    }
}
