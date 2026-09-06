using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

using uniffi.votport_client_core;

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
        // The preview line's brush is assigned in code, so a theme flip
        // repaints it here rather than through ThemeResource.
        ActualThemeChanged += (_, _) => Refresh();
        previewer = new LinkPreviewer(LinkKind.Request, Refresh);
        Paths.ItemsSource = paths;
        paths.CollectionChanged += (_, _) => Refresh();
        LinkBox.TextChanged += (_, _) => previewer.Update(LinkBox.Text);
        Loaded += (_, _) => PortStore.Shared.Changed += ShipTo;
        Unloaded += (_, _) => PortStore.Shared.Changed -= ShipTo;
        ShipTo();
        if (TransferStore.Shared.PrefillSend is string link)
        {
            LinkBox.Text = link;
            TransferStore.Shared.PrefillSend = null;
            // Set before the box is loaded, so no TextChanged fires for it.
            previewer.Update(link);
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
        PreviewText.Foreground = Theme.Brush(this, previewer.IsProblem ? "VotDanger" : "VotMuted");
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

    /// The port's open request links behind the Ship to button.
    private void ShipTo()
    {
        var requests = PortStore.Shared.Requests;
        ShipToButton.Visibility = requests.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        // An open flyout keeps its items until it closes.
        if (ShipToMenu.IsOpen) return;
        ShipToMenu.Items.Clear();
        foreach (var request in requests)
        {
            var item = new MenuFlyoutItem { Text = request.Label };
            item.Click += (_, _) => LinkBox.Text = request.Url;
            ShipToMenu.Items.Add(item);
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
