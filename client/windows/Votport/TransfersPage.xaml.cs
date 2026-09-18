using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;

namespace Votport;

/// The transfer list: every transfer of the session, newest first. A
/// clicked transfer expands to its files; nothing is selected or marked.
public sealed partial class TransfersPage : Page
{
    public TransfersPage()
    {
        InitializeComponent();
        List.ItemsSource = TransferStore.Shared.Items;
        // Every visit is a new page; the handler leaves with it.
        Loaded += (_, _) =>
        {
            TransferStore.Shared.Items.CollectionChanged += OnItemsChanged;
            TransferStore.Shared.ActiveChanged += OnActiveChanged;
        };
        Unloaded += (_, _) =>
        {
            TransferStore.Shared.Items.CollectionChanged -= OnItemsChanged;
            TransferStore.Shared.ActiveChanged -= OnActiveChanged;
        };
        Refresh();
        if (TransferStore.Shared.Items.FirstOrDefault() is TransferItem first && !TransferStore.Shared.Items.Any(item => item.Expanded))
        {
            first.Expanded = true;
        }
    }

    private void OnItemsChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e) => Refresh();

    private void OnActiveChanged(int _) => Refresh();

    private void Refresh()
    {
        var any = TransferStore.Shared.Items.Count > 0;
        EmptyText.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        List.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        ClearFinishedButton.IsEnabled = TransferStore.Shared.Items.Any(item => !item.Running && !item.Journalled);
    }

    /// A click expands the card and collapses the others; nothing is
    /// selected or marked.
    private void List_ItemClick(object sender, ItemClickEventArgs e)
    {
        var clicked = e.ClickedItem as TransferItem;
        foreach (var item in TransferStore.Shared.Items) item.Expanded = item == clicked && !item.Expanded;
    }

    private void Pause_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Pause(item);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Cancel(item);
    }

    private async void Resume_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not TransferItem item) return;
        // The password box sits beside the button in the same panel.
        var box = ((sender as FrameworkElement)?.Parent as Panel)?.Children.OfType<PasswordBox>().FirstOrDefault();
        var password = box is null || box.Password.Length == 0 ? null : box.Password;
        if (item.NeedsPassword && password is null) return;
        if (box is not null) box.Password = "";
        // The one thing a journalled receive can be asked again: where it
        // lands. The tray's resume takes no answer and keeps the journalled
        // folder.
        string? destination = null;
        if (item.Kind == TransferItem.Kinds.Receive)
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
            var picked = await picker.PickSingleFolderAsync();
            if (picked is null) return;
            destination = picked.Path;
        }
        TransferStore.Shared.Resume(item, password, destination);
    }

    private void Reveal_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item && item.Landed is string landed)
        {
            // A --receive launch may have named a relative folder; explorer
            // wants the full path.
            var path = System.IO.Path.GetFullPath(landed);
            var arguments = item.RevealDestinationFolder ? $"\"{path}\"" : $"/select,\"{path}\"";
            System.Diagnostics.Process.Start("explorer.exe", arguments);
        }
    }

    private void ClearFinished_Click(object sender, RoutedEventArgs e) => TransferStore.Shared.ClearFinished();

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Remove(item);
    }
}
