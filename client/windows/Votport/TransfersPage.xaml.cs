using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Votport;

/// The transfer list: every transfer of the session, newest first. A
/// selected transfer shows its files; nothing is marked with a border.
public sealed partial class TransfersPage : Page
{
    public TransfersPage()
    {
        InitializeComponent();
        List.ItemsSource = TransferStore.Shared.Items;
        // Every visit is a new page; the handler leaves with it.
        Loaded += (_, _) => TransferStore.Shared.Items.CollectionChanged += OnItemsChanged;
        Unloaded += (_, _) => TransferStore.Shared.Items.CollectionChanged -= OnItemsChanged;
        Refresh();
        if (TransferStore.Shared.Items.Count > 0) List.SelectedIndex = 0;
    }

    private void OnItemsChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e) => Refresh();

    private void Refresh()
    {
        var any = TransferStore.Shared.Items.Count > 0;
        EmptyText.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        List.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
    }

    private void List_ItemClick(object sender, ItemClickEventArgs e) { }

    private void List_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        foreach (var item in TransferStore.Shared.Items) item.Expanded = item == List.SelectedItem;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Cancel(item);
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Remove(item);
    }
}
