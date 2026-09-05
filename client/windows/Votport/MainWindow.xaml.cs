using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Votport;

public sealed partial class MainWindow : Window
{
    private readonly Tray tray;

    public MainWindow()
    {
        InitializeComponent();
        tray = new Tray(
            Path.Combine(AppContext.BaseDirectory, "Assets", "tray.ico"),
            open: () => DispatcherQueue.TryEnqueue(Raise),
            quit: () => DispatcherQueue.TryEnqueue(() => { tray!.Dispose(); Application.Current.Exit(); }),
            statusLines: () => TransferStore.Shared.Items.Where(item => item.Running).Select(Format.MenuLine).ToList());
        TransferStore.Shared.ActiveChanged += count =>
        {
            ActiveBadge.Value = count;
            ActiveBadge.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
            tray.SetTip(count == 0 ? "votport" : $"votport, {count} active");
        };
        Nav.SelectedItem = Nav.MenuItems[0];
        Closed += (_, _) => tray.Dispose();
    }

    /// Brings the window to the front, restoring it when minimized, which
    /// Activate alone does not.
    public void Raise()
    {
        if (AppWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter presenter
            && presenter.State == Microsoft.UI.Windowing.OverlappedPresenterState.Minimized)
        {
            presenter.Restore();
        }
        AppWindow.Show();
        Activate();
    }

    /// Shows a section. Selecting it navigates; when it is already selected
    /// (which fires no change event) this navigates itself, so a prefill
    /// handed in by a votport: link is read by a fresh page either way.
    public void Show(string section)
    {
        var target = Nav.MenuItems.OfType<NavigationViewItem>().First(nav => (string)nav.Tag == section);
        if (ReferenceEquals(Nav.SelectedItem, target)) Pages.Navigate(PageFor(section));
        else Nav.SelectedItem = target;
    }

    private static Type PageFor(string? tag) => tag switch
    {
        "receive" => typeof(ReceivePage),
        "transfers" => typeof(TransfersPage),
        "settings" => typeof(SettingsPage),
        _ => typeof(SendPage),
    };

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        Pages.Navigate(PageFor((string?)(args.SelectedItem as NavigationViewItem)?.Tag));
    }
}
