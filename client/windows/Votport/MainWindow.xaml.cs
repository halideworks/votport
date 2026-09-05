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
        // The taskbar and Alt-Tab icon; the executable's own icon does not
        // reach an unpackaged WinUI window.
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "tray.ico"));
        // A first window at the shell's default size fills a 4K display;
        // Resize takes physical pixels, so the size follows the DPI.
        var scale = GetDpiForWindow(WinRT.Interop.WindowNative.GetWindowHandle(this)) / 96.0;
        AppWindow.Resize(new Windows.Graphics.SizeInt32((int)(900 * scale), (int)(580 * scale)));
        if (AppWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter sized)
        {
            sized.PreferredMinimumWidth = (int)(720 * scale);
            sized.PreferredMinimumHeight = (int)(460 * scale);
        }
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBar);
        PaintCaptionButtons();
        if (Content is FrameworkElement root) root.ActualThemeChanged += (_, _) => PaintCaptionButtons();
        // Closing hides to the tray when the setting says so; Quit in the
        // tray menu is the way out then, and a running transfer carries on.
        AppWindow.Closing += (_, args) =>
        {
            if (!Settings.CloseToTray) return;
            args.Cancel = true;
            AppWindow.Hide();
        };
        Closed += (_, _) => tray.Dispose();
    }

    /// The system caption buttons sit on the app's own title bar, so they
    /// take the theme's colours from the generated token dictionary.
    private void PaintCaptionButtons()
    {
        if (Content is not FrameworkElement root) return;
        var bar = AppWindow.TitleBar;
        var dark = root.ActualTheme != ElementTheme.Light;
        var muted = Theme.Color(root, "VotMuted");
        var text = Theme.Color(root, "VotText");
        var hoverBackground = dark ? Windows.UI.Color.FromArgb(0x14, 255, 255, 255) : Windows.UI.Color.FromArgb(0x14, 0x0F, 0x17, 0x2A);
        bar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        bar.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        bar.ButtonHoverBackgroundColor = hoverBackground;
        bar.ButtonForegroundColor = muted;
        bar.ButtonInactiveForegroundColor = muted;
        bar.ButtonHoverForegroundColor = text;
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

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);
}
