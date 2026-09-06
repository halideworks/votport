using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Windows.Graphics;

namespace Votport;

/// The tray panel: a small borderless window above the notification area
/// with what is under way, the core's status lines, bars, and Pause,
/// Cancel, or Resume. A left click on the tray icon shows it; clicking
/// anywhere else hides it.
public sealed partial class TrayPanel : Window
{
    private const int WidthDip = 380;
    private const int MaxHeightDip = 520;

    public TrayPanel()
    {
        InitializeComponent();
        List.ItemsSource = TransferStore.Shared.Items;
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
            presenter.IsResizable = false;
            presenter.IsMaximizable = false;
            presenter.IsMinimizable = false;
            presenter.SetBorderAndTitleBar(false, false);
        }
        AppWindow.IsShownInSwitchers = false;
        Activated += (_, e) =>
        {
            // Closing deactivates too; a closed window has no AppWindow.
            if (closing || e.WindowActivationState != WindowActivationState.Deactivated) return;
            HidePanel();
        };
        Closed += (_, _) => closing = true;
        TransferStore.Shared.Items.CollectionChanged += (_, _) => Refresh();
        TransferStore.Shared.ActiveChanged += _ => Refresh();
        Refresh();
    }

    private void Refresh()
    {
        var items = TransferStore.Shared.Items;
        EmptyText.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var active = TransferStore.Shared.ActiveCount;
        Headline.Text = active switch
        {
            0 => "All quiet",
            1 => "1 under way",
            _ => $"{active} under way",
        };
    }

    private long hiddenAt;
    private bool closing;
    /// Tracked here: a never-shown AppWindow reports itself visible.
    private bool shown;

    private void HidePanel()
    {
        AppWindow.Hide();
        shown = false;
        hiddenAt = Environment.TickCount64;
    }

    /// A click on the tray icon while the panel is open: the click's
    /// button-down already deactivated and hid the panel, so the button-up
    /// that reaches the tray must not put it straight back.
    public void ToggleNearTray()
    {
        if (Environment.TickCount64 - hiddenAt < 400) return;
        // A click from the overflow flyout takes no focus, so the panel is
        // still up when the button-up arrives: that click closes it.
        if (shown)
        {
            HidePanel();
            return;
        }
        ShowNearTray();
    }

    /// Shows the panel just above the tray, at the cursor's corner of the
    /// work area, sized to its content, at that monitor's scale.
    public void ShowNearTray()
    {
        GetCursorPos(out var cursor);
        var scale = ScaleAt(cursor);
        var rows = Math.Min(TransferStore.Shared.Items.Count, 5);
        var heightDip = Math.Min(MaxHeightDip, 120 + (rows == 0 ? 30 : rows * 78));
        var width = (int)(WidthDip * scale);
        var height = (int)(heightDip * scale);
        var area = DisplayArea.GetFromPoint(new PointInt32(cursor.X, cursor.Y), DisplayAreaFallback.Nearest).WorkArea;
        var x = Math.Max(area.X, Math.Min(cursor.X - width / 2, area.X + area.Width - width - 8));
        var y = area.Y + area.Height - height - 8;
        AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
        AppWindow.Show();
        shown = true;
        Activate();
    }

    private void Pause_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Pause(item);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Cancel(item);
    }

    private void Resume_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TransferItem item) TransferStore.Shared.Resume(item, null);
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        HidePanel();
        App.Window?.Raise();
    }

    private void Quit_Click(object sender, RoutedEventArgs e)
    {
        closing = true;
        App.Quit();
    }

    /// The scale of the monitor under `point`, which is where the panel is
    /// about to go, not where its window happens to sit now.
    private static double ScaleAt(Point point)
    {
        var monitor = MonitorFromPoint(point, 2 /* MONITOR_DEFAULTTONEAREST */);
        return GetDpiForMonitor(monitor, 0, out var dpiX, out _) == 0 ? dpiX / 96.0 : 1.0;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct Point { public int X; public int Y; }

    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool GetCursorPos(out Point point);
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(Point point, uint flags);
    [System.Runtime.InteropServices.DllImport("shcore.dll")] private static extern int GetDpiForMonitor(IntPtr monitor, int type, out uint dpiX, out uint dpiY);
}
