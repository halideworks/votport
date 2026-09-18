using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;

namespace Votport;

public sealed partial class MainWindow : Window
{
    private readonly Tray tray;

    public MainWindow()
    {
        InitializeComponent();
        tray = new Tray(
            Path.Combine(AppContext.BaseDirectory, "Assets", "tray.ico"),
            panel: () => DispatcherQueue.TryEnqueue(ShowPanel),
            menu: () => DispatcherQueue.TryEnqueue(ShowTrayMenu));
        PortStore.Shared.Changed += () =>
        {
            // The operator items show only for an admin session: a viewer
            // or auditor pressing them only earns a 403.
            var operating = PortStore.Shared.CanOperate;
            ShareItem.Visibility = LinksItem.Visibility = operating ? Visibility.Visible : Visibility.Collapsed;
            // Signing out or a folded role from either operator page lands
            // on Settings.
            if (!operating && Nav.SelectedItem is NavigationViewItem current && ((string)current.Tag == "links" || (string)current.Tag == "share")) Show("settings");
        };
        TransferStore.Shared.ActiveChanged += _ => Indicate();
        // Every view moves the taskbar bar; the tip already re-reads here too.
        TransferStore.Shared.ViewChanged += Indicate;
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
        // The panel is a real window: left open, it would keep the process
        // alive with no icon and no way back.
        Closed += (_, _) => QuitFromTray();
        // Built once the window is up, so the first tray click shows it at
        // once instead of paying for the XAML load then.
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => panel ??= new TrayPanel());
    }

    /// The tray tip and the taskbar bar. The tip carries the last settled
    /// transfer's outcome, so a failure reads differently from idle; the
    /// bar is the active transfers' moved bytes over their totals.
    private void Indicate()
    {
        var store = TransferStore.Shared;
        var count = store.ActiveCount;
        ActiveBadge.Value = count;
        ActiveBadge.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
        var last = store.Items.FirstOrDefault(item => !item.Running);
        tray.SetTip(count == 0
            ? (last is null ? "votport" : $"votport; {Format.StatusLine(last)}")
            : $"votport, {count} active" + (last is null ? "" : $"; {Format.StatusLine(last)}"));
        ulong moved = 0, total = 0;
        foreach (var item in store.Items.Where(item => item.Running))
        {
            moved += item.View?.MovedBytes ?? 0;
            total += item.View?.TotalBytes ?? 0;
        }
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (total > 0)
        {
            Taskbar.SetProgressState(hwnd, TaskbarState.Normal);
            Taskbar.SetProgressValue(hwnd, moved, total);
        }
        else
        {
            Taskbar.SetProgressState(hwnd, TaskbarState.NoProgress);
        }
    }

    /// Taskbar progress through the Win32 taskbar interface: the App SDK's
    /// AppWindow carries no taskbar surface, so the shell talks to
    /// ITaskbarList3 directly.
    private static class Taskbar
    {
        private static readonly ITaskbarList3 Instance = (ITaskbarList3)new TaskbarInstance();

        public static void SetProgressValue(IntPtr hwnd, ulong completed, ulong total) =>
            Instance.SetProgressValue(hwnd, completed, total);

        public static void SetProgressState(IntPtr hwnd, TaskbarState state) =>
            Instance.SetProgressState(hwnd, state);

        [ComImport, Guid("ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf")]
        private class TaskbarInstance;

        [ComImport, Guid("56FDF344-FD6D-11d0-958A-006097C9A090"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ITaskbarList3
        {
            // Vtable order: ITaskbarList, ITaskbarList2, then the progress
            // members. Only the two progress members are called.
            [PreserveSig] int HrInit();
            [PreserveSig] int AddTab(IntPtr hwnd);
            [PreserveSig] int DeleteTab(IntPtr hwnd);
            [PreserveSig] int ActivateTab(IntPtr hwnd);
            [PreserveSig] int SetActiveAlt(IntPtr hwnd);
            [PreserveSig] int MarkFullscreenWindow(IntPtr hwnd, [MarshalAs(UnmanagedType.Bool)] bool fullscreen);
            void SetProgressValue(IntPtr hwnd, ulong completed, ulong total);
            void SetProgressState(IntPtr hwnd, TaskbarState state);
        }
    }

    private enum TaskbarState : uint
    {
        NoProgress = 0,
        Normal = 2,
    }

    /// Ends the app from the tray or the panel: the icon goes first, so no
    /// stale icon lingers in the notification area.
    public void QuitFromTray()
    {
        tray.Dispose();
        var open = panel;
        panel = null;
        open?.Close();
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

    internal void ShowActivationError(string? message)
    {
        ActivationError.Message = message ?? "";
        ActivationError.IsOpen = message is not null;
    }

    /// Shows a section. Selecting it navigates; when it is already selected
    /// (which fires no change event) this navigates itself, so a prefill
    /// handed in by a votport: link is read by a fresh page either way.
    public void Show(string section)
    {
        var target = Nav.MenuItems.OfType<NavigationViewItem>().First(nav => (string)nav.Tag == section);
        if (ReferenceEquals(Nav.SelectedItem, target)) Navigate(PageFor(section));
        else Nav.SelectedItem = target;
    }

    private TrayPanel? panel;

    /// The tray panel, made on first use and shown above the tray.
    private void ShowTrayMenu()
    {
        panel ??= new TrayPanel();
        panel.ShowContextMenu();
    }

    private void ShowPanel()
    {
        panel ??= new TrayPanel();
        panel.ToggleNearTray();
    }

    private static Type PageFor(string? tag) => tag switch
    {
        "receive" => typeof(ReceivePage),
        "share" => typeof(DeliverPage),
        "links" => typeof(LinksPage),
        "transfers" => typeof(TransfersPage),
        "settings" => typeof(SettingsPage),
        "workflows" => typeof(WorkflowsPage),
        _ => typeof(SendPage),
    };

    // A click raises ItemInvoked (with SelectedItem already updated) and
    // then, for a new item, SelectionChanged; both navigate only when the
    // frame shows a different page, so a click lands one page. A click on
    // the selected item raises ItemInvoked alone, which is what brings
    // Links back over its Deliver page.
    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        ShowIfDifferent(PageFor((string?)(args.SelectedItem as NavigationViewItem)?.Tag));
    }

    private void Nav_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        ShowIfDifferent(PageFor((string?)args.InvokedItemContainer?.Tag));
    }

    private void ShowIfDifferent(Type page)
    {
        if (Pages.Content?.GetType() != page) Navigate(page);
    }

    // No page transition: the frame's entrance animation runs alongside the
    // pane's selection indicator and the two stutter on a section switch.
    private void Navigate(Type page) => Pages.Navigate(page, null, new SuppressNavigationTransitionInfo());

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);
}
