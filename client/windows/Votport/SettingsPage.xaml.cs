using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using uniffi.votport_client_core;

namespace Votport;

public sealed partial class SettingsPage : Page
{
    private readonly LinkPreviewer watchPreviewer;
    private string watchFolder = "";

    public SettingsPage()
    {
        InitializeComponent();
        NotifySwitch.IsOn = Settings.Notify;
        TraySwitch.IsOn = Settings.CloseToTray;
        StartSwitch.IsOn = Settings.StartWithWindows;
        CoreText.Text = $"Core {VotportClientCoreMethods.CoreVersion()}";
        WatchList.ItemsSource = PortStore.Shared.Watches;
        watchPreviewer = new LinkPreviewer(LinkKind.Request, Refresh);
        WatchLinkBox.TextChanged += (_, _) => watchPreviewer.Update(WatchLinkBox.Text);
        BaseBox.TextChanged += (_, _) => Refresh();
        AdminPasswordBox.PasswordChanged += (_, _) => Refresh();
        Loaded += (_, _) => PortStore.Shared.Changed += Refresh;
        Unloaded += (_, _) => PortStore.Shared.Changed -= Refresh;
        ActualThemeChanged += (_, _) => Refresh();
        Refresh();
    }

    private void Refresh()
    {
        var folder = Settings.ReceiveFolder;
        FolderText.Text = folder.Length == 0 ? "Ask each time" : folder;
        ClearButton.Visibility = folder.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

        var port = PortStore.Shared;
        SignedOut.Visibility = port.SignedIn ? Visibility.Collapsed : Visibility.Visible;
        SignedIn.Visibility = port.SignedIn ? Visibility.Visible : Visibility.Collapsed;
        if (port.Port is Port signed)
        {
            PortText.Text = signed.Tenant.Length == 0 ? $"Signed in to {signed.Base}" : $"Signed in to {signed.Base} (tenant {signed.Tenant})";
        }
        SignInButton.IsEnabled = !port.Busy && BaseBox.Text.Trim().Length > 0 && AdminPasswordBox.Password.Length > 0;
        var portProblem = port.ProblemFor(PortStore.Scope.Port);
        PortProblem.Text = portProblem ?? "";
        PortProblem.Visibility = portProblem is null ? Visibility.Collapsed : Visibility.Visible;
        PortProblem.Foreground = Theme.Brush(this, "VotDanger");

        WatchFolderText.Text = watchFolder.Length == 0 ? "No folder chosen" : watchFolder;
        var line = watchPreviewer.Line();
        WatchPreviewText.Text = line ?? "";
        WatchPreviewText.Visibility = line is null ? Visibility.Collapsed : Visibility.Visible;
        WatchPreviewText.Foreground = Theme.Brush(this, watchPreviewer.IsProblem ? "VotDanger" : "VotMuted");
        WatchPasswordBox.Visibility = watchPreviewer.NeedsPassword ? Visibility.Visible : Visibility.Collapsed;
        WatchButton.IsEnabled = !port.Busy && watchFolder.Length > 0 && watchPreviewer.Ready;
        ShipToButton.Visibility = port.Requests.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        var watchProblem = port.ProblemFor(PortStore.Scope.Watch);
        WatchProblem.Text = watchProblem ?? "";
        WatchProblem.Visibility = watchProblem is null ? Visibility.Collapsed : Visibility.Visible;
        WatchProblem.Foreground = Theme.Brush(this, "VotDanger");
        if (ShipToMenu.IsOpen) return;
        ShipToMenu.Items.Clear();
        foreach (var request in port.Requests)
        {
            var item = new MenuFlyoutItem { Text = request.Label };
            item.Click += (_, _) => WatchLinkBox.Text = request.Url;
            ShipToMenu.Items.Add(item);
        }
    }

    private void SignIn_Click(object sender, RoutedEventArgs e)
    {
        PortStore.Shared.SignIn(BaseBox.Text.Trim(), AdminPasswordBox.Password);
        AdminPasswordBox.Password = "";
    }

    private void SignOut_Click(object sender, RoutedEventArgs e) => PortStore.Shared.SignOut();

    private async void ChooseWatch_Click(object sender, RoutedEventArgs e)
    {
        var picked = await PickFolder(PickerLocationId.DocumentsLibrary);
        if (picked is not null)
        {
            watchFolder = picked;
            Refresh();
        }
    }

    private void AddWatch_Click(object sender, RoutedEventArgs e)
    {
        var password = WatchPasswordBox.Password.Length == 0 ? null : WatchPasswordBox.Password;
        PortStore.Shared.AddWatch(watchFolder, WatchLinkBox.Text.Trim(), password, added =>
        {
            // The form clears only once the watch took; a refusal keeps the
            // folder and the link to try again from.
            if (!added) return;
            watchFolder = "";
            WatchLinkBox.Text = "";
            WatchPasswordBox.Password = "";
            Refresh();
        });
    }

    private void RemoveWatch_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is WatchItem item) PortStore.Shared.RemoveWatch(item.Id);
    }

    private async void Choose_Click(object sender, RoutedEventArgs e)
    {
        var picked = await PickFolder(PickerLocationId.Downloads);
        if (picked is not null)
        {
            Settings.ReceiveFolder = picked;
            Refresh();
        }
    }

    private static async Task<string?> PickFolder(PickerLocationId start)
    {
        var picker = new FolderPicker { SuggestedStartLocation = start };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        return (await picker.PickSingleFolderAsync())?.Path;
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        Settings.ReceiveFolder = "";
        Refresh();
    }

    private void Notify_Toggled(object sender, RoutedEventArgs e) => Settings.Notify = NotifySwitch.IsOn;

    private void Tray_Toggled(object sender, RoutedEventArgs e) => Settings.CloseToTray = TraySwitch.IsOn;

    private void Start_Toggled(object sender, RoutedEventArgs e) => Settings.StartWithWindows = StartSwitch.IsOn;
}
