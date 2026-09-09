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
        AgentAccess.Visibility = port.SignedIn ? Visibility.Visible : Visibility.Collapsed;
        AgentIssue.IsEnabled = !port.Busy;
        if (!port.SignedIn) { AgentTokenValue.Text = ""; AgentResult.Visibility = Visibility.Collapsed; }
        var agentProblem = port.ProblemFor(PortStore.Scope.Agents);
        AgentProblem.Text = agentProblem ?? "";
        AgentProblem.Visibility = agentProblem is null ? Visibility.Collapsed : Visibility.Visible;
        AgentProblem.Foreground = Theme.Brush(this, "VotDanger");
        AgentTokens.Children.Clear();
        if (port.SignedIn) foreach (var token in port.AutomationTokens)
        {
            var row = new StackPanel { Spacing = 3 };
            row.Children.Add(new TextBlock { Text = token.Label });
            row.Children.Add(new TextBlock { Text = token.Directory ?? "Any folder" });
            row.Children.Add(new TextBlock { Text = string.Join(", ", token.Permissions.Select(p => p switch { "library:read" => "Browse files", "deliveries:create" => "Create deliveries", "deliveries:read" => "Read activity", "deliveries:revoke" => "Revoke deliveries", _ => p })), TextWrapping = TextWrapping.Wrap });
            row.Children.Add(new TextBlock { Text = $"Expires {DateTimeOffset.FromUnixTimeSeconds((long)token.ExpiresAt):g}" });
            if (token.LastUsedAt is ulong used) row.Children.Add(new TextBlock { Text = $"Last used {DateTimeOffset.FromUnixTimeSeconds((long)used):g}" });
            if (token.RevokedAt is not null) row.Children.Add(new TextBlock { Text = "Revoked" });
            else
            {
                var button = new Button { Content = "Revoke token", IsEnabled = !port.Busy };
                Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, $"Revoke token for {token.Label}");
                button.Click += async (_, _) =>
                {
                    var confirm = new ContentDialog { XamlRoot = XamlRoot, Title = "Revoke agent token", Content = "This agent's automation will stop working.", PrimaryButtonText = "Revoke", CloseButtonText = "Cancel" };
                    if (await confirm.ShowAsync() == ContentDialogResult.Primary) port.RevokeAutomationToken(token.Id);
                };
                row.Children.Add(button);
            }
            AgentTokens.Children.Add(row);
        }

        SignedOut.Visibility = port.SignedIn ? Visibility.Collapsed : Visibility.Visible;
        SignedIn.Visibility = port.SignedIn ? Visibility.Visible : Visibility.Collapsed;
        if (port.Port is Port signed)
        {
            PortText.Text = signed.Tenant.Length == 0 ? $"Signed in to {signed.Base}" : $"Signed in to {signed.Base} (tenant {signed.Tenant})";
        }
        SignInButton.IsEnabled = !port.Busy && !port.SigningInBrowser && BaseBox.Text.Trim().Length > 0 && AdminPasswordBox.Password.Length > 0;
        BaseBox.IsEnabled = !port.SigningInBrowser;
        SsoButton.IsEnabled = !port.Busy && BaseBox.Text.Trim().Length > 0;
        SsoButton.Visibility = port.SigningInBrowser ? Visibility.Collapsed : Visibility.Visible;
        SsoPending.Visibility = port.SigningInBrowser ? Visibility.Visible : Visibility.Collapsed;
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

    private void AgentAccess_Expanding(Expander sender, ExpanderExpandingEventArgs args) => PortStore.Shared.RefreshAutomationTokens();
    private void AgentAccess_Collapsed(Expander sender, ExpanderCollapsedEventArgs args)
    {
        AgentTokenValue.Text = "";
        AgentResult.Visibility = Visibility.Collapsed;
    }
    private void AgentRefresh_Click(object sender, RoutedEventArgs e) => PortStore.Shared.RefreshAutomationTokens();
    private void AgentCopy_Click(object sender, RoutedEventArgs e)
    {
        var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
        data.SetText(AgentTokenValue.Text);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
    }
    private void AgentConfig_Click(object sender, RoutedEventArgs e)
    {
        if (PortStore.Shared.Port is not Port port) return;
        var config = VotportClientCoreMethods.AutomationMcpConfig(System.IO.Path.Combine(AppContext.BaseDirectory, "votport-cli.exe"), port.Base, AgentTokenValue.Text);
        var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
        data.SetText(config);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
    }
    private void AgentIssue_Click(object sender, RoutedEventArgs e)
    {
        var permissions = new List<string>();
        if (AgentBrowse.IsChecked == true) permissions.Add("library:read");
        if (AgentCreate.IsChecked == true) permissions.Add("deliveries:create");
        if (AgentActivity.IsChecked == true) permissions.Add("deliveries:read");
        if (AgentRevoke.IsChecked == true) permissions.Add("deliveries:revoke");
        if (AgentJobsRead.IsChecked == true) permissions.Add("jobs:read");
        if (AgentJobsCreate.IsChecked == true) permissions.Add("jobs:create");
        if (AgentJobsCancel.IsChecked == true) permissions.Add("jobs:cancel");
        if (AgentLabel.Text.Trim().Length == 0 || AgentDirectory.Text.Trim().Length == 0 || !uint.TryParse(AgentDays.Text, out var days) || days is < 1 or > 365 || permissions.Count == 0)
        {
            AgentProblem.Text = "Enter a label, folder, expiry from 1 to 365 days, and at least one allowed action.";
            AgentProblem.Visibility = Visibility.Visible;
            return;
        }
        PortStore.Shared.CreateAutomationToken(new AutomationTokenSpec(AgentLabel.Text.Trim(), AgentDirectory.Text.Trim(), days, permissions.ToArray()), issued =>
        {
            if (issued is null) return;
            AgentTokenValue.Text = issued.Token;
            AgentResult.Visibility = Visibility.Visible;
        });
    }

    private void SignIn_Click(object sender, RoutedEventArgs e)
    {
        PortStore.Shared.SignIn(BaseBox.Text.Trim(), AdminPasswordBox.Password);
        AdminPasswordBox.Password = "";
    }

    private void Sso_Click(object sender, RoutedEventArgs e) => PortStore.Shared.BeginSso(BaseBox.Text.Trim());
    private void CancelSso_Click(object sender, RoutedEventArgs e) => PortStore.Shared.CancelSso();

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
