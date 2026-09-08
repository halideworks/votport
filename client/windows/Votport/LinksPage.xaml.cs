using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using uniffi.votport_client_core;

namespace Votport;

/// The port's links: the request links senders ship to, and the deliveries
/// recipients pull. Each section opens with its issue form: the request
/// form inline, the delivery browser as its own page.
public sealed partial class LinksPage : Page
{
    private string? issued;

    public LinksPage()
    {
        InitializeComponent();
        RequestList.ItemsSource = PortStore.Shared.Requests;
        DeliveryList.ItemsSource = PortStore.Shared.Deliveries;
        Loaded += (_, _) => PortStore.Shared.Changed += Refresh;
        Unloaded += (_, _) => PortStore.Shared.Changed -= Refresh;
        ActualThemeChanged += (_, _) => Refresh();
        LabelBox.TextChanged += (_, _) => Refresh();
        Numeric.Integer(ExpiresBox);
        PortStore.Shared.Refresh();
        Refresh();
    }

    private void Refresh()
    {
        var port = PortStore.Shared;
        NoRequests.Visibility = port.Requests.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        NoDeliveries.Visibility = port.Deliveries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        IssueButton.IsEnabled = !port.Busy && LabelBox.Text.Trim().Length > 0;
        var problem = port.ProblemFor(PortStore.Scope.Links);
        ProblemText.Text = problem ?? "";
        ProblemText.Visibility = problem is null ? Visibility.Collapsed : Visibility.Visible;
        ProblemText.Foreground = Theme.Brush(this, "VotDanger");
        IssuedPanel.Visibility = issued is null ? Visibility.Collapsed : Visibility.Visible;
        IssuedText.Text = issued ?? "";
    }

    private void Issue_Click(object sender, RoutedEventArgs e)
    {
        // Positional: the generated record constructor names its parameters
        // after the Rust fields, which the compiler does not accept as named.
        var spec = new RequestSpec(
            LabelBox.Text.Trim(),
            RequestPasswordBox.Password.Length == 0 ? null : RequestPasswordBox.Password,
            Numeric.Whole(ExpiresBox),
            // No Minimum on the box: a 0.5 GB cap is ordinary, and 0 or less
            // means the port's own cap, as it does on the Mac.
            CapBox.Value is var gb && double.IsFinite(gb) && gb > 0 && gb <= 1_000_000 ? (ulong)(gb * 1_000_000_000) : null);
        PortStore.Shared.IssueRequest(spec, link =>
        {
            if (link is null) return;
            issued = link.Url;
            Copy(link.Url);
            LabelBox.Text = "";
            RequestPasswordBox.Password = "";
            Refresh();
        });
    }

    private void CopyIssued_Click(object sender, RoutedEventArgs e)
    {
        if (issued is not null) Copy(issued, sender as Button);
    }

    private void CopyRequest_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is RequestItem item) Copy(item.Url, sender as Button);
    }

    private void NewDelivery_Click(object sender, RoutedEventArgs e)
    {
        App.Window?.Show("share");
    }

    private void CloseRequest_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is RequestItem item) PortStore.Shared.CloseRequest(item.Id);
    }

    private void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is DeliveryItem item) PortStore.Shared.RevokeDelivery(item.Id);
    }

    /// Copies the text; a button that asked says "Copied" for a moment.
    public static void Copy(string text, Button? button = null)
    {
        var package = new DataPackage();
        package.SetText(text);
        Clipboard.SetContent(package);
        // A second click inside the two seconds copies again and leaves
        // the first timer to restore the label.
        if (button is null || (string?)button.Content == "Copied") return;
        var label = button.Content;
        button.Content = "Copied";
        var timer = button.DispatcherQueue.CreateTimer();
        timer.Interval = TimeSpan.FromSeconds(2);
        timer.IsRepeating = false;
        timer.Tick += (_, _) => button.Content = label;
        timer.Start();
    }
}
