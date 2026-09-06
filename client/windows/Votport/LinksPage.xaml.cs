using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using uniffi.votport_client_core;

namespace Votport;

/// The port's links: the request links senders ship to, and the deliveries
/// recipients pull. Issue a request here; close or revoke what is done.
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
            uint.TryParse(ExpiresBox.Text.Trim(), out var days) ? days : null,
            double.TryParse(CapBox.Text.Trim(), out var gb) && double.IsFinite(gb) && gb >= 0 && gb <= 1_000_000 ? (ulong)(gb * 1_000_000_000) : null);
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
        if (issued is not null) Copy(issued);
    }

    private void CopyRequest_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is RequestItem item) Copy(item.Url);
    }

    private void CloseRequest_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is RequestItem item) PortStore.Shared.CloseRequest(item.Id);
    }

    private void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is DeliveryItem item) PortStore.Shared.RevokeDelivery(item.Id);
    }

    public static void Copy(string text)
    {
        var package = new DataPackage();
        package.SetText(text);
        Clipboard.SetContent(package);
    }
}
