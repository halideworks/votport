using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using uniffi.votport_client_core;
using Windows.ApplicationModel.DataTransfer;

namespace Votport;

public sealed partial class WorkflowsPage : Page
{
    private readonly StackPanel body = new() { Spacing = 16, Padding = new Thickness(24) };
    private readonly StackPanel jobs = new() { Spacing = 14 };
    private readonly StackPanel evidence = new() { Spacing = 14 };
    private readonly StackPanel metadata = new() { Spacing = 8 };
    private readonly StackPanel recipients = new() { Spacing = 6 };
    private readonly ComboBox project = new() { Header = "Project", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox label = new() { Header = "Delivery label", MaxLength = 200 };
    private readonly TextBox days = new() { Header = "Expires after (days)", Text = "7" };
    private readonly TextBlock problem = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private IReadOnlyList<WorkflowProject> projects = Array.Empty<WorkflowProject>();
    private string operation = Guid.NewGuid().ToString();
    private string? cursor;
    private bool busy;

    public WorkflowsPage()
    {
        InitializeComponent();
        Content = new ScrollViewer { Content = body };
        body.Children.Add(Text("Delivery workflows", 24));
        body.Children.Add(problem);
        body.Children.Add(Action("Refresh", () => Refresh()));
        if (PortStore.Shared.SignedIn)
        {
            body.Children.Add(Action("Projects, reception routes, storage and events", () =>
            {
                var address = PortStore.Shared.Port!.Base.TrimEnd('/') + "/workflows";
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(address) { UseShellExecute = true });
                return Task.CompletedTask;
            }));
            body.Children.Add(project); body.Children.Add(label); body.Children.Add(days);
            body.Children.Add(metadata); body.Children.Add(recipients);
            body.Children.Add(Action("Queue delivery", Create));
            body.Children.Add(Action("Start a separate delivery", () => { operation = Guid.NewGuid().ToString(); problem.Text = "Ready to create a separate delivery."; return Task.CompletedTask; }));
            body.Children.Add(Text("Jobs", 20)); body.Children.Add(jobs);
            body.Children.Add(Action("Load more jobs", () => LoadJobs(true)));
        }
        body.Children.Add(Text("Recipient verification and acceptance", 20));
        body.Children.Add(Text("Accept a delivery only after reviewing the verified files. Acceptance signs the exact manifest shown here."));
        body.Children.Add(Action("Copy this device's public key", async () => Copy(await Task.Run(VotportClientCoreMethods.RecipientDeviceKey))));
        body.Children.Add(Action("Retry pending reports", async () => { await Task.Run(VotportClientCoreMethods.RetryEvidence); await LoadEvidence(); }));
        body.Children.Add(evidence);
        project.SelectionChanged += (_, _) => ProjectFields();
        Loaded += async (_, _) => await Run(Refresh);
    }

    private static TextBlock Text(string value, double size = 14) => new() { Text = value, FontSize = size, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private Button Action(string title, Func<Task> action)
    {
        var button = new Button { Content = title };
        button.Click += async (_, _) => await Run(action);
        return button;
    }
    private async Task Run(Func<Task> action)
    {
        if (busy) return;
        busy = true; problem.Text = "";
        try { await action(); }
        catch (Exception error) { problem.Text = error.Message; }
        finally { busy = false; }
    }
    private static void Copy(string value)
    {
        var data = new DataPackage(); data.SetText(value); Clipboard.SetContent(data);
    }
    private async Task Refresh()
    {
        await LoadEvidence();
        if (!PortStore.Shared.SignedIn) return;
        var selected = (project.SelectedItem as ComboBoxItem)?.Tag as string;
        projects = await Task.Run(VotportClientCoreMethods.WorkflowProjects);
        project.Items.Clear();
        foreach (var item in projects) project.Items.Add(new ComboBoxItem { Content = item.Label, Tag = item.Id });
        project.SelectedIndex = Math.Max(0, projects.ToList().FindIndex(item => item.Id == selected));
        await LoadJobs(false);
    }
    private void ProjectFields()
    {
        metadata.Children.Clear(); recipients.Children.Clear();
        var current = projects.FirstOrDefault(item => item.Id == (project.SelectedItem as ComboBoxItem)?.Tag as string);
        if (current is null) return;
        metadata.Children.Add(Text($"{current.Directory} · {(current.RequireApproval ? "Approval required" : "No approval required")}"));
        foreach (var key in current.RequiredMetadata) metadata.Children.Add(new TextBox { Header = key, Tag = key, MaxLength = 4096 });
        foreach (var recipient in current.Recipients) recipients.Children.Add(new CheckBox { Content = $"{recipient.Email} ({recipient.Holder[..12]}…)", Tag = recipient.Holder });
    }
    private async Task Create()
    {
        var id = (project.SelectedItem as ComboBoxItem)?.Tag as string;
        if (id is null || string.IsNullOrWhiteSpace(label.Text) || !ulong.TryParse(days.Text, out var expiry) || expiry is < 1 or > 365) throw new InvalidOperationException("Choose a project, label and expiry from 1 to 365 days.");
        var fields = metadata.Children.OfType<TextBox>().ToDictionary(item => (string)item.Tag, item => item.Text);
        if (fields.Values.Any(string.IsNullOrWhiteSpace)) throw new InvalidOperationException("Complete the required metadata fields.");
        var selected = recipients.Children.OfType<CheckBox>().Where(item => item.IsChecked == true).Select(item => (string)item.Tag).ToArray();
        var spec = new WorkflowJobSpec(operation, id, label.Text.Trim(), fields, selected, expiry, null, null);
        var issued = await Task.Run(() => VotportClientCoreMethods.CreateWorkflowJob(spec));
        problem.Text = $"Job {issued.Id}: {issued.State.Replace('_', ' ')}. Refresh to follow its progress.";
        await LoadJobs(false);
    }
    private async Task LoadJobs(bool more)
    {
        if (more && cursor is null) return;
        var page = await Task.Run(() => VotportClientCoreMethods.WorkflowJobs(more ? cursor : null));
        cursor = page.Next;
        if (!more) jobs.Children.Clear();
        foreach (var job in page.Jobs)
        {
            var row = new StackPanel { Spacing = 6 };
            row.Children.Add(Text($"{job.Label} · {job.Project} · {job.State.Replace('_', ' ')}"));
            if (job.Manifest is not null) row.Children.Add(Text($"Manifest: {job.Manifest}"));
            if (job.Received) row.Children.Add(Text("Incoming reception workflow"));
            foreach (var destination in job.Destinations) row.Children.Add(Text(destination));
            if (job.Url is not null && job.State != "ready") row.Children.Add(Text("Local download link released; destination copies are pending."));
            row.Children.Add(Action("Route details and signed evidence", () =>
            {
                var address = PortStore.Shared.Port!.Base.TrimEnd('/') + "/workflows#job-" + job.Id;
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(address) { UseShellExecute = true });
                return Task.CompletedTask;
            }));
            if (job.Error is not null) row.Children.Add(Text(job.Error));
            if (job.Url is not null) row.Children.Add(Action("Copy download link", () => { Copy(job.Url); return Task.CompletedTask; }));
            if (job.State == "awaiting_approval") row.Children.Add(Action("Approve this manifest", () => Change(job, "approve")));
            if (job.State is "failed" or "retrying") row.Children.Add(Action("Retry job", () => Change(job, "retry")));
            if (job.State is not ("cancelled" or "retired" or "retiring")) row.Children.Add(Action("Cancel job", () => Change(job, "cancel")));
            jobs.Children.Add(row);
        }
    }
    private async Task Change(WorkflowJob job, string action)
    {
        if (action != "retry")
        {
            var dialog = new ContentDialog { XamlRoot = XamlRoot, Title = action == "approve" ? "Approve delivery" : "Cancel delivery", Content = action == "approve" ? $"Release {job.Label} with manifest {job.Manifest}?" : "Stop downloads here and request revocation at connected ports? Independent copies remain.", PrimaryButtonText = action == "approve" ? "Approve" : "Cancel job", CloseButtonText = "Back" };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        }
        await Task.Run(() => VotportClientCoreMethods.ChangeWorkflowJob(job.Id, action, job.Manifest));
        await LoadJobs(false);
    }
    private async Task LoadEvidence()
    {
        var records = await Task.Run(VotportClientCoreMethods.DeliveryVerifications);
        evidence.Children.Clear();
        if (!records.Any()) evidence.Children.Add(Text("Verified deliveries received on this device will appear here."));
        foreach (var record in records)
        {
            var row = new StackPanel { Spacing = 6 };
            row.Children.Add(Text($"{record.Server} · Delivery {record.GrantId}"));
            row.Children.Add(Text($"Manifest: {record.Manifest}"));
            row.Children.Add(Text($"Verification: {record.VerificationStatus} · Acceptance: {record.AcceptanceStatus.Replace('_', ' ')}"));
            if (record.AcceptanceStatus == "not_accepted") row.Children.Add(Action("Accept verified delivery", async () =>
            {
                var dialog = new ContentDialog { XamlRoot = XamlRoot, Title = "Accept verified delivery", Content = $"Confirm you reviewed and accept manifest {record.Manifest}?", PrimaryButtonText = "Accept", CloseButtonText = "Back" };
                if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
                await Task.Run(() => VotportClientCoreMethods.AcceptDelivery(record.Id)); await LoadEvidence();
            }));
            evidence.Children.Add(row);
        }
    }
}
