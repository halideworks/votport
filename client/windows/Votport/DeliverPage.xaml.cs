using System.Collections.ObjectModel;
using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using uniffi.votport_client_core;

namespace Votport;

/// One row of the library browser: a folder to enter or a file to tick.
public sealed class LibraryEntry : INotifyPropertyChanged
{
    public string Name { get; init; } = "";
    /// Library-relative path, forward slashes.
    public string Path { get; init; } = "";
    public string Size { get; init; } = "";
    public bool IsFile { get; init; }
    public bool IsFolder => !IsFile;
    private bool chosen;

    public bool Chosen
    {
        get => chosen;
        set { chosen = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Chosen))); ChosenChanged?.Invoke(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public Action? ChosenChanged { get; set; }
}

/// Share files through a delivery link. Files dropped or chosen here go up
/// to the port first and come back ticked; what is already on the port is
/// browsed one directory at a time and ticked the same way. Then the
/// delivery is issued and its one link copied.
public sealed partial class DeliverPage : Page
{
    private const string DropPrompt = "Drop files or folders here";
    private readonly ObservableCollection<LibraryEntry> entries = new();
    private readonly HashSet<string> chosen = new();
    private string directory = "";
    private string? issued;
    /// The cancel handle of the upload in flight, if any, and the core's
    /// last word on it.
    private Transfer? uploading;
    private UploadView? lastUpload;

    public DeliverPage()
    {
        InitializeComponent();
        Entries.ItemsSource = entries;
        Loaded += (_, _) => PortStore.Shared.Changed += Refresh;
        Unloaded += (_, _) => PortStore.Shared.Changed -= Refresh;
        ActualThemeChanged += (_, _) => Refresh();
        LabelBox.TextChanged += (_, _) => Refresh();
        Numeric.Integer(ExpiresBox);
        Numeric.Integer(DownloadsBox);
        // The local day, not the core's UTC one: an evening drop belongs to today.
        FolderBox.Text = DateTime.Now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        Open("");
        Refresh();
    }

    private void Refresh()
    {
        var port = PortStore.Shared;
        // The button carries the count, so the row has one control to read.
        IssueButton.Content = chosen.Count == 0 ? "Choose files to share" : chosen.Count == 1 ? "Share 1 file" : $"Share {chosen.Count} files";
        IssueButton.IsEnabled = !port.Busy && chosen.Count > 0 && LabelBox.Text.Trim().Length > 0;
        var busy = uploading is not null;
        ChooseButton.IsEnabled = !busy;
        ChooseFolderButton.Visibility = busy ? Visibility.Collapsed : Visibility.Visible;
        PasteButton.IsEnabled = !busy;
        CancelUploadButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        FolderBox.IsEnabled = !busy;
        var problem = port.ProblemFor(PortStore.Scope.Deliver);
        ProblemText.Text = problem ?? "";
        ProblemText.Visibility = problem is null ? Visibility.Collapsed : Visibility.Visible;
        ProblemText.Foreground = Theme.Brush(this, "VotDanger");
        IssuedPanel.Visibility = issued is null ? Visibility.Collapsed : Visibility.Visible;
        IssuedText.Text = issued ?? "";
    }

    private void Open(string target)
    {
        directory = target;
        entries.Clear();
        BrowserNote.Text = "Reading what is on the port";
        BrowserNote.Visibility = Visibility.Visible;
        DrawCrumbs();
        PortStore.Shared.Library(target, listing =>
        {
            if (listing is null || directory != target) return;
            entries.Clear();
            foreach (var name in listing.Directories)
            {
                entries.Add(new LibraryEntry { Name = name, Path = target.Length == 0 ? name : $"{target}/{name}" });
            }
            foreach (var file in listing.Files)
            {
                var entry = new LibraryEntry { Name = System.IO.Path.GetFileName(file.Path), Path = file.Path, Size = file.Size, IsFile = true, Chosen = chosen.Contains(file.Path) };
                entry.ChosenChanged = () =>
                {
                    if (entry.Chosen) chosen.Add(entry.Path); else chosen.Remove(entry.Path);
                    Refresh();
                };
                entries.Add(entry);
            }
            BrowserNote.Text = listing.Truncated ? "More files than shown" : "Nothing here yet.";
            BrowserNote.Visibility = entries.Count == 0 || listing.Truncated ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.AcceptedOperation = uploading is null && e.DataView.Contains(StandardDataFormats.StorageItems)
            ? DataPackageOperation.Copy
            : DataPackageOperation.None;
    }

    private async void DropZone_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        Upload(await e.DataView.GetStorageItemsAsync());
    }

    private async void Choose_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        Upload(await picker.PickMultipleFilesAsync());
    }

    private async void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        var folder = await picker.PickSingleFolderAsync();
        if (folder is not null) Upload(new[] { folder });
    }

    private async void Paste_Click(object sender, RoutedEventArgs e)
    {
        var data = Clipboard.GetContent();
        if (data.Contains(StandardDataFormats.StorageItems)) Upload(await data.GetStorageItemsAsync());
    }

    private void CancelUpload_Click(object sender, RoutedEventArgs e) => uploading?.Cancel();

    /// Sends the items up to the port under the folder named in the box;
    /// what lands is ticked and its folder opened so the ticks are seen.
    private void Upload(IEnumerable<IStorageItem> items)
    {
        var paths = items.Select(item => item.Path).Where(path => path.Length > 0).ToArray();
        if (paths.Length == 0 || uploading is not null) return;
        var transfer = new Transfer();
        uploading = transfer;
        lastUpload = null;
        Refresh();
        // What landed is ticked whether the upload ended well or not: a
        // failure or a cancel midway still put the earlier files on the port.
        PortStore.Shared.Upload(paths, FolderBox.Text.Trim(), transfer, new UploadHop(this), _ => Landed(reopen: true), () =>
        {
            // The problem line below says what went wrong; the prompt returns.
            // No reload here: a library call would clear that line.
            DropText.Text = DropPrompt;
            Landed(reopen: false);
        });
    }

    private void Landed(bool reopen)
    {
        uploading = null;
        var landed = lastUpload?.Landed ?? Array.Empty<string>();
        foreach (var path in landed) chosen.Add(path);
        if (reopen && landed.Length > 0) Open(landed[0][..Math.Max(landed[0].LastIndexOf('/'), 0)]);
        Refresh();
    }

    /// The core's line stays up after the upload ends ("Added 2 files to
    /// the port, 21 MB") until the next one starts.
    private void ShowUpload(UploadView view)
    {
        lastUpload = view;
        DropText.Text = view.Status;
    }

    /// The core's progress callback for an upload. Called on the core's
    /// thread; hops to the UI thread before touching the page.
    private sealed class UploadHop : UploadListener
    {
        private readonly DeliverPage page;
        public UploadHop(DeliverPage page) => this.page = page;
        public void Update(UploadView view) => page.DispatcherQueue.TryEnqueue(() => page.ShowUpload(view));
    }

    /// The path into what is on the port, in the path type: every directory
    /// above the current one is a link back to it, the current one is plain
    /// text.
    private void DrawCrumbs()
    {
        Crumbs.Children.Clear();
        var parts = directory.Split('/', StringSplitOptions.RemoveEmptyEntries);
        AddCrumb("On the port", "", current: parts.Length == 0);
        for (var i = 0; i < parts.Length; i++)
        {
            Crumbs.Children.Add(new TextBlock { Text = "/", Foreground = Theme.Brush(this, "VotMuted"), VerticalAlignment = VerticalAlignment.Center });
            AddCrumb(parts[i], string.Join('/', parts.Take(i + 1)), current: i == parts.Length - 1);
        }
    }

    private void AddCrumb(string text, string target, bool current)
    {
        var mono = (FontFamily)Application.Current.Resources["VotMonoFont"];
        var padding = new Thickness(4, 2, 4, 2);
        if (current)
        {
            Crumbs.Children.Add(new TextBlock { Text = text, FontFamily = mono, Padding = padding, VerticalAlignment = VerticalAlignment.Center });
            return;
        }
        var button = new HyperlinkButton { Content = text, FontFamily = mono, Padding = padding };
        button.Click += (_, _) => Open(target);
        Crumbs.Children.Add(button);
    }

    private void Entries_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is LibraryEntry entry && entry.IsFolder) Open(entry.Path);
    }

    private void Issue_Click(object sender, RoutedEventArgs e)
    {
        var spec = new DeliverySpec(
            chosen.OrderBy(p => p).ToArray(),
            LabelBox.Text.Trim(),
            DeliveryPasswordBox.Password.Length == 0 ? null : DeliveryPasswordBox.Password,
            Numeric.Whole(ExpiresBox) ?? 7,
            Numeric.Whole(DownloadsBox));
        PortStore.Shared.IssueDelivery(spec, result =>
        {
            if (result is null) return;
            issued = result.Url;
            LinksPage.Copy(result.Url);
            chosen.Clear();
            foreach (var entry in entries) entry.Chosen = false;
            LabelBox.Text = "";
            DeliveryPasswordBox.Password = "";
            Refresh();
        });
    }

    private void CopyIssued_Click(object sender, RoutedEventArgs e)
    {
        if (issued is not null) LinksPage.Copy(issued, sender as Button);
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        App.Window?.Show("links");
    }
}
