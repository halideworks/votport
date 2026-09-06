using System.Collections.ObjectModel;
using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
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

/// A new delivery from the port's library, reached from Links: browse a
/// directory, tick files, issue the delivery, copy the one link the server
/// shows for it.
public sealed partial class DeliverPage : Page
{
    private readonly ObservableCollection<LibraryEntry> entries = new();
    private readonly HashSet<string> chosen = new();
    private string directory = "";
    private string? issued;

    public DeliverPage()
    {
        InitializeComponent();
        Entries.ItemsSource = entries;
        Loaded += (_, _) => PortStore.Shared.Changed += Refresh;
        Unloaded += (_, _) => PortStore.Shared.Changed -= Refresh;
        ActualThemeChanged += (_, _) => Refresh();
        LabelBox.TextChanged += (_, _) => Refresh();
        Open("");
        Refresh();
    }

    private void Refresh()
    {
        var port = PortStore.Shared;
        ChosenText.Text = chosen.Count == 0 ? "Tick the files to deliver" : chosen.Count == 1 ? "1 file" : $"{chosen.Count} files";
        IssueButton.IsEnabled = !port.Busy && chosen.Count > 0 && LabelBox.Text.Trim().Length > 0;
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
        BrowserNote.Text = "Reading the library";
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

    private void DrawCrumbs()
    {
        Crumbs.Children.Clear();
        AddCrumb("Library", "");
        var parts = directory.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < parts.Length; i++)
        {
            Crumbs.Children.Add(new TextBlock { Text = "/", Foreground = Theme.Brush(this, "VotMuted"), VerticalAlignment = VerticalAlignment.Center });
            AddCrumb(parts[i], string.Join('/', parts.Take(i + 1)));
        }
    }

    private void AddCrumb(string text, string target)
    {
        var button = new HyperlinkButton { Content = text, Padding = new Thickness(4, 2, 4, 2) };
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
            uint.TryParse(ExpiresBox.Text.Trim(), out var days) ? days : 7,
            ulong.TryParse(DownloadsBox.Text.Trim(), out var max) ? max : null);
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

    // XAML handlers must live on the page; the rule itself is shared.
    private void Digits(TextBox sender, TextBoxBeforeTextChangingEventArgs args) => Numeric.Digits(sender, args);

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (Frame.CanGoBack) Frame.GoBack(); else Frame.Navigate(typeof(LinksPage));
    }
}
