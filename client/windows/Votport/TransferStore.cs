using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.UI.Dispatching;
using uniffi.votport_client_core;

namespace Votport;

/// One transfer the app started, with the latest view the core handed back.
/// The core owns every number and state here; the pages only draw.
public sealed class TransferItem : INotifyPropertyChanged
{
    public enum Kinds { Send, Receive }

    public Guid Id { get; } = Guid.NewGuid();
    public Kinds Kind { get; init; }
    /// What the user pointed at: the dropped paths or the destination folder.
    public string Subject { get; init; } = "";
    public string Link { get; init; } = "";
    public DateTime Started { get; } = DateTime.Now;
    public string[] Landed { get; set; } = Array.Empty<string>();

    private TransferView? view;
    private bool running = true;
    private bool expanded;

    public bool Expanded
    {
        get => expanded;
        set { expanded = value; Changed(); }
    }

    internal TransferView? View
    {
        get => view;
        set { view = value; Changed(); Changed(nameof(Status)); Changed(nameof(Fraction)); Changed(nameof(Files)); }
    }

    public bool Running
    {
        get => running;
        set { running = value; Changed(); Changed(nameof(NotRunning)); }
    }

    public bool NotRunning => !running;
    public string Icon => Kind == Kinds.Send ? "" : "";
    public string Status => Format.StatusLine(this);
    public double Fraction => view is null || view.TotalBytes is null || view.TotalBytes == 0
        ? 0
        : 100.0 * view.MovedBytes / view.TotalBytes.Value;
    public IEnumerable<FileRow> Files => view?.Files.Select(file => new FileRow(file)) ?? Enumerable.Empty<FileRow>();
    public bool Done => view?.Phase == Phase.Done;

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Changed([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// One file of a transfer, drawn from the core's row.
public sealed class FileRow
{
    private readonly FileView file;

    internal FileRow(FileView file) { this.file = file; }

    public string Path => file.Path;
    public double Fraction => file.Bytes == 0 ? 100 : 100.0 * file.Moved / file.Bytes;
    public string Label => Format.FileLabel(file);
    public bool Verified => file.State == FileState.Verified;
}

/// Every transfer of this app session, newest first, and the one place a
/// transfer is started or cancelled.
public sealed class TransferStore
{
    public static TransferStore Shared { get; } = new();

    public ObservableCollection<TransferItem> Items { get; } = new();
    public event Action<int>? ActiveChanged;
    /// A view arrived for some transfer; the tray line re-reads the rates.
    public event Action? ViewChanged;
    /// Links handed in by a votport: URL, taken by the page that shows them.
    public string? PrefillSend { get; set; }
    public string? PrefillReceive { get; set; }

    private readonly Dictionary<Guid, Transfer> handles = new();
    private readonly DispatcherQueue dispatcher = DispatcherQueue.GetForCurrentThread();

    public int ActiveCount => Items.Count(item => item.Running);

    public void Send(string link, string? password, string[] paths)
    {
        var subject = paths.Length == 1 ? System.IO.Path.GetFileName(paths[0]) : $"{paths.Length} items";
        var item = Start(TransferItem.Kinds.Send, subject, link);
        Run(item, (transfer, listener) =>
        {
            try { VotportClientCoreMethods.Send(link, password, paths, transfer, listener); }
            catch (VotportException) { /* the final view carries the outcome */ }
            return Array.Empty<string>();
        });
    }

    public void Receive(string link, string? password, string destination)
    {
        var item = Start(TransferItem.Kinds.Receive, destination, link);
        Run(item, (transfer, listener) =>
        {
            try
            {
                return VotportClientCoreMethods.Receive(link, password, destination, transfer, listener).Files;
            }
            catch (VotportException) { return Array.Empty<string>(); }
        });
    }

    public void Cancel(TransferItem item)
    {
        if (handles.TryGetValue(item.Id, out var transfer)) transfer.Cancel();
    }

    public void Remove(TransferItem item)
    {
        if (!item.Running) Items.Remove(item);
    }

    private TransferItem Start(TransferItem.Kinds kind, string subject, string link)
    {
        var item = new TransferItem { Kind = kind, Subject = subject, Link = link };
        Items.Insert(0, item);
        ActiveChanged?.Invoke(ActiveCount);
        return item;
    }

    /// Runs the blocking core call on a worker thread. Every view comes back
    /// through the listener's dispatcher hop, and the last one carries the
    /// outcome, so the call's own exception is not needed.
    private void Run(TransferItem item, Func<Transfer, Listener, string[]> work)
    {
        var transfer = new Transfer();
        handles[item.Id] = transfer;
        var listener = new Listener(this, item);
        var thread = new Thread(() =>
        {
            var landed = Array.Empty<string>();
            try
            {
                landed = work(transfer, listener);
            }
            catch (Exception e)
            {
                // A panic or a binding mismatch surfaces here, not as a
                // VotportException; on a bare thread it would end the process
                // with nothing written. The last core view stands as the outcome.
                CrashLog.Append(e);
            }
            dispatcher.TryEnqueue(() => Finished(item, landed));
        }) { IsBackground = true, Name = "votport transfer" };
        thread.Start();
    }

    internal void Apply(TransferItem item, TransferView view)
    {
        item.View = view;
        ViewChanged?.Invoke();
    }

    private void Finished(TransferItem item, string[] landed)
    {
        item.Running = false;
        item.Landed = landed;
        handles.Remove(item.Id);
        ActiveChanged?.Invoke(ActiveCount);
        Notifier.TransferEnded(item);
        Snapshot.WriteIfRequested();
    }

    /// The core's callback target for one transfer. Called on the core's
    /// thread; hops to the UI thread before touching the item. The dispatcher
    /// queue is FIFO, so views apply in the order the core sent them.
    private sealed class Listener : TransferListener
    {
        private readonly TransferStore store;
        private readonly TransferItem item;

        public Listener(TransferStore store, TransferItem item)
        {
            this.store = store;
            this.item = item;
        }

        public void Update(TransferView view)
        {
            store.dispatcher.TryEnqueue(() => store.Apply(item, view));
        }
    }
}

/// `Votport --receive <link> <dir>` starts a receive at launch, once per
/// process; `votport:` links from the web pages prefill a page.
public static class Launch
{
    public static bool Done { get; private set; }

    public static void StartFromArguments(string[] arguments)
    {
        var flag = Array.IndexOf(arguments, "--receive");
        if (Done || flag < 0 || arguments.Length <= flag + 2) return;
        Done = true;
        TransferStore.Shared.Receive(arguments[flag + 1], null, arguments[flag + 2]);
        App.Window?.Show("transfers");
    }

    /// A votport: link opened from a web page prefills the page it names.
    public static void OpenUrl(Uri url)
    {
        if (WebLink(url) is not (string kind, string link)) return;
        if (kind == "r")
        {
            TransferStore.Shared.PrefillSend = link;
            App.Window?.Show("send");
        }
        else
        {
            TransferStore.Shared.PrefillReceive = link;
            App.Window?.Show("receive");
        }
    }

    /// The web link a `votport://r/<token>?base=<origin>` or
    /// `votport://s/<token>?base=<origin>` URL names, or null for any other
    /// shape. The base is the page's own origin, so the app talks to the
    /// votport the link came from and nowhere else.
    public static (string kind, string link)? WebLink(Uri url)
    {
        if (url.Scheme != "votport") return null;
        var kind = url.Host;
        if (kind != "r" && kind != "s") return null;
        var token = url.AbsolutePath.Trim('/');
        if (token.Length == 0 || token.Contains('/')) return null;
        var query = System.Web.HttpUtility.ParseQueryString(url.Query);
        var origin = query["base"];
        if (origin is null || !Uri.TryCreate(origin, UriKind.Absolute, out var parsed)) return null;
        if (parsed.Scheme != "https" && parsed.Scheme != "http") return null;
        return (kind, $"{origin.TrimEnd('/')}/{kind}/{token}");
    }
}

/// Words and units around the core's numbers. Every value comes from the
/// core; nothing is computed here.
public static class Format
{
    public static string Bytes(ulong value)
    {
        string[] units = { "bytes", "KB", "MB", "GB", "TB" };
        double amount = value;
        var unit = 0;
        while (amount >= 1000 && unit < units.Length - 1) { amount /= 1000; unit++; }
        return unit == 0 ? $"{value} {units[0]}" : $"{amount:0.#} {units[unit]}";
    }

    public static string Seconds(ulong value)
    {
        var span = TimeSpan.FromSeconds(value);
        return value >= 3600 ? $"{(int)span.TotalHours} h {span.Minutes} min" : $"{span.Minutes} min {span.Seconds} s";
    }

    internal static string TransportName(Transport transport) => transport switch
    {
        Transport.Push => "QUIC push",
        Transport.Fetch => "QUIC fetch",
        _ => "HTTP",
    };

    internal static string FileLabel(FileView file) => file.State switch
    {
        FileState.Waiting => Bytes(file.Bytes),
        FileState.Moving => $"{Bytes(file.Moved)} of {Bytes(file.Bytes)}",
        FileState.Landed => "landed",
        _ => "verified",
    };

    public static string MenuLine(TransferItem item)
    {
        var line = item.Subject;
        if (item.View?.RateBytesPerSecond is ulong rate) line += $"  {Bytes(rate)}/s";
        return line;
    }

    internal static string StatusLine(TransferItem item)
    {
        var view = item.View;
        // No view at all means the core never answered (a panic or a load
        // failure the crash log names), which is the shell's failure to show.
        if (view is null) return item.Running ? "Starting" : "Failed";
        var verb = item.Kind == TransferItem.Kinds.Send ? "Sending" : "Receiving";
        switch (view.Phase)
        {
            case Phase.Preparing:
                return item.Kind == TransferItem.Kinds.Send ? "Hashing" : "Preparing";
            case Phase.Transferring:
                var parts = new List<string> { verb };
                if (view.Transport is Transport via) parts.Add($"over {TransportName(via)}");
                if (view.TotalBytes is ulong total) parts.Add($"{Bytes(view.MovedBytes)} of {Bytes(total)}");
                if (view.RateBytesPerSecond is ulong rate) parts.Add($"{Bytes(rate)}/s");
                if (view.EtaSeconds is ulong eta) parts.Add($"about {Seconds(eta)} left");
                return string.Join(", ", parts);
            case Phase.Done:
                return item.Kind == TransferItem.Kinds.Send
                    ? $"Done, {view.Files.Length} file(s) sent"
                    : $"Done, {view.Files.Length} file(s) received and verified";
            case Phase.Cancelled:
                return "Cancelled";
            default:
                return view.Headline ?? "Failed";
        }
    }
}
