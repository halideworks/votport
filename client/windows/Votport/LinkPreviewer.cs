using Microsoft.UI.Dispatching;
using uniffi.votport_client_core;

namespace Votport;

/// Previews the link a box holds: debounced, off the UI thread, and a result
/// is kept only while the box still holds the link it was for. The core
/// decides everything about the link; this only carries it.
public sealed class LinkPreviewer
{
    private readonly DispatcherQueue dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly DispatcherQueueTimer timer;
    private readonly Action changed;
    private string current = "";

    internal LinkPreview? Preview { get; private set; }
    public bool Checking { get; private set; }
    public bool Ready => Preview?.Usable == true;
    public bool NeedsPassword => Preview?.NeedsPassword == true;

    /// `changed` runs on the UI thread whenever the preview or its checking
    /// state changes.
    public LinkPreviewer(Action changed)
    {
        this.changed = changed;
        timer = dispatcher.CreateTimer();
        // Typing pauses this long before the core is asked.
        timer.Interval = TimeSpan.FromMilliseconds(400);
        timer.IsRepeating = false;
        timer.Tick += (_, _) => Ask();
    }

    public void Update(string link)
    {
        current = link.Trim();
        timer.Stop();
        if (current.Length == 0)
        {
            Preview = null;
            Checking = false;
            changed();
            return;
        }
        Checking = true;
        changed();
        timer.Start();
    }

    private void Ask()
    {
        var link = current;
        var thread = new Thread(() =>
        {
            LinkPreview? result = null;
            try { result = VotportClientCoreMethods.Inspect(link); }
            catch (Exception e)
            {
                // inspect never fails by contract; a binding mismatch would.
                // The line clears rather than pinning "Checking" forever.
                CrashLog.Append(e);
            }
            dispatcher.TryEnqueue(() =>
            {
                if (link != current) return;
                Preview = result;
                Checking = false;
                changed();
            });
        }) { IsBackground = true, Name = "votport preview" };
        thread.Start();
    }

    /// The one line under a link box, from the core's preview.
    public string? Line()
    {
        if (Checking) return "Checking the link";
        if (Preview is not LinkPreview preview) return null;
        if (preview.Problem is string problem) return problem;
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(preview.Label)) parts.Add(preview.Label);
        if (preview.Kind == LinkKind.Request && preview.MaxBytes is ulong max) parts.Add($"accepts up to {Format.Bytes(max)}");
        if (preview.Kind == LinkKind.Delivery && preview.TotalBytes is ulong total)
        {
            var count = preview.Files.Length;
            parts.Add($"{count} file{(count == 1 ? "" : "s")}, {Format.Bytes(total)}");
        }
        if (preview.NeedsPassword) parts.Add("password needed");
        if (preview.Quic == true) parts.Add("QUIC offered");
        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    public bool IsProblem => Preview?.Problem is not null;
}
