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
    /// The kind of link the page takes; the other kind is named as such.
    private readonly LinkKind expect;
    private string current = "";

    internal LinkPreview? Preview { get; private set; }
    public bool Checking { get; private set; }
    public bool Ready => Preview?.Usable == true;
    public bool NeedsPassword => Preview?.NeedsPassword == true;

    /// `changed` runs on the UI thread whenever the preview or its checking
    /// state changes.
    internal LinkPreviewer(LinkKind expect, Action changed)
    {
        this.expect = expect;
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
            try { result = VotportClientCoreMethods.Inspect(link, expect); }
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
        return Preview?.Line;
    }

    public bool IsProblem => Preview?.Problem is not null;
}
