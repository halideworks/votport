using System.Collections.ObjectModel;
using Microsoft.UI.Dispatching;
using uniffi.votport_client_core;

namespace Votport;

/// The home port: the votport the operator signed in to, and what the core
/// lists there. Every core call runs on its own thread and lands back on
/// the UI thread; the core owns the session, this only carries results.
public sealed class PortStore
{
    public static PortStore Shared { get; } = new();

    private readonly DispatcherQueue dispatcher = DispatcherQueue.GetForCurrentThread();

    internal Port? Port { get; private set; }
    public bool SignedIn => Port is not null;
    public ObservableCollection<RequestItem> Requests { get; } = new();
    public ObservableCollection<DeliveryItem> Deliveries { get; } = new();
    public ObservableCollection<WatchItem> Watches { get; } = new();
    /// The last failure's headline, for the line under the form that made
    /// the call, named by ProblemScope.
    public string? Problem { get; private set; }
    public enum Scope { Port, Watch, Links, Deliver }
    public Scope ProblemScope { get; private set; }

    /// The headline to show under a form, when the failure was its own.
    public string? ProblemFor(Scope scope) => ProblemScope == scope ? Problem : null;
    public bool Busy { get; private set; }
    /// Calls in flight; Busy follows it, so two overlapping calls do not
    /// re-enable a form when the first one lands.
    private int inFlight;
    /// The port, the lists, the problem, or busy changed; pages redraw.
    public event Action? Changed;

    /// Reads the stored port without a round trip, then asks the server
    /// whether the session still holds. Called once at launch.
    public void Load()
    {
        Port = VotportClientCoreMethods.Port();
        ReloadWatches();
        if (Port is null) return;
        Run(Scope.Port, () => VotportClientCoreMethods.CheckPort(), port =>
        {
            Port = port;
            if (port is not null) Refresh();
        });
    }

    public void SignIn(string @base, string password) =>
        Run(Scope.Port, () => VotportClientCoreMethods.SignIn(@base, password), port =>
        {
            Port = port;
            Problem = null;
            Refresh();
        });

    public void SignOut() =>
        Run(Scope.Port, () => { VotportClientCoreMethods.SignOut(); return true; }, _ =>
        {
            Port = null;
            Requests.Clear();
            Deliveries.Clear();
        });

    /// Reloads the request links and deliveries.
    public void Refresh() =>
        Run(Scope.Links, () => (VotportClientCoreMethods.Requests(), VotportClientCoreMethods.Deliveries()), lists =>
        {
            Requests.Clear();
            foreach (var link in lists.Item1) Requests.Add(new RequestItem(link));
            Deliveries.Clear();
            foreach (var delivery in lists.Item2) Deliveries.Add(new DeliveryItem(delivery));
        });

    internal void IssueRequest(RequestSpec spec, Action<RequestLink?> done) =>
        Run(Scope.Links, () => VotportClientCoreMethods.IssueRequest(spec), link =>
        {
            Requests.Insert(0, new RequestItem(link));
            Problem = null;
            done(link);
        }, () => done(null));

    public void CloseRequest(string id) =>
        Run(Scope.Links, () => { VotportClientCoreMethods.CloseRequest(id); return true; }, _ =>
        {
            var item = Requests.FirstOrDefault(r => r.Id == id);
            if (item is not null) Requests.Remove(item);
        });

    public void RevokeDelivery(string id) =>
        Run(Scope.Links, () => { VotportClientCoreMethods.RevokeDelivery(id); return true; }, _ => Refresh());

    internal void Library(string directory, Action<Library?> done) =>
        Run(Scope.Deliver, () => VotportClientCoreMethods.Library(directory), done, () => done(null));

    /// Uploads a drop (files, and folders with everything under them) into
    /// the port under `into` and hands back every library file made.
    /// Progress reaches `listener` on the core's thread; a failure midway
    /// returns nothing here, and the listener's last view names what landed.
    internal void Upload(string[] paths, string into, Transfer transfer, UploadListener listener, Action<LibraryFile[]> done, Action failed) =>
        Run(Scope.Deliver, () => VotportClientCoreMethods.Upload(paths, into, transfer, listener), done, failed);

    internal void IssueDelivery(DeliverySpec spec, Action<IssuedDelivery?> done) =>
        Run(Scope.Deliver, () => VotportClientCoreMethods.IssueDelivery(spec), issued =>
        {
            Deliveries.Insert(0, new DeliveryItem(issued.Delivery));
            Problem = null;
            done(issued);
        }, () => done(null));

    public void AddWatch(string dir, string link, string? password, Action<bool> done) =>
        Run(Scope.Watch, () => VotportClientCoreMethods.AddWatch(dir, link, password), _ =>
        {
            ReloadWatches();
            done(true);
        }, () => done(false));

    public void RemoveWatch(string id) =>
        Run(Scope.Watch, () => { VotportClientCoreMethods.RemoveWatch(id); return true; }, _ => ReloadWatches());

    private void ReloadWatches()
    {
        Watches.Clear();
        foreach (var watch in VotportClientCoreMethods.Watches()) Watches.Add(new WatchItem(watch));
    }

    /// Runs `work` on its own thread (a core call blocks for its round trips
    /// and through the retry budget) and hands the result to `done` on the
    /// UI thread. A failure sets the problem; a session the server ended
    /// clears the port so the pages fold.
    private void Run<T>(Scope scope, Func<T> work, Action<T> done, Action? failed = null)
    {
        inFlight++;
        Busy = true;
        Problem = null;
        Changed?.Invoke();
        var thread = new Thread(() =>
        {
            T? result = default;
            string? problem = null;
            var signedOut = false;
            try { result = work(); }
            catch (PortException.Failed e)
            {
                problem = e.headline;
                signedOut = e.signedOut;
            }
            catch (Exception e) { problem = e.Message; }
            dispatcher.TryEnqueue(() =>
            {
                inFlight--;
                Busy = inFlight > 0;
                if (problem is null) done(result!);
                else
                {
                    // Stamped at the failure, so a slow call landing after a
                    // later one still reports under its own form.
                    Problem = problem;
                    ProblemScope = scope;
                    if (signedOut)
                    {
                        Port = null;
                        Requests.Clear();
                        Deliveries.Clear();
                    }
                    failed?.Invoke();
                }
                Changed?.Invoke();
            });
        }) { IsBackground = true, Name = "votport port" };
        thread.Start();
    }
}

/// One request link, as the Links page draws it.
public sealed class RequestItem
{
    internal RequestLink Link { get; }
    internal RequestItem(RequestLink link) { Link = link; }
    public string Id => Link.Id;
    public string Label => Link.Label;
    public string Url => Link.Url;
    public string Summary => Link.Summary;
    public bool Receiving => Link.Receiving > 0;
}

/// One delivery, as the Links page draws it.
public sealed class DeliveryItem
{
    internal Delivery Delivery { get; }
    internal DeliveryItem(Delivery delivery) { Delivery = delivery; }
    public string Id => Delivery.Id;
    public string Name => Delivery.Label ?? Delivery.Name ?? Delivery.Id;
    public string Summary => Delivery.Summary;
    public bool Live => Delivery.RevokedAt is null;
}

/// One watched folder, as Settings draws it.
public sealed class WatchItem
{
    internal Watch Watch { get; }
    internal WatchItem(Watch watch) { Watch = watch; }
    public string Id => Watch.Id;
    public string Dir => Watch.Dir;
    public string Link => Watch.Link;
}
