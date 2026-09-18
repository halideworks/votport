extern alias VotportApp;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using VotportApp::uniffi.votport_client_core;
using VotportApp::Votport;

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static TransferView View(IReadOnlyList<FileView> files, Phase phase = Phase.Done) => new(
    phase == Phase.Failed ? "failed" : "verified",
    phase,
    Transport.Fetch,
    true,
    files.ToArray(),
    (ulong)files.Count,
    (ulong)files.Count,
    null,
    null,
    1_700_000_000UL,
    false,
    phase == Phase.Failed ? "Failure headline" : phase == Phase.Paused ? "Paused" : "Complete",
    phase == Phase.Failed ? "Failure detail" : "All files complete",
    phase == Phase.Failed ? "Failed, 4 files" : phase == Phase.Paused ? "Paused, 4 files" : "Done, 4 files",
    "Direct route (QUIC)",
    "1 B/s");

static FileView File(ulong index, string path) =>
    new(index, path, 1, 1, 100, FileState.Verified, "verified");

static PropertyInfo Property<T>(string name) =>
    typeof(T).GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
    ?? throw new InvalidOperationException($"Missing {typeof(T).Name}.{name}");

static TransferView GetView(TransferItem item) =>
    (TransferView)(Property<TransferItem>("View").GetValue(item)
        ?? throw new InvalidOperationException("view was not retained"));

static void SetView(TransferItem item, TransferView view) =>
    Property<TransferItem>("View").SetValue(item, view);

static Dictionary<ulong, FileRow> Index(TransferItem item) =>
    (Dictionary<ulong, FileRow>)(typeof(TransferItem).GetField(
        "filesByIndex", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(item)
        ?? throw new InvalidOperationException("missing file index"));

static void Compact(TransferItem item, string[] landed) =>
    typeof(TransferItem).GetMethod("CompactStopped", BindingFlags.Instance | BindingFlags.NonPublic)!
        .Invoke(item, new object[] { landed });

var dispatcherController = DispatcherQueueController.CreateOnCurrentThread();
var terminal = new TransferItem
{
    Kind = TransferItem.Kinds.Receive,
    Subject = @"C:\received",
    Running = false,
};
var files = new[] { File(0, "a"), File(1, "b"), File(2, "c"), File(3, "d") };
var before = View(files, Phase.Failed);
SetView(terminal, before);
Check(terminal.Files.Count == 4 && Index(terminal).Count == 4 && GetView(terminal).Files.Length == 4,
    "production View setter did not populate all file owners");
var emptyIndexCapacity = new Dictionary<ulong, FileRow>(1).EnsureCapacity(0);
Check(Index(terminal).EnsureCapacity(0) > emptyIndexCapacity,
    "fixture must allocate more than an empty index");
Compact(terminal, new[] { @"C:\received\a", @"C:\received\b", @"C:\received\c", @"C:\received\d" });
var after = GetView(terminal);
Check(terminal.Files.Count == 0 && after.Files.Length == 0 && Index(terminal).Count == 0,
    "terminal compaction did not release rendered rows, view files, and index");
Check(Index(terminal).EnsureCapacity(0) <= emptyIndexCapacity,
    "terminal compaction retained its per-file index allocation");
Check(after.Phase == before.Phase && after.EvidenceStatus == before.EvidenceStatus
    && after.Headline == before.Headline && after.Status == before.Status
    && after.Detail == before.Detail && after.Route == before.Route
    && after.FinishedUnixSeconds == before.FinishedUnixSeconds,
    "failed terminal compaction changed aggregate view fields");
Check(terminal.Landed == @"C:\received" && terminal.RevealDestinationFolder
    && terminal.RevealLabel == "Show destination folder",
    "multiple landed files did not retain the destination folder reveal");
var single = new TransferItem
{
    Kind = TransferItem.Kinds.Receive,
    Subject = @"C:\received",
    Running = false,
};
typeof(TransferItem).GetMethod("SetRevealDestination", BindingFlags.Instance | BindingFlags.NonPublic)!
    .Invoke(single, new object[] { new[] { @"C:\received\a" } });
Check(single.Landed == @"C:\received\a" && !single.RevealDestinationFolder
    && single.CanReveal && single.RevealLabel == "Show in Explorer",
    "single landed file did not retain exact-file reveal");

var active = new TransferItem
{
    Kind = TransferItem.Kinds.Receive,
    Subject = @"C:\active",
    Running = true,
};
var activeBefore = View(files);
SetView(active, activeBefore);
Compact(active, new[] { @"C:\active\a" });
var activeAfter = GetView(active);
Check(active.Files.Count == 4 && activeAfter.Files.Length == 4 && Index(active).Count == 4
    && activeAfter.Headline == activeBefore.Headline && activeAfter.Status == activeBefore.Status,
    "active compaction changed rendered rows or aggregate view");

var paused = new TransferItem
{
    Kind = TransferItem.Kinds.Receive,
    Subject = @"C:\paused",
    Running = false,
    Journalled = true,
};
var pausedBefore = View(files, Phase.Paused);
SetView(paused, pausedBefore);
Compact(paused, new[] { @"C:\paused\a" });
var pausedAfter = GetView(paused);
Check(paused.Files.Count == 4 && pausedAfter.Files.Length == 4 && Index(paused).Count == 4
    && pausedAfter.Phase == pausedBefore.Phase && pausedAfter.Headline == pausedBefore.Headline
    && pausedAfter.Detail == pausedBefore.Detail && pausedAfter.Status == pausedBefore.Status,
    "journalled compaction changed rendered rows or aggregate view");

var store = new TransferStore();
store.Items.Add(active);
store.Items.Add(paused);
store.Items.Add(terminal);
store.ClearFinished();
Check(store.Items.Count == 2 && store.Items.Contains(active) && store.Items.Contains(paused)
    && !store.Items.Contains(terminal),
    "Clear finished did not preserve active and journalled cards");
Check(paused.Files.Count == 4 && GetView(paused).Files.Length == 4,
    "journalled card lost its file rows");
Check(paused.CanResume, "journalled card is not resumable");

RunPortStoreSessionEpochRegression();

dispatcherController.ShutdownQueue();
Console.WriteLine("Windows transfer retention model and session ownership checks passed.");

static void RunPortStoreSessionEpochRegression()
{
    var store = PortStore.Shared;
    var generation = Generation(store);
    Run<int>(store, () => 1, _ => { }, null);
    PumpUntil(() => !store.Busy, "same-session production call did not settle");
    Check(Generation(store) == generation, "same-session refresh advanced the session generation");

    var signedOutFailed = false;
    Run<int>(store,
        () => throw new PortException.Failed("expired", "expired", true),
        _ => { },
        () => signedOutFailed = true,
        () => false);
    PumpUntil(() => signedOutFailed && !store.Busy, "signed-out production failure did not settle");
    Check(Generation(store) == generation + 1 && !store.SignedIn,
        "signed-out failure did not invalidate the session");

    Set(store, "Port", new Port("https://replacement", "tenant", "admin"));
    var workerEntered = new ManualResetEventSlim();
    var releaseWorker = new ManualResetEventSlim();
    var workerFinished = new ManualResetEventSlim();
    var staleFailed = false;
    try
    {
        Run<int>(store,
            () => {
                workerEntered.Set();
                try
                {
                    if (!releaseWorker.Wait(TimeSpan.FromSeconds(5)))
                        throw new InvalidOperationException("worker release timed out");
                    throw new PortException.Failed("old account", "old account", true);
                }
                finally { workerFinished.Set(); }
            },
            _ => { },
            () => staleFailed = true);
        Check(workerEntered.Wait(TimeSpan.FromSeconds(5)), "controlled old-account worker did not start");
        var problem = typeof(PortStore).GetProperty("Problem", BindingFlags.Instance | BindingFlags.Public)!;
        problem.SetValue(store, "replacement problem");
        var reset = typeof(PortStore).GetMethod("ResetLibraryUploadForSession", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var beforeReset = Generation(store);
        reset.Invoke(store, null);
        releaseWorker.Set();
        PumpUntil(() => staleFailed && !store.Busy, "stale worker failure callback did not settle");
        Check(store.Problem == "replacement problem",
            "stale old-account failure overwrote the replacement problem");
        Check(store.SignedIn, "stale old-account failure signed out the replacement session");
        Check(Generation(store) == beforeReset + 1,
            "stale failure performed a second session reset");
    }
    finally
    {
        releaseWorker.Set();
        Check(workerFinished.Wait(TimeSpan.FromSeconds(5)), "old-account worker did not exit");
        if (!staleFailed) PumpUntil(() => !store.Busy, "old-account callback did not drain before cleanup");
        workerEntered.Dispose();
        releaseWorker.Dispose();
        workerFinished.Dispose();
    }

    var uploadId = Guid.NewGuid();
    Set(store, "LibraryUploadId", uploadId);
    Set(store, "LibraryUploadActive", true);
    Set(store, "LibraryUpload", new Transfer());
    SetField(store, "libraryUploadWorkerId", uploadId);
    var uploadReset = typeof(PortStore).GetMethod("ResetLibraryUploadForSession", BindingFlags.Instance | BindingFlags.NonPublic)!;
    uploadReset.Invoke(store, null);
    var finish = typeof(PortStore).GetMethod("FinishLibraryUpload", BindingFlags.Instance | BindingFlags.NonPublic)!;
    finish.Invoke(store, new object?[] { uploadId, "old account failure" });
    Check(!Get<bool>(store, "LibraryUploadActive")
        && GetField<Guid?>(store, "libraryUploadWorkerId") is null
        && Get<string?>(store, "LibraryUploadOutcome") is null,
        "old upload worker did not settle after session reset");
}

static void Run<T>(PortStore store, Func<T> work, Action<T> done, Action? failed, Func<bool>? isCurrent = null) =>
    typeof(PortStore).GetMethod("Run", BindingFlags.Instance | BindingFlags.NonPublic)!
        .MakeGenericMethod(typeof(T))
        .Invoke(store, new object?[] { PortStore.Scope.Port, work, done, failed, isCurrent });

static long Generation(PortStore store) => (long)(typeof(PortStore)
    .GetField("sessionGeneration", BindingFlags.Instance | BindingFlags.NonPublic)!
    .GetValue(store)!);

static T Get<T>(PortStore store, string name) => (T)typeof(PortStore)
    .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
    .GetValue(store)!;

static T GetField<T>(PortStore store, string name) => (T)typeof(PortStore)
    .GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
    .GetValue(store)!;

static void Set<T>(PortStore store, string name, T value) => typeof(PortStore)
    .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
    .SetValue(store, value);

static void SetField<T>(PortStore store, string name, T value) => typeof(PortStore)
    .GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
    .SetValue(store, value);

static void PumpUntil(Func<bool> condition, string message)
{
    var stop = Stopwatch.StartNew();
    while (!condition() && stop.Elapsed < TimeSpan.FromSeconds(10))
    {
        while (stop.Elapsed < TimeSpan.FromSeconds(10)
            && Native.PeekMessage(out var messageValue, IntPtr.Zero, 0, 0, 1))
        {
            Native.TranslateMessage(ref messageValue);
            Native.DispatchMessage(ref messageValue);
        }
        Thread.Sleep(10);
    }
    Check(condition(), message);
}

static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Point { internal int X; internal int Y; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Message
    {
        internal IntPtr Hwnd;
        internal uint Id;
        internal UIntPtr WParam;
        internal IntPtr LParam;
        internal uint Time;
        internal Point Point;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PeekMessage(out Message message, IntPtr hwnd, uint min, uint max, uint remove);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TranslateMessage(ref Message message);

    [DllImport("user32.dll")]
    internal static extern IntPtr DispatchMessage(ref Message message);
}
