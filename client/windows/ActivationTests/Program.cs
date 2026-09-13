using System.Runtime.InteropServices;
using Microsoft.Windows.AppLifecycle;
using Votport;
using Windows.ApplicationModel.Activation;

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static ActivationRequest Cli(string arguments) =>
    ActivationRequest.Parse(ExtendedActivationKind.Launch, new LaunchPayload(arguments));

var empty = new ActivationRequest();
foreach (var data in new object?[] { null, new object(), new LaunchPayload("--receive https://port/s/token C:\\files --snapshot C:\\target.png") })
    Check(ActivationRequest.Parse(ExtendedActivationKind.Protocol, data) == empty, "Protocol requires its own payload");
foreach (var kind in new[] { ExtendedActivationKind.File, ExtendedActivationKind.StartupTask })
    Check(ActivationRequest.Parse(kind, new LaunchPayload("--minimized --receive https://port/s/token C:\\files")) == empty, "Unrelated activations cannot consume CLI options");
Check(ActivationRequest.Parse(ExtendedActivationKind.Launch, new ProtocolPayload(new Uri("votport://s/token"))) == empty, "Launch requires its own payload");

var uri = new Uri("votport://s/token?base=https://port&text=--receive%20https://evil/s/token%20C:/files%20--snapshot%20C:/target.png%20--minimized");
var protocol = ActivationRequest.Parse(ExtendedActivationKind.Protocol, new DualPayload(uri));
Check(protocol == new ActivationRequest(Protocol: uri), "Protocol must never inspect CLI arguments");

foreach (var prefix in new[] { "", "\"C:\\Program Files\\Votport.exe\" " })
{
    var request = Cli(prefix + "--receive https://port/s/token \"C:\\folder with spaces\\\\\" --snapshot \"C:\\proof folder\\final.png\" --minimized");
    Check(request == new ActivationRequest(ReceiveLink: "https://port/s/token", Destination: "C:\\folder with spaces\\", SnapshotPath: "C:\\proof folder\\final.png", Minimized: true), "Full and argument-only launches preserve Windows quoting");
}
foreach (var arguments in new[] { "", " ", "--receive", "--receive https://port/s/token", "--receive --snapshot --minimized", "--snapshot", "--minimized --snapshot --receive" })
    Check(Cli(arguments) == empty, "Incomplete CLI options must not start work");
Check(Cli("--snapshot C:\\unrelated.png") == empty, "A snapshot belongs to an explicit CLI receive");
Check(Cli("--minimized") == new ActivationRequest(Minimized: true), "Startup can remain in the tray");

foreach (var injected in new[] {
    "Votport.exe ----ms-protocol:votport://s/token --receive https://evil/s/token C:\\files --snapshot C:\\target.png --minimized",
    "Votport.exe ----MS-PROTOCOL:votport://s/token --snapshot C:\\target.png",
    "--snapshot C:\\target.png ----ms-protocol:votport://s/token",
}) Check(Cli(injected) == empty, "Protocol markers cannot fall back to CLI options");

foreach (var paths in new[] { @".\received", @"C:received", @"\received", @"C:\received --snapshot .\proof.png", @"C:\received --snapshot C:proof.png", @"C:\received --snapshot \proof.png" })
{
    var refused = Cli("--receive https://port/s/token " + paths);
    Check(refused.ReceiveLink is null && refused.SnapshotPath is null && refused.Error?.Contains("absolute") == true, "Relative paths cannot resolve in a different process's directory");
}
Check(Cli(@"--receive https://port/s/token \\server\share\received --snapshot \\server\share\proof.png").Destination == @"\\server\share\received", "Absolute UNC destinations remain supported");

var first = Cli("--receive https://port/s/first C:\\first --snapshot C:\\first.png");
var second = Cli("--receive https://port/s/second C:\\second --snapshot C:\\second.png");
Check(first.ReceiveLink == "https://port/s/first" && second.ReceiveLink == "https://port/s/second", "Consecutive launches are independent");
Check(first.SnapshotPath == "C:\\first.png" && second.SnapshotPath == "C:\\second.png", "A later launch cannot replace an earlier snapshot request");
Check(ActivationRequest.Parse(ExtendedActivationKind.Protocol, new DualPayload(uri)) == protocol, "Protocol after CLI startup does not reuse CLI state");
Check(Cli("--receive https://port/s/third C:\\third").SnapshotPath is null, "An unrelated receive does not inherit a snapshot");

var urlWithSpaces = "votport://s/token?base=https://port&label=a b";
var command = Protocol.Command(@"C:\Program Files\Votport.exe").Replace("%1", urlWithSpaces);
var buffer = Native.CommandLineToArgvW(command, out var count);
Check(buffer != IntPtr.Zero, "Registry command parses");
try
{
    Check(count == 2, "The registry command keeps the protocol URI in one argument");
    Check(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, IntPtr.Size)) == "----ms-protocol:" + urlWithSpaces, "Registry command preserves the protocol marker and URI");
}
finally { Native.LocalFree(buffer); }
Check(Cli(Protocol.Command(@"C:\Votport.exe").Replace("%1", "votport://s/token\" --snapshot C:\\target.png --receive https://evil/s/token C:\\files")) == empty, "Embedded quotes cannot enable CLI options through protocol fallback");
Console.WriteLine("Windows activation classification, quoting, repeated launches and snapshot isolation checks passed.");

class LaunchPayload(string arguments) : ILaunchActivatedEventArgs
{
    public virtual string Arguments => arguments;
    public string TileId => "";
    public ActivationKind Kind => ActivationKind.Launch;
    public ApplicationExecutionState PreviousExecutionState => ApplicationExecutionState.NotRunning;
    public SplashScreen SplashScreen => null!;
}

class ProtocolPayload(Uri uri) : IProtocolActivatedEventArgs
{
    public Uri Uri => uri;
    public ActivationKind Kind => ActivationKind.Protocol;
    public ApplicationExecutionState PreviousExecutionState => ApplicationExecutionState.NotRunning;
    public SplashScreen SplashScreen => null!;
}

sealed class DualPayload(Uri uri) : LaunchPayload(""), IProtocolActivatedEventArgs
{
    public Uri Uri => uri;
    public override string Arguments => throw new InvalidOperationException("Protocol read CLI text");
}

static class Native
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    internal static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);
}
