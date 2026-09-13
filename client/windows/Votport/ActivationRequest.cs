using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;

namespace Votport;

internal sealed record ActivationRequest(Uri? Protocol = null, string? ReceiveLink = null,
    string? Destination = null, string? SnapshotPath = null, bool Minimized = false, string? Error = null)
{
    internal static ActivationRequest Parse(ExtendedActivationKind kind, object? data)
    {
        if (kind == ExtendedActivationKind.Protocol && data is IProtocolActivatedEventArgs protocol)
            return new(Protocol: protocol.Uri);
        if (kind != ExtendedActivationKind.Launch || data is not ILaunchActivatedEventArgs launch)
            return new();
        var arguments = Split(launch.Arguments);
        // A malformed protocol invocation must not fall back to CLI options.
        if (arguments.Any(argument => argument.StartsWith("----ms-protocol:", StringComparison.OrdinalIgnoreCase)))
            return new();
        string? link = null, destination = null, snapshot = null;
        var minimized = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            switch (arguments[index])
            {
                case "--receive":
                    if (index + 2 >= arguments.Length || arguments[index + 1].StartsWith("--") || arguments[index + 2].StartsWith("--")) return new();
                    link = arguments[++index];
                    destination = arguments[++index];
                    break;
                case "--snapshot":
                    if (index + 1 >= arguments.Length || arguments[index + 1].StartsWith("--")) return new();
                    snapshot = arguments[++index];
                    break;
                case "--minimized":
                    minimized = true;
                    break;
            }
        }
        // Redirected launch payloads do not carry the sender's working directory.
        if (link is not null && (!Path.IsPathFullyQualified(destination!) || (snapshot is not null && !Path.IsPathFullyQualified(snapshot))))
            return new(Error: @"Use an absolute destination folder, such as C:\Deliveries, and an absolute path for --snapshot.");
        return new(ReceiveLink: link, Destination: destination, SnapshotPath: link is null ? null : snapshot, Minimized: minimized);
    }

    private static string[] Split(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return Array.Empty<string>();
        // Launch supplies a full command line or arguments only. A dummy argv[0]
        // gives every supplied token the native parser's argument quoting rules.
        var buffer = CommandLineToArgvW("votport " + commandLine, out var count);
        if (buffer == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var arguments = new string[count - 1];
            for (var index = 1; index < count; index++)
                arguments[index - 1] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, index * IntPtr.Size))!;
            return arguments;
        }
        finally { LocalFree(buffer); }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
