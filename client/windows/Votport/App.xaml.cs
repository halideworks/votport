using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;

namespace Votport;

public partial class App : Application
{
    public static MainWindow? Window { get; private set; }

    public App()
    {
        InitializeComponent();
        // A XAML failure otherwise dies as 0xc000027b with no message; the
        // log beside the executable names it. The domain hook covers threads
        // the dispatcher never sees.
        UnhandledException += (_, e) => CrashLog.Append(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => CrashLog.Append(e.ExceptionObject as Exception);
    }

    protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        // One instance: a votport: link opened while the app runs reaches the
        // running window instead of starting a second app.
        var activation = AppInstance.GetCurrent().GetActivatedEventArgs();
        var main = AppInstance.FindOrRegisterForKey("main");
        if (!main.IsCurrent)
        {
            await main.RedirectActivationToAsync(activation);
            Exit();
            return;
        }
        var dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
        main.Activated += (_, e) => dispatcher.TryEnqueue(() => Activate(e));

        Window = new MainWindow();
        Protocol.RegisterIfUnpackaged();
        // The Run value names this executable; a moved or updated build
        // rewrites it so the next boot still finds the app.
        if (Settings.StartWithWindows) Settings.StartWithWindows = true;
        TransferStore.Shared.LoadPending();
        PortStore.Shared.Load();
        TransferStore.Shared.StartWatching();
        if (TransferStore.Shared.Items.Count > 0) Window.Show("transfers");
        Activate(activation);
    }

    /// Quit from the tray menu or the tray panel.
    public static void Quit()
    {
        Window?.QuitFromTray();
        Current.Exit();
    }

    private static void Activate(AppActivationArguments activation)
    {
        var request = ActivationRequest.Parse(activation.Kind, activation.Data);
        Window?.ShowActivationError(request.Error);
        if (request.Minimized) Window?.AppWindow.Hide();
        else Window?.Raise();
        if (request.Protocol is Uri uri) Launch.OpenUrl(uri);
        else if (request.ReceiveLink is string link && request.Destination is string destination)
        {
            TransferStore.Shared.Receive(link, null, destination, request.SnapshotPath);
            Window?.Show("transfers");
        }
    }
}
