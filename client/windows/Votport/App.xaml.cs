using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;

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
        main.Activated += (_, e) => Window?.DispatcherQueue.TryEnqueue(() =>
        {
            // A link clicked in a browser reaches an app that may be minimized
            // or behind other windows.
            Window.Raise();
            Activate(e);
        });

        Window = new MainWindow();
        // Started with Windows: stay in the tray until the icon is clicked.
        if (Environment.GetCommandLineArgs().Contains("--minimized")) Window.AppWindow.Hide();
        else Window.Activate();
        Protocol.RegisterIfUnpackaged();
        // The Run value names this executable; a moved or updated build
        // rewrites it so the next boot still finds the app.
        if (Settings.StartWithWindows) Settings.StartWithWindows = true;
        TransferStore.Shared.LoadPending();
        PortStore.Shared.Load();
        TransferStore.Shared.StartWatching();
        if (TransferStore.Shared.Items.Count > 0) Window.Show("transfers");
        // Launch-time work must not wait for the window: a headless run
        // (over ssh, into the console session) still has to move bytes.
        Launch.StartFromArguments(Environment.GetCommandLineArgs());
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
        if (activation.Kind != ExtendedActivationKind.Protocol) return;
        if (activation.Data is IProtocolActivatedEventArgs protocol)
        {
            Launch.OpenUrl(protocol.Uri);
        }
    }
}
