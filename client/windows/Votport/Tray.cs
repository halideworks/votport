using System.Runtime.InteropServices;

namespace Votport;

/// The tray icon, through the shell's own notification area API on a hidden
/// message window: left click opens transfers, right click opens the menu.
public sealed class Tray : IDisposable
{
    private const uint WmApp = 0x8000;
    private const uint WmTray = WmApp + 1;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonUp = 0x0205;
    private const uint NifMessage = 0x1, NifIcon = 0x2, NifTip = 0x4;
    private const uint NimAdd = 0, NimModify = 1, NimDelete = 2;

    private readonly WndProc procedure;
    private readonly IntPtr window;
    private readonly IntPtr icon;
    private readonly Action panel;
    private readonly Action menu;
    private bool disposed;

    public Tray(string iconPath, Action panel, Action menu)
    {
        this.panel = panel;
        this.menu = menu;
        procedure = Procedure;
        var instance = GetModuleHandle(null);
        var cls = new WndClass
        {
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(procedure),
            hInstance = instance,
            lpszClassName = "VotportTray",
        };
        RegisterClass(ref cls);
        window = CreateWindowEx(0, "VotportTray", "votport", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        icon = LoadImage(IntPtr.Zero, iconPath, 1, 16, 16, 0x10);
        var data = Data();
        data.uFlags = NifMessage | NifIcon | NifTip;
        data.uCallbackMessage = WmTray;
        data.hIcon = icon;
        data.szTip = "votport";
        Shell_NotifyIcon(NimAdd, ref data);
    }

    public void SetTip(string tip)
    {
        if (disposed) return;
        var data = Data();
        data.uFlags = NifTip;
        data.szTip = tip.Length > 120 ? tip[..120] : tip;
        Shell_NotifyIcon(NimModify, ref data);
    }

    private NotifyIconData Data() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
        hWnd = window,
        uID = 1,
    };

    private IntPtr Procedure(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == WmTray)
        {
            var mouse = (uint)(lParam.ToInt64() & 0xffff);
            if (mouse == WmLButtonUp) panel();
            else if (mouse == WmRButtonUp) menu();
            return IntPtr.Zero;
        }
        return DefWindowProc(hwnd, message, wParam, lParam);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        var data = Data();
        Shell_NotifyIcon(NimDelete, ref data);
        DestroyWindow(window);
        if (icon != IntPtr.Zero) DestroyIcon(icon);
    }

    private delegate IntPtr WndProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClass
    {
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern ushort RegisterClass(ref WndClass cls);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowEx(uint exStyle, string cls, string name, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr DefWindowProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadImage(IntPtr instance, string name, uint type, int cx, int cy, uint load);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string? module);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIcon(uint message, ref NotifyIconData data);
}
