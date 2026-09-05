using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;

namespace Votport;

/// `--snapshot <png>` writes the window's own rendering when a transfer
/// ends, so a headless run (over ssh, into the console session) still
/// leaves a picture of what the user would see.
public static class Snapshot
{
    public static void WriteIfRequested()
    {
        var arguments = Environment.GetCommandLineArgs();
        var flag = Array.IndexOf(arguments, "--snapshot");
        if (flag < 0 || arguments.Length <= flag + 1 || App.Window is null) return;
        var path = arguments[flag + 1];
        // One more layout pass so the final phase is drawn before it is read.
        App.Window.DispatcherQueue.TryEnqueue(async () =>
        {
            await Task.Delay(500);
            try
            {
                var bitmap = new RenderTargetBitmap();
                await bitmap.RenderAsync(App.Window.Content);
                var pixels = await bitmap.GetPixelsAsync();
                var folder = await StorageFolder.GetFolderFromPathAsync(
                    System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
                var target = await folder.CreateFileAsync(
                    System.IO.Path.GetFileName(path), CreationCollisionOption.ReplaceExisting);
                using var stream = await target.OpenAsync(FileAccessMode.ReadWrite);
                var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
                encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
                    (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, pixels.ToArray());
                await encoder.FlushAsync();
            }
            catch (Exception)
            {
                // A snapshot is evidence, never a feature; a failure is not
                // the transfer's.
            }
        });
    }
}
