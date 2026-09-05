using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Votport;

/// Token colours for the theme an element is actually drawn in. XAML's
/// ThemeResource follows a system theme flip on its own; code that paints
/// (the caption buttons, a brush swapped in code) reads the generated
/// Tokens.xaml dictionary for the element's ActualTheme instead of the
/// application-level lookup, which is fixed at startup.
public static class Theme
{
    private static object Lookup(FrameworkElement element, string key)
    {
        var theme = element.ActualTheme != ElementTheme.Light ? "Default" : "Light";
        // XamlControlsResources is merged too and carries the same theme
        // names, so the block is chosen by the key it holds.
        foreach (var merged in Application.Current.Resources.MergedDictionaries)
        {
            if (merged.ThemeDictionaries.TryGetValue(theme, out var block)
                && block is ResourceDictionary dictionary
                && dictionary.TryGetValue(key, out var value))
            {
                return value;
            }
        }
        throw new InvalidOperationException($"{key} is not in Tokens.xaml");
    }

    public static Windows.UI.Color Color(FrameworkElement element, string key) => (Windows.UI.Color)Lookup(element, key);

    public static Brush Brush(FrameworkElement element, string key) => (Brush)Lookup(element, key + "Brush");
}
