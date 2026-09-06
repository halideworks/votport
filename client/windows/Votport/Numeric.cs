using Microsoft.UI.Xaml.Controls;

namespace Votport;

/// Keeps a TextBox to digits (and one point for Decimal): anything else
/// typed or pasted is refused before it lands.
public static class Numeric
{
    public static void Digits(TextBox sender, TextBoxBeforeTextChangingEventArgs args) =>
        args.Cancel = !args.NewText.All(char.IsAsciiDigit);

    public static void Decimal(TextBox sender, TextBoxBeforeTextChangingEventArgs args) =>
        args.Cancel = !args.NewText.All(c => char.IsAsciiDigit(c) || c == '.') || args.NewText.Count(c => c == '.') > 1;
}
