using Microsoft.UI.Xaml.Controls;
using Windows.Globalization.NumberFormatting;

namespace Votport;

/// Number entry helpers for the link forms.
public static class Numeric
{
    /// Keeps a NumberBox to whole numbers: a typed fraction rounds half up
    /// in the box's text, so "7.5" days shows 8; Whole rounds the same way,
    /// since the box keeps the unrounded value behind the rounded text.
    public static void Integer(NumberBox box)
    {
        box.NumberFormatter = new DecimalFormatter
        {
            IntegerDigits = 1,
            FractionDigits = 0,
            IsGrouped = false,
            NumberRounder = new IncrementNumberRounder { Increment = 1, RoundingAlgorithm = RoundingAlgorithm.RoundHalfUp },
        };
    }

    /// The box's value as a whole number, or null when it is empty.
    public static uint? Whole(NumberBox box) =>
        double.IsNaN(box.Value) ? null : (uint)Math.Clamp(Math.Round(box.Value, MidpointRounding.AwayFromZero), 0, uint.MaxValue);
}
