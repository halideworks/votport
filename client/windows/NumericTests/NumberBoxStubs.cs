namespace Microsoft.UI.Xaml.Controls
{
    public sealed class NumberBox
    {
        public double Value { get; set; }
        public object? NumberFormatter { get; set; }
    }
}

namespace Windows.Globalization.NumberFormatting
{
    public enum RoundingAlgorithm
    {
        RoundHalfUp,
    }

    public sealed class DecimalFormatter
    {
        public int IntegerDigits { get; set; }
        public int FractionDigits { get; set; }
        public bool IsGrouped { get; set; }
        public IncrementNumberRounder? NumberRounder { get; set; }
    }

    public sealed class IncrementNumberRounder
    {
        public uint Increment { get; set; }
        public RoundingAlgorithm RoundingAlgorithm { get; set; }
    }
}
