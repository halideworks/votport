using Microsoft.UI.Xaml.Controls;
using Votport;

static void Check(uint? actual, uint? expected, double input)
{
    if (actual != expected)
        throw new InvalidOperationException($"{input}: expected {expected}, got {actual}");
}

foreach (var (input, expected) in new (double, uint?)[]
{
    (0, null),
    (double.NaN, null),
    (double.NegativeInfinity, null),
    (-0.5, null),
    (0.49, null),
    (0.5, 1),
    (1.49, 1),
    (1.5, 2),
    (3650, 3650),
    (double.PositiveInfinity, uint.MaxValue),
})
{
    Check(Numeric.Whole(new NumberBox { Value = input }), expected, input);
}

Console.WriteLine("Windows numeric conversion checks passed.");
