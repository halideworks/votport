import SwiftUI

/// The votport type: Plus Jakarta Sans for text and JetBrains Mono for
/// hashes and paths, bundled under the OFL from client/design/fonts. Every
/// size scales with the text style it stands in for, so Dynamic Type and
/// the accessibility sizes still apply.
enum Type {
    static let sansFamily = "Plus Jakarta Sans"
    static let monoFamily = "JetBrains Mono"

    static func sans(_ size: CGFloat, _ weight: Font.Weight = .regular, relativeTo style: Font.TextStyle) -> Font {
        Font.custom(sansFamily, size: size, relativeTo: style).weight(weight)
    }

    static func mono(_ size: CGFloat, relativeTo style: Font.TextStyle) -> Font {
        Font.custom(monoFamily, size: size, relativeTo: style)
    }

    static let body = sans(13, relativeTo: .body)
    static let callout = sans(12, relativeTo: .callout)
    static let caption = sans(11, relativeTo: .caption)
    static let label = sans(11, .semibold, relativeTo: .caption)
    static let monoBody = mono(12.5, relativeTo: .body)
    static let monoCallout = mono(12, relativeTo: .callout)
}
