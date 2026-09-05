import SwiftUI

// The votport tokens from web/assets/style.css, dark block.
// ponytail: hand-copied; generate client/design/tokens.json from the CSS when a
// second screen needs more than these.
enum Tokens {
    static let bg = Color(red: 0x0b / 255, green: 0x14 / 255, blue: 0x1e / 255)
    static let text = Color(red: 0xf8 / 255, green: 0xfa / 255, blue: 0xfc / 255)
    static let muted = Color(red: 0x88 / 255, green: 0x96 / 255, blue: 0xa6 / 255)
    static let progress = Color(red: 0x38 / 255, green: 0xbd / 255, blue: 0xf8 / 255)
    static let ok = Color(red: 0x5f / 255, green: 0xd4 / 255, blue: 0xa2 / 255)
    static let danger = Color(red: 0xf0 / 255, green: 0x92 / 255, blue: 0x8d / 255)
    static let panel = Color.white.opacity(0.025)
    static let border = Color.white.opacity(0.08)
}
