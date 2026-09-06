import SwiftUI

/// A password field with a reveal toggle: dots by default, the text when
/// the eye is on. Takes the surrounding text field style like any field.
struct PasswordField: View {
    let title: String
    @Binding var text: String
    @State private var revealed = false
    @FocusState private var focused: Bool

    init(_ title: String, text: Binding<String>) {
        self.title = title
        _text = text
    }

    var body: some View {
        HStack(spacing: 4) {
            if revealed {
                TextField(title, text: $text).focused($focused)
            } else {
                SecureField(title, text: $text).focused($focused)
            }
            Button {
                // The swap makes a new field; the caret follows it.
                let hadFocus = focused
                revealed.toggle()
                if hadFocus { DispatchQueue.main.async { focused = true } }
            } label: {
                Image(systemName: revealed ? "eye.slash" : "eye")
                    .foregroundStyle(Tokens.muted)
            }
            .buttonStyle(.plain)
            .help(revealed ? "Hide the password" : "Show the password")
            .accessibilityLabel(revealed ? "Hide password" : "Show password")
        }
    }
}
