import AppKit
import SwiftUI
import VotportCore

enum Prefs {
    static let receiveFolderKey = "receiveFolder"
    static let notifyKey = "notifyOnEnd"
}

struct SettingsView: View {
    @AppStorage(Prefs.receiveFolderKey) private var receiveFolder = ""
    @AppStorage(Prefs.notifyKey) private var notify = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SETTINGS")
                .font(.caption.weight(.semibold))
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            Form {
                LabeledContent("Receive into") {
                    HStack {
                        Text(receiveFolder.isEmpty ? "Ask each time" : receiveFolder)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Choose") { choose() }
                        if !receiveFolder.isEmpty {
                            Button("Clear") { receiveFolder = "" }
                        }
                    }
                }
                Toggle("Notify when a transfer ends", isOn: $notify)
                LabeledContent("Core", value: coreVersion())
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            Spacer()
        }
        .padding(20)
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url {
            receiveFolder = url.path
        }
    }
}
