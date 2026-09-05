import AppKit
import ServiceManagement
import SwiftUI
import VotportCore

enum Prefs {
    static let receiveFolderKey = "receiveFolder"
    static let notifyKey = "notifyOnEnd"
}

struct SettingsView: View {
    @AppStorage(Prefs.receiveFolderKey) private var receiveFolder = ""
    @AppStorage(Prefs.notifyKey) private var notify = true
    @State private var openAtLogin = Self.registered
    @State private var loginProblem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SETTINGS")
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            Form {
                LabeledContent("Receive into") {
                    HStack {
                        Text(receiveFolder.isEmpty ? "Ask each time" : receiveFolder)
                            .font(Type.monoBody)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Choose") { choose() }
                        if !receiveFolder.isEmpty {
                            Button("Clear") { receiveFolder = "" }
                        }
                    }
                }
                Toggle("Notify when a transfer ends", isOn: $notify)
                Toggle("Open at login", isOn: $openAtLogin)
                    .onChange(of: openAtLogin) { _, wanted in setOpenAtLogin(wanted) }
                if let loginProblem {
                    Text(loginProblem)
                        .font(Type.caption)
                        .foregroundStyle(Tokens.danger)
                }
                LabeledContent("Core", value: coreVersion())
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            Spacer()
        }
        .padding(20)
    }

    /// Registers or removes the app as a login item through the system's
    /// own service, which asks nothing of the user on first use. The menu
    /// bar item and a closed window already keep it running afterwards.
    /// Registered as a login item, whether enabled or waiting on the
    /// person's approval in System Settings; either way unregister is the
    /// way off.
    private static var registered: Bool {
        switch SMAppService.mainApp.status {
        case .enabled, .requiresApproval: return true
        default: return false
        }
    }

    private func setOpenAtLogin(_ wanted: Bool) {
        // A failure snaps the toggle back, which re-enters here; nothing to
        // do when the system already agrees.
        guard wanted != Self.registered else { return }
        do {
            if wanted {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            loginProblem = nil
        } catch {
            loginProblem = error.localizedDescription
            openAtLogin = Self.registered
        }
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
