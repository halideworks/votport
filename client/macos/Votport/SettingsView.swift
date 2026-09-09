import AppKit
import ServiceManagement
import SwiftUI
import VotportCore

enum Prefs {
    static let receiveFolderKey = "receiveFolder"
    static let notifyKey = "notifyOnEnd"
}

struct SettingsView: View {
    @EnvironmentObject private var port: PortStore
    @AppStorage(Prefs.receiveFolderKey) private var receiveFolder = ""
    @AppStorage(Prefs.notifyKey) private var notify = true
    @State private var openAtLogin = Self.registered
    @State private var loginProblem: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("SETTINGS")
                    .font(Type.label)
                    .tracking(1.5)
                    .foregroundStyle(Tokens.muted)

                HomePortSection()
                if port.signedIn { AgentAccessSection() }

                WatchFoldersSection()

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
            }
            .padding(20)
        }
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

/// The votport this app is signed in to. Signed in, the sidebar gains Links
/// and Deliver and Ship offers the open request links.
struct HomePortSection: View {
    @EnvironmentObject private var port: PortStore
    @State private var base = ""
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("HOME PORT")
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            if let signed = port.port {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Signed in to \(signed.base)")
                        if !signed.tenant.isEmpty {
                            Text("Tenant \(signed.tenant)")
                                .font(Type.caption)
                                .foregroundStyle(Tokens.muted)
                        }
                        Text("Issue links, deliver from the library, and see what lands.")
                            .font(Type.caption)
                            .foregroundStyle(Tokens.muted)
                    }
                    Spacer()
                    Button("Sign out") { port.signOut() }
                }
            } else {
                Text("Sign in to your votport to issue links and deliver from its library.")
                    .font(Type.callout)
                    .foregroundStyle(Tokens.muted)
                HStack {
                    TextField("https://drop.example", text: $base)
                        .textFieldStyle(.roundedBorder)
                        .disabled(port.signingInBrowser)
                    PasswordField("Admin password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 180)
                    Button("Sign in") {
                        port.signIn(base: base, password: password)
                        password = ""
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(base.trimmingCharacters(in: .whitespaces).isEmpty || password.isEmpty || port.busy || port.signingInBrowser)
                }
                HStack {
                    if port.signingInBrowser {
                        Text("Complete sign-in in your browser.")
                            .font(Type.caption)
                            .foregroundStyle(Tokens.muted)
                        Button("Cancel sign-in") { port.cancelSso() }
                    } else {
                        Button("Sign in with SSO") { port.beginSso(base: base) }
                            .disabled(base.trimmingCharacters(in: .whitespaces).isEmpty || port.busy)
                    }
                }
                if let problem = port.problem(for: .port) {
                    Text(problem)
                        .font(Type.callout)
                        .foregroundStyle(Tokens.danger)
                }
            }
        }
        .padding(14)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// Folders whose settled drops ship on their own to a request link.
struct WatchFoldersSection: View {
    @EnvironmentObject private var port: PortStore
    @State private var folder: URL?
    @State private var link = ""
    @State private var password = ""
    @StateObject private var previewer = LinkPreviewer(expect: .request)

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("WATCH FOLDERS")
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            Text("Anything placed in a watched folder ships to its request link once it holds still, then moves into a shipped folder inside it.")
                .font(Type.callout)
                .foregroundStyle(Tokens.muted)
            ForEach(port.watches, id: \.id) { watch in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(watch.dir)
                            .font(Type.monoBody)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(watch.link)
                            .font(Type.monoCallout)
                            .foregroundStyle(Tokens.muted)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                    Button("Remove") { port.removeWatch(watch.id) }
                }
                .padding(10)
                .background(Tokens.panelHover)
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                Button("Choose Folder") { choose() }
                Text(folder?.path ?? "No folder chosen")
                    .font(Type.monoBody)
                    .foregroundStyle(Tokens.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            HStack {
                TextField("Request link", text: $link)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: link) { _, value in previewer.update(value) }
                if !port.requests.isEmpty {
                    Menu("Ship to") {
                        ForEach(port.requests) { request in
                            Button(request.label) { link = request.url }
                        }
                    }
                    .frame(width: 100)
                }
                if previewer.needsPassword {
                    PasswordField("Password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 140)
                }
                Button("Watch") {
                    guard let folder else { return }
                    // The form clears only once the watch took; a refusal
                    // keeps the folder and the link to try again from.
                    port.addWatch(dir: folder.path, link: link, password: password.isEmpty ? nil : password) { added in
                        guard added else { return }
                        link = ""
                        password = ""
                        self.folder = nil
                    }
                }
                .disabled(folder == nil || !previewer.ready || port.busy)
            }
            if let line = PreviewLine.text(previewer) {
                Text(line)
                    .font(Type.callout)
                    .foregroundStyle(PreviewLine.isProblem(previewer) ? Tokens.danger : Tokens.muted)
            }
            if let problem = port.problem(for: .watch) {
                Text(problem)
                    .font(Type.callout)
                    .foregroundStyle(Tokens.danger)
            }
        }
        .padding(14)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Watch"
        if panel.runModal() == .OK {
            folder = panel.url
        }
    }
}


struct AgentAccessSection: View {
    @EnvironmentObject private var port: PortStore
    @State private var expanded = false
    @State private var label = ""
    @State private var directory = ""
    @State private var days = 30
    @State private var browse = true
    @State private var create = true
    @State private var activity = true
    @State private var revoke = false
    @State private var issued: IssuedAutomationToken?
    @State private var revokeId: String?

    private var permissions: [String] {
        [("library:read", browse), ("deliveries:create", create), ("deliveries:read", activity), ("deliveries:revoke", revoke)].compactMap { $0.1 ? $0.0 : nil }
    }

    var body: some View {
        DisclosureGroup("Agent access", isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Give an agent access to a library folder and the deliveries it creates.")
                    .font(Type.caption).foregroundStyle(Tokens.muted)
                TextField("Agent label", text: $label).textFieldStyle(.roundedBorder)
                TextField("Library folder (required)", text: $directory).textFieldStyle(.roundedBorder)
                Stepper("Expires after \(days) days", value: $days, in: 1...365)
                Toggle("Browse files", isOn: $browse)
                Toggle("Create delivery links", isOn: $create)
                Toggle("Read delivery activity and receipts", isOn: $activity)
                Toggle("Revoke its delivery links", isOn: $revoke)
                HStack {
                    Button("Issue token") {
                        port.createAutomationToken(AutomationTokenSpec(label: label, directory: directory, expiresDays: UInt32(days), permissions: permissions)) { result in
                            if let result { issued = result }
                        }
                    }.disabled(port.busy || label.trimmingCharacters(in: .whitespaces).isEmpty || directory.trimmingCharacters(in: .whitespaces).isEmpty || permissions.isEmpty)
                    Button("Refresh") { port.refreshAutomationTokens() }.disabled(port.busy)
                }
                if let issued {
                    Text("Copy this token now. It is shown only once.").font(Type.caption)
                    Text(issued.token).font(Type.monoBody).textSelection(.enabled)
                    Button("Copy token") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(issued.token, forType: .string)
                    }
                    if let command = Bundle.main.url(forResource: "votport-cli", withExtension: nil), let base = port.port?.base {
                        Button("Copy MCP configuration") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(automationMcpConfig(command: command.path, base: base, token: issued.token), forType: .string)
                        }
                    }
                }
                if let problem = port.problem(for: .agents) {
                    Text(problem).foregroundStyle(Tokens.danger)
                }
                ForEach(port.automationTokens, id: \.id) { token in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(token.label)
                            Spacer()
                            if token.revokedAt == nil {
                                Button("Revoke token", role: .destructive) { revokeId = token.id }.disabled(port.busy)
                                    .accessibilityLabel("Revoke token for \(token.label)")
                            } else { Text("Revoked").foregroundStyle(Tokens.muted) }
                        }
                        Text(token.directory ?? "Any folder").font(Type.monoBody)
                        Text(token.permissions.map { ["library:read": "Browse files", "deliveries:create": "Create deliveries", "deliveries:read": "Read activity", "deliveries:revoke": "Revoke deliveries"][$0] ?? $0 }.joined(separator: ", ")).font(Type.caption)
                        Text("Expires \(Date(timeIntervalSince1970: Double(token.expiresAt)).formatted())").font(Type.caption)
                        if let at = token.lastUsedAt {
                            Text("Last used \(Date(timeIntervalSince1970: Double(at)).formatted())").font(Type.caption)
                        }
                    }
                }
            }.padding(.top, 10)
        }
        .padding(14).background(Tokens.panel).clipShape(RoundedRectangle(cornerRadius: 8))
        .onChange(of: expanded) { _, open in if open { port.refreshAutomationTokens() } else { issued = nil } }
        .confirmationDialog("Revoke this agent's token? Its automation will stop working.", isPresented: Binding(get: { revokeId != nil }, set: { if !$0 { revokeId = nil } })) {
            Button("Revoke token", role: .destructive) { if let id = revokeId { port.revokeAutomationToken(id) }; revokeId = nil }
        }
    }
}
