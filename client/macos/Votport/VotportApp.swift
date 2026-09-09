import OSLog
import SwiftUI
import VotportCore

private let launchLog = Logger(subsystem: "com.halideworks.votport", category: "launch")

@main
struct VotportApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var store = TransferStore.shared
    @StateObject private var port = PortStore.shared

    var body: some Scene {
        WindowGroup(id: "main") {
            MainWindow()
                .environmentObject(store)
                .environmentObject(port)
                .frame(minWidth: 720, minHeight: 460)
        }
        .defaultSize(width: 900, height: 580)
        // The menu bar uses the system menu layout and appearance.
        MenuBarExtra {
            MenuPanel()
                .environmentObject(store)
        } label: {
            Image(systemName: store.active.isEmpty ? "sailboat" : "sailboat.fill")
        }
        .menuBarExtraStyle(.menu)
    }
}

/// Sharing and link management appear once the operator signs in to a port.
enum Screen: String, CaseIterable, Identifiable {
    case send = "Send"
    case receive = "Receive"
    case share = "Share"
    case links = "Manage links"
    case transfers = "Transfers"
    case settings = "Settings"
    case workflows = "Workflows"

    // The sidebar's selection binding holds a Screen, so the row id must be
    // the Screen itself: a string id matches no selection and the rows
    // ignore clicks.
    var id: Self { self }

    var symbol: String {
        switch self {
        // The same glyph as the Windows shell's Send icon.
        case .send: return "paperplane"
        case .receive: return "arrow.down.doc"
        case .share: return "square.and.arrow.up"
        case .links: return "link"
        case .transfers: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        case .workflows: return "checkmark.seal"
        }
    }

    /// Whether the screen needs a signed-in port.
    var operator_: Bool {
        self == .share || self == .links
    }
}

struct MainWindow: View {
    @EnvironmentObject private var store: TransferStore
    @EnvironmentObject private var port: PortStore
    @State private var section: Screen? = .send
    @State private var urlChoseSection = false

    private var screens: [Screen] {
        Screen.allCases.filter { port.signedIn || !$0.operator_ }
    }

    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 0) {
                // The web masthead's mark: the ship on its square, the name.
                // The Mark asset, not the app icon: the icon sits inset on
                // Apple's grid and would draw smaller than Windows' 24 pt mark.
                HStack(spacing: 8) {
                    Image("Mark")
                        .resizable()
                        .frame(width: 24, height: 24)
                    Text("votport")
                        .font(Type.sans(14, .semibold, relativeTo: .body))
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 10)
                List(screens, selection: $section) { section in
                    Label(section.rawValue, systemImage: section.symbol)
                        .badge(section == .transfers ? store.active.count : 0)
                }
                if let signed = port.port {
                    Text(signed.base.replacingOccurrences(of: "https://", with: ""))
                        .font(Type.caption)
                        .foregroundStyle(Tokens.muted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .padding(.horizontal, 16)
                        .padding(.bottom, 10)
                }
            }
            // With no max the sidebar animates to its ideal width, then snaps
            // to the last dragged width at the end: the "catch" on expand.
            .navigationSplitViewColumnWidth(min: 160, ideal: 180, max: 240)
        } detail: {
            switch section ?? .send {
            case .send: SendView()
            case .receive: ReceiveView()
            case .share: DeliverView(manageLinks: { section = .links })
            case .links: LinksView(share: { section = .share })
            case .transfers: TransfersView()
            case .settings: SettingsView()
            case .workflows: WorkflowsView()
            }
        }
        .background(Tokens.bg)
        .foregroundStyle(Tokens.text)
        .font(Type.body)
        .onAppear {
            if Launch.done || store.items.contains(where: \.interrupted) {
                section = .transfers
            }
        }
        // The journal is read from the app delegate, which can run after the
        // window is already up; an interrupted transfer still opens the list,
        // unless a votport:// link already chose a screen this launch.
        .onChange(of: store.items.contains(where: \.interrupted)) { _, interrupted in
            if interrupted && !urlChoseSection { section = .transfers }
        }
        // Signing out while on an operator screen lands on Settings.
        .onChange(of: port.signedIn) { _, signedIn in
            // The list loses its operator rows in the same update, which can
            // clear the selection before this runs; either way land on
            // Settings.
            if !signedIn && (section == nil || section?.operator_ == true) { section = .settings }
        }
        .onOpenURL { url in
            if url.scheme == "votport", url.host == "signin" {
                port.completeSso(url)
                section = .settings
                return
            }
            // votport://r/<token>?base=<origin> opens Send with the request
            // link; votport://s/<token>?base=<origin> opens Receive with the
            // delivery link. The web pages offer both as "Open in the app".
            // Any page can emit one, so the link is only prefilled: the full
            // origin is visible in the field and nothing moves until the user
            // presses Send or Receive.
            guard let link = Launch.webLink(from: url) else { return }
            urlChoseSection = true
            if url.host == "r" {
                store.prefillSend = link
                section = .send
            } else {
                store.prefillReceive = link
                section = .receive
            }
        }
    }
}

/// Launch-time work that must not wait for a window to appear: a locked
/// screen never shows one, and a headless run still has to move bytes.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // The bundled families register through ATSApplicationFontsPath; a
        // headless run reads this line to know the type resolved.
        let families = NSFontManager.shared.availableFontFamilies
        launchLog.notice(
            "fonts: sans \(families.contains(Type.sansFamily)) mono \(families.contains(Type.monoFamily))")
        MainActor.assumeIsolated {
            TransferStore.shared.loadPending()
            PortStore.shared.load()
            TransferStore.shared.startWatching()
            _ = Launch.startFromArguments(store: .shared)
        }
    }
}

/// `Votport --receive <link> <dir>` starts a receive at launch, once per
/// process; `votport://` links from the web pages prefill a screen.
enum Launch {
    /// The web link a `votport://r/<token>?base=<origin>` or
    /// `votport://s/<token>?base=<origin>` URL names, or nil for any other
    /// shape: an http or https base with a host, and a one-component token.
    static func webLink(from url: URL) -> String? {
        guard url.scheme == "votport", let kind = url.host, kind == "r" || kind == "s",
            url.pathComponents.count == 2, let token = url.pathComponents.last, !token.isEmpty,
            let base = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "base" })?.value,
            let origin = URL(string: base), let scheme = origin.scheme,
            scheme == "https" || scheme == "http", origin.host != nil,
            origin.path.isEmpty || origin.path == "/", origin.query == nil, origin.user == nil
        else { return nil }
        let trimmed = base.hasSuffix("/") ? String(base.dropLast()) : base
        return "\(trimmed)/\(kind)/\(token)"
    }

    // Process-wide: a second window (Cmd+N, Dock reopen) must not rerun it.
    private(set) static var done = false

    @MainActor
    static func startFromArguments(
        store: TransferStore, _ arguments: [String] = CommandLine.arguments
    ) -> Bool {
        guard !done, let flag = arguments.firstIndex(of: "--receive"),
            arguments.count > flag + 2
        else { return false }
        done = true
        store.receive(
            link: arguments[flag + 1], password: nil,
            destination: URL(fileURLWithPath: arguments[flag + 2]))
        return true
    }
}
