import OSLog
import SwiftUI
import VotportCore

private let launchLog = Logger(subsystem: "com.halideworks.votport", category: "launch")

@main
struct VotportApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var store = TransferStore.shared

    var body: some Scene {
        WindowGroup(id: "main") {
            MainWindow()
                .environmentObject(store)
                .frame(minWidth: 720, minHeight: 460)
        }
        .defaultSize(width: 900, height: 580)
        MenuBarExtra {
            MenuBarContent()
                .environmentObject(store)
        } label: {
            Image(systemName: store.active.isEmpty ? "arrow.up.arrow.down.circle" : "arrow.up.arrow.down.circle.fill")
        }
    }
}

/// The four sections the design names; the transfer list is the rest of the
/// app.
enum Screen: String, CaseIterable, Identifiable {
    case send = "Ship"
    case receive = "Receive"
    case transfers = "Transfers"
    case settings = "Settings"

    // The sidebar's selection binding holds a Screen, so the row id must be
    // the Screen itself: a string id matches no selection and the rows
    // ignore clicks.
    var id: Self { self }

    var symbol: String {
        switch self {
        case .send: return "sailboat"
        case .receive: return "arrow.down.doc"
        case .transfers: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        }
    }
}

struct MainWindow: View {
    @EnvironmentObject private var store: TransferStore
    @State private var section: Screen? = .send
    @State private var urlChoseSection = false

    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 0) {
                // The web masthead's mark: the ship on its square, the name.
                HStack(spacing: 8) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 26, height: 26)
                    Text("votport")
                        .font(Type.sans(14, .semibold, relativeTo: .body))
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 10)
                List(Screen.allCases, selection: $section) { section in
                    Label(section.rawValue, systemImage: section.symbol)
                        .badge(section == .transfers ? store.active.count : 0)
                }
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            switch section ?? .send {
            case .send: SendView()
            case .receive: ReceiveView()
            case .transfers: TransfersView()
            case .settings: SettingsView()
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
        .onOpenURL { url in
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

/// The menu bar item: the active transfers and their rates, from the core's
/// views.
struct MenuBarContent: View {
    @EnvironmentObject private var store: TransferStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if store.active.isEmpty {
            Text("Nothing under way")
        } else {
            ForEach(store.active) { item in
                Text(Format.menuLine(item))
            }
        }
        Divider()
        Button("Open votport") {
            // Reuses the main window or makes a new one after it was closed.
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
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
