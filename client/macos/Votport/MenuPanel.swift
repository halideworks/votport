import SwiftUI

/// Native menu-bar controls follow the system's appearance and menu behavior.
struct MenuPanel: View {
    @EnvironmentObject private var store: TransferStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(headline)
        ForEach(store.items.prefix(6)) { item in
            Menu {
                Text(Format.statusLine(item))
                if item.running {
                    Button("Pause") { store.pause(item.id) }
                    Button("Cancel") { store.cancel(item.id) }
                } else if item.canResume && !item.needsPassword {
                    Button(item.interrupted || item.view?.phase == .paused ? "Resume" : "Retry") {
                        store.resume(item.id, password: nil)
                    }
                }
            } label: {
                Label(item.subject, systemImage: item.kind == .send ? "sailboat" : "arrow.down.doc")
            }
        }
        Divider()
        Button("Open Votport") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit Votport") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var headline: String {
        switch store.active.count {
        case 0: return "All quiet"
        case 1: return "1 transfer under way"
        default: return "\(store.active.count) transfers under way"
        }
    }
}
