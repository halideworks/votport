import AppKit
import SwiftUI
import VotportCore

/// The menu bar panel: what is under way, live, with the core's status
/// line, bar, and the controls a person reaches for from the menu bar.
struct MenuPanel: View {
    @EnvironmentObject private var store: TransferStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image("Mark")
                    .resizable()
                    .frame(width: 22, height: 22)
                Text("votport")
                    .font(Type.sans(13, .semibold, relativeTo: .body))
                Spacer()
                Text(headline)
                    .font(Type.caption)
                    .foregroundStyle(Tokens.muted)
            }
            if store.items.isEmpty {
                Text("Nothing under way. Ship files or receive a delivery from the window.")
                    .font(Type.callout)
                    .foregroundStyle(Tokens.muted)
                    .padding(.vertical, 6)
            } else {
                ForEach(store.items.prefix(6)) { item in
                    PanelRow(item: item)
                }
            }
            Divider()
            HStack {
                Button("Open votport") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
                    .keyboardShortcut("q")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Tokens.progress)
            .font(Type.callout)
        }
        .padding(14)
        .frame(width: 360)
        .background(Tokens.bg)
        .foregroundStyle(Tokens.text)
        .font(Type.body)
    }

    private var headline: String {
        let active = store.active.count
        switch active {
        case 0: return "All quiet"
        case 1: return "1 under way"
        default: return "\(active) under way"
        }
    }
}

/// One transfer in the panel: subject, the core's status line, the bar,
/// and Pause, Resume, or Cancel.
struct PanelRow: View {
    @EnvironmentObject private var store: TransferStore
    let item: TransferItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Image(systemName: item.kind == .send ? "sailboat" : "arrow.down.doc")
                    .foregroundStyle(Tokens.muted)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.subject)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(Format.statusLine(item))
                        .font(Type.caption.monospacedDigit())
                        .foregroundStyle(color)
                }
                Spacer()
                controls
            }
            if let view = item.view, let total = view.totalBytes {
                ProgressView(value: Double(view.movedBytes), total: Double(max(total, 1)))
                    .tint(view.phase == .done ? Tokens.ok : Tokens.progress)
            }
        }
        .padding(10)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private var controls: some View {
        HStack(spacing: 6) {
            if item.running {
                Button("Pause") { store.pause(item.id) }
                Button("Cancel") { store.cancel(item.id) }
            } else if item.canResume && !item.needsPassword {
                Button(item.interrupted || item.view?.phase == .paused ? "Resume" : "Retry") {
                    store.resume(item.id, password: nil)
                }
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
    }

    private var color: Color {
        switch item.view?.phase {
        case .done: return Tokens.ok
        case .failed: return Tokens.danger
        default: return Tokens.muted
        }
    }
}
