import AppKit
import SwiftUI
import VotportCore

/// The transfer list: every transfer of the session, newest first. A
/// clicked transfer expands to its files; nothing is selected or marked.
struct TransfersView: View {
    @EnvironmentObject private var store: TransferStore
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var expanded: UUID?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("TRANSFERS")
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            if store.items.isEmpty {
                Spacer()
                Text("Nothing under way. Ship files or receive a delivery.")
                    .foregroundStyle(Tokens.muted)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(store.items) { item in
                            TransferCard(item: item, expanded: expanded == item.id) {
                                withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.15)) {
                                    expanded = expanded == item.id ? nil : item.id
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding(20)
        .onAppear { expanded = expanded ?? store.items.first?.id }
    }
}

struct TransferCard: View {
    @EnvironmentObject private var store: TransferStore
    let item: TransferItem
    let expanded: Bool
    let toggle: () -> Void
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: item.kind == .send ? "sailboat" : "arrow.down.doc")
                    .foregroundStyle(Tokens.muted)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.subject)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(Format.statusLine(item))
                        .font(Type.caption.monospacedDigit())
                        .foregroundStyle(statusColor)
                }
                Spacer()
                if item.running {
                    Button("Pause") { store.pause(item.id) }
                    Button("Cancel") { store.cancel(item.id) }
                } else {
                    if item.canResume {
                        if item.needsPassword {
                            PasswordField("Password", text: $password)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 160)
                        }
                        Button(item.interrupted || item.view?.phase == .paused ? "Resume" : "Retry") {
                            store.resume(item.id, password: password.isEmpty ? nil : password)
                            password = ""
                        }
                        .disabled(item.needsPassword && password.isEmpty)
                    }
                    if item.kind == .receive, !item.landed.isEmpty {
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting(
                                item.landed.map { URL(fileURLWithPath: $0) })
                        }
                    }
                    Button("Remove") { store.remove(item.id) }
                }
            }
            if let view = item.view {
                if let total = view.totalBytes {
                    ProgressView(value: Double(view.movedBytes), total: Double(max(total, 1)))
                        .tint(view.phase == .done ? Tokens.ok : Tokens.progress)
                } else if item.running {
                    ProgressView()
                }
                if expanded {
                    if let route = view.route {
                        Text(route)
                            .font(Type.caption)
                            .foregroundStyle(Tokens.muted)
                    }
                    if let detail = view.detail {
                        Text(detail)
                            .font(Type.caption)
                            .foregroundStyle(Tokens.muted)
                            .textSelection(.enabled)
                    }
                    ForEach(view.files, id: \.index) { file in
                        FileRowView(file: file)
                    }
                }
            }
        }
        .padding(14)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
        .onTapGesture(perform: toggle)
    }

    private var statusColor: Color {
        switch item.view?.phase {
        case .done: return Tokens.ok
        case .failed: return Tokens.danger
        default: return Tokens.muted
        }
    }
}

/// One file of a transfer, drawn from the core's row.
struct FileRowView: View {
    let file: FileView

    var body: some View {
        HStack {
            Text(file.path)
                .font(Type.monoCallout)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            ProgressView(value: Double(file.moved), total: Double(max(file.bytes, 1)))
                .frame(width: 120)
                .tint(file.state == .verified ? Tokens.ok : Tokens.progress)
            Text(file.label)
                .font(Type.caption.monospacedDigit())
                .foregroundStyle(file.state == .verified ? Tokens.ok : Tokens.muted)
                .frame(width: 150, alignment: .trailing)
        }
    }
}

/// The core's words, joined for the places that show them. Nothing is
/// computed or formatted here.
enum Format {
    /// The core's status line, or the two states only the shell knows: a
    /// journal entry not yet run, and a transfer the core has not answered.
    static func statusLine(_ item: TransferItem) -> String {
        if item.interrupted { return "Interrupted before it finished" }
        guard let view = item.view else { return item.running ? "Starting" : "Failed" }
        return view.status
    }

    static func menuLine(_ item: TransferItem) -> String {
        var line = item.subject
        if let rate = item.view?.rateText {
            line += "  \(rate)"
        }
        return line
    }
}
