import AppKit
import SwiftUI
import VotportCore

/// The transfer list: every transfer of the session, newest first. A
/// selected transfer expands to its files; nothing is marked with a border.
struct TransfersView: View {
    @EnvironmentObject private var store: TransferStore
    @State private var expanded: UUID?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("TRANSFERS")
                .font(.caption.weight(.semibold))
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            if store.items.isEmpty {
                Spacer()
                Text("Nothing yet. Send a drop or receive a delivery.")
                    .foregroundStyle(Tokens.muted)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(store.items) { item in
                            TransferCard(item: item, expanded: expanded == item.id) {
                                withAnimation(.easeInOut(duration: 0.15)) {
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

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: item.kind == .send ? "arrow.up.doc" : "arrow.down.doc")
                    .foregroundStyle(Tokens.muted)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.subject)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(Format.statusLine(item))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(statusColor)
                }
                Spacer()
                if item.running {
                    Button("Cancel") { store.cancel(item.id) }
                } else {
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
                } else {
                    ProgressView()
                }
                if expanded {
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
                .font(.system(.callout, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            ProgressView(value: Double(file.moved), total: Double(max(file.bytes, 1)))
                .frame(width: 120)
                .tint(file.state == .verified ? Tokens.ok : Tokens.progress)
            Text(Format.fileLabel(file))
                .font(.caption.monospacedDigit())
                .foregroundStyle(file.state == .verified ? Tokens.ok : Tokens.muted)
                .frame(width: 150, alignment: .trailing)
        }
    }
}

/// Words and units around the core's numbers. Every value comes from the
/// core; nothing is computed here.
enum Format {
    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
    }

    static func seconds(_ value: UInt64) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = value >= 3600 ? [.hour, .minute] : [.minute, .second]
        formatter.unitsStyle = .short
        return formatter.string(from: TimeInterval(value)) ?? "\(value) s"
    }

    static func transport(_ transport: Transport) -> String {
        switch transport {
        case .push: return "QUIC push"
        case .fetch: return "QUIC fetch"
        case .http: return "HTTP"
        }
    }

    static func fileLabel(_ file: FileView) -> String {
        switch file.state {
        case .waiting: return bytes(file.bytes)
        case .moving: return "\(bytes(file.moved)) of \(bytes(file.bytes))"
        case .landed: return "landed"
        case .verified: return "verified"
        }
    }

    static func statusLine(_ item: TransferItem) -> String {
        guard let view = item.view else { return "Starting" }
        let verb = item.kind == .send ? "Sending" : "Receiving"
        switch view.phase {
        case .preparing:
            return item.kind == .send ? "Hashing" : "Preparing"
        case .transferring:
            var parts = [verb]
            if let via = view.transport { parts.append("over \(transport(via))") }
            if let total = view.totalBytes { parts.append("\(bytes(view.movedBytes)) of \(bytes(total))") }
            if let rate = view.rateBytesPerSecond { parts.append("\(bytes(rate))/s") }
            if let eta = view.etaSeconds { parts.append("about \(seconds(eta)) left") }
            return parts.joined(separator: ", ")
        case .done:
            let count = view.files.count
            return item.kind == .send
                ? "Done, \(count) file(s) sent"
                : "Done, \(count) file(s) received and verified"
        case .cancelled:
            return "Cancelled"
        case .failed:
            return view.headline ?? "Failed"
        }
    }

    static func menuLine(_ item: TransferItem) -> String {
        var line = item.subject
        if let rate = item.view?.rateBytesPerSecond {
            line += "  \(bytes(rate))/s"
        }
        return line
    }
}
