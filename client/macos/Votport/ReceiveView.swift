import AppKit
import SwiftUI
import VotportCore

struct ReceiveView: View {
    @StateObject private var model = ReceiveModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("RECEIVE")
                .font(.caption.weight(.semibold))
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)

            TextField("Delivery link", text: $model.link)
                .textFieldStyle(.roundedBorder)
            SecureField("Password, if the delivery has one", text: $model.password)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Choose Folder") { chooseFolder() }
                Text(model.destination?.path ?? "No folder chosen")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(Tokens.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                if model.running {
                    Button("Cancel") { model.cancel() }
                } else {
                    Button("Receive") { model.start() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.canStart)
                }
            }

            List(model.view?.files ?? [], id: \.index) { file in
                FileRowView(file: file)
            }
            .scrollContentBackground(.hidden)
            .background(Tokens.panel)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Tokens.border))

            status
        }
        .padding(20)
        .onAppear { model.startFromLaunchArguments() }
        .background(Tokens.bg)
        .foregroundStyle(Tokens.text)
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private var status: some View {
        switch model.view?.phase {
        case nil:
            Text("Paste a delivery link and choose where its files land.")
                .foregroundStyle(Tokens.muted)
        case .preparing:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Preparing")
            }
        case .transferring:
            TransferStatus(view: model.view!)
        case .done:
            Text("Done: \(model.view!.files.count) file(s) received and verified.")
                .foregroundStyle(Tokens.ok)
        case .cancelled:
            Text("Cancelled. Receive again to continue.")
                .foregroundStyle(Tokens.muted)
        case .failed:
            Text(model.view!.message ?? "Failed")
                .foregroundStyle(Tokens.danger)
                .textSelection(.enabled)
        }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Receive Here"
        if panel.runModal() == .OK {
            model.destination = panel.url
        }
    }
}

/// One file of the transfer list, drawn from the core's row.
struct FileRowView: View {
    let file: FileView

    var body: some View {
        HStack {
            Text(file.path)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            ProgressView(value: Double(file.moved), total: Double(max(file.bytes, 1)))
                .frame(width: 140)
                .tint(file.state == .verified ? Tokens.ok : Tokens.progress)
            Text(label)
                .font(.caption.monospacedDigit())
                .foregroundStyle(file.state == .verified ? Tokens.ok : Tokens.muted)
                .frame(width: 150, alignment: .trailing)
        }
    }

    private var label: String {
        switch file.state {
        case .waiting: return Format.bytes(file.bytes)
        case .moving: return "\(Format.bytes(file.moved)) of \(Format.bytes(file.bytes))"
        case .landed: return "landed"
        case .verified: return "verified"
        }
    }
}

/// The moving-bytes line: the transport, the rate, and the ETA once the core
/// is willing to state one.
struct TransferStatus: View {
    let view: TransferView

    var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(line)
                .monospacedDigit()
        }
    }

    private var line: String {
        var parts = ["Receiving"]
        if let transport = view.transport {
            parts.append("over \(Format.transport(transport))")
        }
        if let total = view.totalBytes {
            parts.append("\(Format.bytes(view.movedBytes)) of \(Format.bytes(total))")
        }
        if let rate = view.rateBytesPerSecond {
            parts.append("\(Format.bytes(rate))/s")
        }
        if let eta = view.etaSeconds {
            parts.append("about \(Format.seconds(eta)) left")
        }
        return parts.joined(separator: ", ")
    }
}

/// Number formatting for the screen. Units and words only; every value comes
/// from the core.
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
}
