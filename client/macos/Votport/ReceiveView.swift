import AppKit
import SwiftUI

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
                Button("Receive") { model.start() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canStart)
            }

            List(model.files) { file in
                HStack {
                    Text(file.path)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    ProgressView(value: Double(file.received), total: Double(max(file.bytes, 1)))
                        .frame(width: 140)
                        .tint(file.verified ? Tokens.ok : Tokens.progress)
                    Text(file.verified ? "verified" : "\(file.received) / \(file.bytes)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(file.verified ? Tokens.ok : Tokens.muted)
                        .frame(width: 150, alignment: .trailing)
                }
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
        switch model.phase {
        case .idle:
            Text("Paste a delivery link and choose where its files land.")
                .foregroundStyle(Tokens.muted)
        case .running:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Receiving")
            }
        case .done(let files):
            Text("Done: \(files) file(s) received and verified.")
                .foregroundStyle(Tokens.ok)
        case .failed(let message):
            Text(message)
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
