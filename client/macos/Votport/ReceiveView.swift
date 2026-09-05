import AppKit
import SwiftUI

/// The recipient screen is the destination picker: a delivery link, a
/// folder, and one primary action. Progress lives in Transfers.
struct ReceiveView: View {
    @EnvironmentObject private var store: TransferStore
    @AppStorage(Prefs.receiveFolderKey) private var defaultFolder = ""
    @State private var link = ""
    @State private var password = ""
    @State private var destination: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("RECEIVE")
                .font(.caption.weight(.semibold))
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)

            TextField("Delivery link", text: $link)
                .textFieldStyle(.roundedBorder)
            SecureField("Password, if the delivery has one", text: $password)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Choose Folder") { chooseFolder() }
                Text(folder?.path ?? "No folder chosen")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(Tokens.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button("Receive") { receive() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(link.isEmpty || folder == nil)
            }

            Spacer()
            Text("Files land verified against the roots the delivery announced.")
                .foregroundStyle(Tokens.muted)
        }
        .padding(20)
        .onAppear { takePrefill() }
        .onChange(of: store.prefillReceive) { _, _ in takePrefill() }
    }

    private func takePrefill() {
        if let prefill = store.prefillReceive {
            link = prefill
            store.prefillReceive = nil
        }
    }

    private var folder: URL? {
        destination ?? (defaultFolder.isEmpty ? nil : URL(fileURLWithPath: defaultFolder))
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Receive Here"
        if panel.runModal() == .OK {
            destination = panel.url
        }
    }

    private func receive() {
        guard let folder else { return }
        store.receive(link: link, password: password.isEmpty ? nil : password, destination: folder)
        link = ""
        password = ""
    }
}
