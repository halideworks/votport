import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The sender screen is the drop target: files and folders from Finder or
/// the clipboard, a request link, and one primary action.
struct SendView: View {
    @EnvironmentObject private var store: TransferStore
    @State private var link = ""
    @State private var password = ""
    @State private var paths: [String] = []
    @State private var targeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SEND")
                .font(.caption.weight(.semibold))
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)

            TextField("Request link", text: $link)
                .textFieldStyle(.roundedBorder)
            SecureField("Password, if the link has one", text: $password)
                .textFieldStyle(.roundedBorder)

            dropZone

            HStack {
                Button("Choose Files") { choose() }
                Button("Paste") { paste() }
                if !paths.isEmpty {
                    Button("Clear") { paths.removeAll() }
                }
                Spacer()
                Button("Send") { send() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(link.isEmpty || paths.isEmpty)
            }
        }
        .padding(20)
        .onAppear { takePrefill() }
        .onChange(of: store.prefillSend) { _, _ in takePrefill() }
    }

    private func takePrefill() {
        if let prefill = store.prefillSend {
            link = prefill
            store.prefillSend = nil
        }
    }

    private var dropZone: some View {
        VStack(spacing: 8) {
            if paths.isEmpty {
                Image(systemName: "arrow.down.doc")
                    .font(.system(size: 28))
                    .foregroundStyle(Tokens.muted)
                Text("Drop files or folders here")
                    .foregroundStyle(Tokens.muted)
            } else {
                List(paths, id: \.self) { path in
                    Text(path)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .scrollContentBackground(.hidden)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(targeted ? Tokens.panelHover : Tokens.panel)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Tokens.border))
        .dropDestination(for: URL.self) { urls, _ in
            add(urls)
            return true
        } isTargeted: { targeted = $0 }
    }

    private func add(_ urls: [URL]) {
        for url in urls where url.isFileURL && !paths.contains(url.path) {
            paths.append(url.path)
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        if panel.runModal() == .OK {
            add(panel.urls)
        }
    }

    private func paste() {
        let urls = NSPasteboard.general.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        add(urls)
    }

    private func send() {
        store.send(link: link, password: password.isEmpty ? nil : password, paths: paths)
        paths.removeAll()
    }
}
