import AppKit
import SwiftUI
import VotportCore

/// Share files through a delivery link. Files dropped or chosen here go
/// up to the port first and come back ticked; what is already on the port
/// is browsed one directory at a time and ticked the same way. Then the
/// delivery is issued and its one link copied.
struct DeliverView: View {
    private static let dropPrompt = "Drop files or folders here"

    @EnvironmentObject private var port: PortStore
    let manageLinks: () -> Void
    @State private var directory = ""
    @State private var listing: Library?
    @State private var chosen: Set<String> = []
    // The local day, not the core's UTC one: an evening drop belongs to today.
    @State private var into = Date.now.formatted(Date.ISO8601FormatStyle(timeZone: .current).year().month().day())
    @State private var targeted = false
    /// The cancel handle of the upload in flight, and the core's last word
    /// on it (its line stays up after the end until the next one starts).
    @State private var uploading: Transfer?
    @State private var lastUpload: UploadView?
    @State private var label = ""
    @State private var password = ""
    @State private var expiresDays = "7"
    @State private var maxDownloads = ""
    @State private var issued: IssuedDelivery?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("SHARE")
                    .font(Type.label)
                    .tracking(1.5)
                    .foregroundStyle(Tokens.muted)
                Spacer()
                Button("Manage links") { manageLinks() }
            }

            Text("Choose files from this Mac or your home port, then create a delivery link.")
                .font(Type.callout)
                .foregroundStyle(Tokens.muted)

            dropZone
            crumbs
            browser
            form
        }
        .padding(20)
        .onAppear { open("") }
    }

    /// Files from this machine go up to the port first, then get ticked
    /// below like anything already there.
    private var dropZone: some View {
        VStack(alignment: .leading, spacing: 8) {
            // The core's line stays up after the upload ends ("Added 2 files
            // to the port, 21 MB") until the next one starts.
            Text(lastUpload?.status ?? Self.dropPrompt)
                .foregroundStyle(Tokens.muted)
                .lineLimit(1)
                .truncationMode(.middle)
            HStack(spacing: 8) {
                if let uploading {
                    Button("Cancel") { uploading.cancel() }
                } else {
                    Button("Choose") { choose() }
                    Button("Paste") { paste() }
                }
                Spacer()
                TextField("Folder on the port", text: $into)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 170)
                    .disabled(uploading != nil)
                    .help("The folder on the port the files go into")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(targeted ? Tokens.panelHover : Tokens.panel)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Tokens.border))
        .dropDestination(for: URL.self) { urls, _ in
            upload(urls.filter(\.isFileURL).map(\.path))
            return true
        } isTargeted: { targeted = $0 }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Put on the port"
        if panel.runModal() == .OK {
            upload(panel.urls.map(\.path))
        }
    }

    private func paste() {
        let urls = NSPasteboard.general.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        upload(urls.map(\.path))
    }

    /// Sends the paths up to the port under the named folder; what lands is
    /// ticked and its folder opened so the ticks are seen.
    private func upload(_ paths: [String]) {
        guard !paths.isEmpty, uploading == nil else { return }
        let transfer = Transfer()
        uploading = transfer
        lastUpload = nil
        let hop = UploadHop { view in lastUpload = view }
        // What landed is ticked whether the upload ended well or not: a
        // failure or a cancel midway still put the earlier files on the port.
        port.upload(paths, into: into.trimmingCharacters(in: .whitespaces), transfer: transfer, listener: hop) { made in
            uploading = nil
            let landed = lastUpload?.landed ?? []
            chosen.formUnion(landed)
            guard made != nil else {
                // The problem line below says what went wrong; the prompt
                // returns. No reload here: a library call would clear that line.
                lastUpload = nil
                return
            }
            if let first = landed.first {
                open(first.split(separator: "/").dropLast().joined(separator: "/"))
            }
        }
    }

    private var crumbs: some View {
        HStack(spacing: 4) {
            Button("On the port") { open("") }
                .buttonStyle(.plain)
                .foregroundStyle(directory.isEmpty ? Tokens.text : Tokens.progress)
            let parts = directory.split(separator: "/").map(String.init)
            ForEach(Array(parts.enumerated()), id: \.offset) { index, part in
                Text("/").foregroundStyle(Tokens.muted)
                let target = parts[...index].joined(separator: "/")
                Button(part) { open(target) }
                    .buttonStyle(.plain)
                    .foregroundStyle(target == directory ? Tokens.text : Tokens.progress)
            }
            Spacer()
            if let listing, listing.truncated {
                Text("More files than shown")
                    .font(Type.caption)
                    .foregroundStyle(Tokens.muted)
            }
        }
        .font(Type.monoCallout)
    }

    private var browser: some View {
        List {
            if let listing {
                ForEach(listing.directories, id: \.self) { name in
                    // A button, not a tap gesture: it answers the keyboard
                    // and assistive presses as well as the mouse.
                    Button {
                        open(directory.isEmpty ? name : "\(directory)/\(name)")
                    } label: {
                        HStack {
                            Image(systemName: "folder").foregroundStyle(Tokens.muted)
                            Text(name).font(Type.monoBody)
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                ForEach(listing.files, id: \.path) { file in
                    Toggle(isOn: binding(for: file.path)) {
                        HStack {
                            Text(name(of: file.path)).font(Type.monoBody)
                            Spacer()
                            Text(file.size)
                                .font(Type.caption.monospacedDigit())
                                .foregroundStyle(Tokens.muted)
                        }
                    }
                }
                if listing.directories.isEmpty && listing.files.isEmpty {
                    Text("Nothing here yet.").foregroundStyle(Tokens.muted)
                }
            } else {
                Text("Reading what is on the port").foregroundStyle(Tokens.muted)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField("Label, e.g. Final grade for Alex", text: $label)
                    .textFieldStyle(.roundedBorder)
                PasswordField("Password (optional)", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
            }
            HStack(alignment: .bottom) {
                NumberField("Expires after", unit: "days", placeholder: "7", text: $expiresDays)
                NumberField("Downloads allowed", unit: "downloads", placeholder: "Unlimited", text: $maxDownloads)
                // The button carries the count, so the row has one control to read.
                Button(chosen.isEmpty ? "Choose files to share" : (chosen.count == 1 ? "Share 1 file" : "Share \(chosen.count) files")) { issue() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
                    .keyboardShortcut(.defaultAction)
                    .disabled(chosen.isEmpty || label.trimmingCharacters(in: .whitespaces).isEmpty || port.busy)
            }
            if let issued {
                HStack(spacing: 8) {
                    Text(issued.url)
                        .font(Type.monoCallout)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    CopyButton(text: issued.url)
                }
                .foregroundStyle(Tokens.ok)
                Text("This is the only time the link is shown; the recipient pastes it into Receive.")
                    .font(Type.caption)
                    .foregroundStyle(Tokens.muted)
            }
            if let problem = port.problem(for: .deliver) {
                Text(problem)
                    .font(Type.callout)
                    .foregroundStyle(Tokens.danger)
            }
        }
    }

    private func binding(for path: String) -> Binding<Bool> {
        Binding(
            get: { chosen.contains(path) },
            set: { on in
                if on { chosen.insert(path) } else { chosen.remove(path) }
            })
    }

    private func name(of path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }

    private func open(_ target: String) {
        directory = target
        listing = nil
        port.library(target) { result in
            if directory == target { listing = result }
        }
    }

    private func issue() {
        let spec = DeliverySpec(
            paths: chosen.sorted(),
            label: label.trimmingCharacters(in: .whitespaces),
            password: password.isEmpty ? nil : password,
            expiresDays: positive(expiresDays) ?? 7,
            maxDownloads: positive(maxDownloads).map(UInt64.init))
        port.issueDelivery(spec) { result in
            guard let result else { return }
            issued = result
            copy(result.url)
            chosen = []
            label = ""
            password = ""
        }
    }
}

/// The core's progress callback for an upload. Called on the core's thread;
/// hops to the main actor before touching the view's state.
final class UploadHop: UploadListener, @unchecked Sendable {
    private let apply: @MainActor (UploadView) -> Void

    init(_ apply: @escaping @MainActor (UploadView) -> Void) {
        self.apply = apply
    }

    func update(view: UploadView) {
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.apply(view) }
        }
    }
}
