import SwiftUI
import VotportCore

/// A new delivery from the port's library, as a sheet over Links: browse a
/// directory, tick files, issue the delivery, copy the one link the server
/// shows for it.
struct DeliverView: View {
    @EnvironmentObject private var port: PortStore
    @Environment(\.dismiss) private var dismiss
    @State private var directory = ""
    @State private var listing: Library?
    @State private var chosen: Set<String> = []
    @State private var label = ""
    @State private var password = ""
    @State private var expiresDays = "7"
    @State private var maxDownloads = ""
    @State private var issued: IssuedDelivery?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("NEW DELIVERY")
                    .font(Type.label)
                    .tracking(1.5)
                    .foregroundStyle(Tokens.muted)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }

            crumbs
            browser
            form
        }
        .padding(20)
        .onAppear { open("") }
    }

    private var crumbs: some View {
        HStack(spacing: 4) {
            Button("Library") { open("") }
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
                Text("Reading the library").foregroundStyle(Tokens.muted)
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
                Button(chosen.isEmpty ? "Tick the files to deliver" : (chosen.count == 1 ? "Deliver 1 file" : "Deliver \(chosen.count) files")) { issue() }
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
