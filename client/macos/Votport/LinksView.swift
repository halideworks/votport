import AppKit
import SwiftUI
import VotportCore

/// The port's links: the request links senders ship to, and the deliveries
/// recipients pull. Issue a request here; close or revoke what is done.
struct LinksView: View {
    @EnvironmentObject private var port: PortStore
    @State private var label = ""
    @State private var password = ""
    @State private var expiresDays = ""
    @State private var maxGigabytes = ""
    @State private var issued: RequestLink?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("LINKS")
                    .font(Type.label)
                    .tracking(1.5)
                    .foregroundStyle(Tokens.muted)

                issueForm

                section("REQUESTS", empty: "No open request links.", items: port.requests) { link in
                    RequestRow(link: link) { port.closeRequest(link.id) }
                }

                section("DELIVERIES", empty: "No deliveries issued yet.", items: port.deliveries) { delivery in
                    DeliveryRow(delivery: delivery) { port.revokeDelivery(delivery.id) }
                }
            }
            .padding(20)
        }
        .onAppear { port.refresh() }
    }

    private var issueForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Issue a request link")
                .font(Type.sans(13, .semibold, relativeTo: .body))
            HStack {
                TextField("Label, e.g. Dailies from Alex", text: $label)
                    .textFieldStyle(.roundedBorder)
                SecureField("Password (optional)", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
            }
            HStack {
                TextField("Closes after (days)", text: $expiresDays)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
                TextField("Accepts up to (GB)", text: $maxGigabytes)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
                Spacer()
                Button("Issue") { issue() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(label.trimmingCharacters(in: .whitespaces).isEmpty || port.busy)
            }
            if let issued {
                HStack(spacing: 8) {
                    Text(issued.url)
                        .font(Type.monoCallout)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button("Copy") { copy(issued.url) }
                }
                .foregroundStyle(Tokens.ok)
            }
            if let problem = port.problem(for: .links) {
                Text(problem)
                    .font(Type.callout)
                    .foregroundStyle(Tokens.danger)
            }
        }
        .padding(14)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func issue() {
        let spec = RequestSpec(
            label: label.trimmingCharacters(in: .whitespaces),
            password: password.isEmpty ? nil : password,
            expiresDays: UInt32(expiresDays.trimmingCharacters(in: .whitespaces)),
            maxBytes: gigabytes(maxGigabytes))
        port.issueRequest(spec) { link in
            guard let link else { return }
            issued = link
            copy(link.url)
            label = ""
            password = ""
        }
    }

    /// A cap typed in gigabytes, or nil for anything that is not a sane
    /// number (the server then applies its own cap).
    private func gigabytes(_ text: String) -> UInt64? {
        guard let value = Double(text.trimmingCharacters(in: .whitespaces)),
            value.isFinite, value >= 0, value <= 1_000_000
        else { return nil }
        return UInt64(value * 1_000_000_000)
    }

    private func section<Item: Identifiable, Row: View>(
        _ title: String, empty: String, items: [Item], @ViewBuilder row: @escaping (Item) -> Row
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            if items.isEmpty {
                Text(empty).foregroundStyle(Tokens.muted)
            } else {
                ForEach(items) { item in row(item) }
            }
        }
    }
}

extension RequestLink: Identifiable {}
extension Delivery: Identifiable {}

func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

struct RequestRow: View {
    let link: RequestLink
    let close: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(link.label)
                Text(link.url)
                    .font(Type.monoCallout)
                    .foregroundStyle(Tokens.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(link.summary)
                    .font(Type.caption)
                    .foregroundStyle(link.receiving > 0 ? Tokens.progress : Tokens.muted)
            }
            Spacer()
            Button("Copy") { copy(link.url) }
            Button("Close") { close() }
        }
        .padding(12)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct DeliveryRow: View {
    let delivery: Delivery
    let revoke: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(delivery.label ?? delivery.name ?? delivery.id)
                Text(delivery.summary)
                    .font(Type.caption)
                    .foregroundStyle(Tokens.muted)
            }
            Spacer()
            if delivery.revokedAt == nil {
                Button("Revoke") { revoke() }
            }
        }
        .padding(12)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
