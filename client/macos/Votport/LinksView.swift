import AppKit
import SwiftUI
import VotportCore

/// The port's links: the request links senders ship to, and the deliveries
/// recipients pull. Each section opens with its issue form: the request
/// form inline, the delivery browser as a sheet.
struct LinksView: View {
    @EnvironmentObject private var port: PortStore
    @State private var newDelivery = false
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

                section("REQUESTS", empty: "No open request links.", items: port.requests, form: issueForm) { link in
                    RequestRow(link: link) { port.closeRequest(link.id) }
                }

                section("DELIVERIES", empty: "No deliveries issued yet.", items: port.deliveries, form: deliveryCard) { delivery in
                    DeliveryRow(delivery: delivery) { port.revokeDelivery(delivery.id) }
                }
            }
            .padding(20)
        }
        .onAppear { port.refresh() }
        .sheet(isPresented: $newDelivery) {
            // Shorter than the 580 pt window, so the issued link at the
            // bottom of the sheet is never off screen.
            DeliverView()
                .environmentObject(port)
                .frame(width: 660, height: 480)
        }
    }

    private var issueForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Issue a request link")
                .font(Type.sans(13, .semibold, relativeTo: .body))
            HStack {
                TextField("Label, e.g. Dailies from Alex", text: $label)
                    .textFieldStyle(.roundedBorder)
                PasswordField("Password (optional)", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
            }
            HStack(alignment: .bottom) {
                NumberField("Closes after", unit: "days", placeholder: "Never", text: $expiresDays)
                NumberField("Accepts up to", unit: "GB", placeholder: "Port default", text: $maxGigabytes, decimal: true)
                Button("Issue request link") { issue() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
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
                    CopyButton(text: issued.url)
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

    /// The way to a new delivery, as the first card of DELIVERIES: the
    /// library browser needs the room of a sheet.
    private var deliveryCard: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Issue a delivery")
                    .font(Type.sans(13, .semibold, relativeTo: .body))
                Text("Pick files from the library; the recipient gets one link.")
                    .font(Type.callout)
                    .foregroundStyle(Tokens.muted)
            }
            Spacer()
            Button("New delivery") { newDelivery = true }
                .buttonStyle(.borderedProminent)
        }
        .padding(14)
        .background(Tokens.panel)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func issue() {
        let spec = RequestSpec(
            label: label.trimmingCharacters(in: .whitespaces),
            password: password.isEmpty ? nil : password,
            expiresDays: positive(expiresDays),
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
    /// number above zero (the server then applies its own cap).
    private func gigabytes(_ text: String) -> UInt64? {
        guard let value = Double(text.trimmingCharacters(in: .whitespaces)),
            value.isFinite, value > 0, value <= 1_000_000
        else { return nil }
        return UInt64(value * 1_000_000_000)
    }

    private func section<Item: Identifiable, Form: View, Row: View>(
        _ title: String, empty: String, items: [Item], form: Form, @ViewBuilder row: @escaping (Item) -> Row
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(Type.label)
                .tracking(1.5)
                .foregroundStyle(Tokens.muted)
            form
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

/// A whole number above zero, or nil: a typed 0 means the same as an empty
/// field (a link that never closes, unlimited downloads), never a zero the
/// server would take literally.
func positive(_ text: String) -> UInt32? {
    UInt32(text.trimmingCharacters(in: .whitespaces)).flatMap { $0 > 0 ? $0 : nil }
}

/// A number entry that reads as one: the quantity as its label, the unit
/// after the field, and a stepper. The field keeps to digits (and one point
/// when `decimal`): an entry with anything else is refused whole, as a typed
/// key or a paste, so "1,5" never turns into 15. Empty means the default
/// the placeholder names: the stepper counts up from 1 and a step below 1
/// empties the field again, so 0 is never sent.
struct NumberField: View {
    let title: String
    let unit: String
    let placeholder: String
    @Binding var text: String
    var decimal = false

    init(_ title: String, unit: String, placeholder: String, text: Binding<String>, decimal: Bool = false) {
        self.title = title
        self.unit = unit
        self.placeholder = placeholder
        _text = text
        self.decimal = decimal
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(Type.caption)
                .foregroundStyle(Tokens.muted)
            HStack(spacing: 4) {
                TextField(placeholder, text: $text)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 96)
                    .accessibilityLabel(title)
                    .onChange(of: text) { old, value in
                        let digitsOnly = value.allSatisfy { ($0.isASCII && $0.isNumber) || (decimal && $0 == ".") }
                        let points = value.filter { $0 == "." }.count
                        if !digitsOnly || points > 1 { text = old }
                    }
                Stepper(unit, value: stepped, in: 0...1_000_000, step: 1)
                    .font(Type.callout)
                    .foregroundStyle(Tokens.muted)
                    .accessibilityLabel("\(title) in \(unit)")
            }
        }
    }

    /// The stepper's view of the text: empty is 0 (one step up gives 1),
    /// a step down to 0 empties the field, and a fraction keeps its digits
    /// after the point.
    private var stepped: Binding<Double> {
        Binding(
            get: { Double(text) ?? 0 },
            set: { value in
                if value < 1 {
                    text = ""
                } else if let whole = Int(exactly: value) {
                    text = String(whole)
                } else {
                    text = String(value)
                }
            })
    }
}

/// Copies its text and says so on the button for a moment.
struct CopyButton: View {
    let text: String
    @State private var copied = false

    var body: some View {
        Button(copied ? "Copied" : "Copy") {
            copy(text)
            // A second click inside the two seconds copies again and
            // leaves the first task to restore the label.
            guard !copied else { return }
            copied = true
            Task {
                try? await Task.sleep(for: .seconds(2))
                copied = false
            }
        }
        .frame(minWidth: 64)
    }
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
            CopyButton(text: link.url)
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
