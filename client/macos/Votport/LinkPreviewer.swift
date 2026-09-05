import Foundation
import VotportCore

/// Previews the link a field holds: debounced, off the main thread, and a
/// result is kept only while the field still holds the link it was for.
/// The core decides everything about the link; this only carries it.
@MainActor
final class LinkPreviewer: ObservableObject {
    @Published private(set) var preview: LinkPreview?
    @Published private(set) var checking = false
    private var pending: DispatchWorkItem?
    private var current = ""

    /// Typing pauses this long before the core is asked.
    private static let settle: TimeInterval = 0.4

    func update(_ link: String) {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        pending?.cancel()
        pending = nil
        current = trimmed
        guard !trimmed.isEmpty else {
            preview = nil
            checking = false
            return
        }
        checking = true
        let work = DispatchWorkItem { [weak self] in
            let thread = Thread {
                let result = VotportCore.inspect(link: trimmed)
                DispatchQueue.main.async {
                    MainActor.assumeIsolated { self?.deliver(result, for: trimmed) }
                }
            }
            thread.name = "votport preview"
            thread.start()
        }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.settle, execute: work)
    }

    private func deliver(_ result: LinkPreview, for link: String) {
        guard link == current else { return }
        preview = result
        checking = false
    }

    /// Whether the primary action may run: the link previewed and is usable.
    var ready: Bool { preview?.usable == true }
    var needsPassword: Bool { preview?.needsPassword == true }
}

/// The one line under a link field, from the core's preview.
@MainActor
enum PreviewLine {
    static func text(_ previewer: LinkPreviewer) -> String? {
        if previewer.checking { return "Checking the link" }
        guard let preview = previewer.preview else { return nil }
        if let problem = preview.problem { return problem }
        var parts: [String] = []
        if let label = preview.label, !label.isEmpty { parts.append(label) }
        switch preview.kind {
        case .request:
            if let max = preview.maxBytes { parts.append("accepts up to \(Format.bytes(max))") }
        case .delivery:
            if let total = preview.totalBytes {
                let count = preview.files.count
                parts.append("\(count) file\(count == 1 ? "" : "s"), \(Format.bytes(total))")
            }
        case nil:
            break
        }
        if preview.needsPassword { parts.append("password needed") }
        if preview.quic == true { parts.append("QUIC offered") }
        return parts.isEmpty ? nil : parts.joined(separator: ", ")
    }

    static func isProblem(_ previewer: LinkPreviewer) -> Bool {
        previewer.preview?.problem != nil
    }
}
