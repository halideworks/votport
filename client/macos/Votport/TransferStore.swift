import AppKit
import Foundation
import OSLog
import VotportCore

private let log = Logger(subsystem: "com.halideworks.votport", category: "transfers")

/// One transfer the app started, with the latest view the core handed back.
/// The core owns every number and state here; the screens only draw.
struct TransferItem: Identifiable {
    enum Kind { case send, receive }

    let id: UUID
    let kind: Kind
    /// What the user pointed at: the dropped paths or the destination folder.
    let subject: String
    let link: String
    let started: Date
    var view: TransferView?
    var running = true
    /// The landed paths, for Reveal in Finder after a receive.
    var landed: [String] = []
}

/// Every transfer of this app session, newest first, and the one place a
/// transfer is started or cancelled.
@MainActor
final class TransferStore: ObservableObject {
    static let shared = TransferStore()

    @Published private(set) var items: [TransferItem] = []
    /// Links handed in by a votport:// URL, taken by the screen that shows them.
    @Published var prefillSend: String?
    @Published var prefillReceive: String?
    private var handles: [UUID: Transfer] = [:]

    var active: [TransferItem] { items.filter(\.running) }

    func send(link: String, password: String?, paths: [String]) {
        let subject = paths.count == 1
            ? (paths[0] as NSString).lastPathComponent
            : "\(paths.count) items"
        let item = start(kind: .send, subject: subject, link: link)
        run(item.id) { transfer, listener in
            _ = try? VotportCore.send(
                link: link, password: password, paths: paths,
                transfer: transfer, listener: listener)
            return []
        }
    }

    func receive(link: String, password: String?, destination: URL) {
        let item = start(kind: .receive, subject: destination.path, link: link)
        run(item.id) { transfer, listener in
            let report = try? VotportCore.receive(
                link: link, password: password, dest: destination.path,
                transfer: transfer, listener: listener)
            return report?.files ?? []
        }
    }

    func cancel(_ id: UUID) {
        handles[id]?.cancel()
    }

    func remove(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }), !items[index].running else {
            return
        }
        items.remove(at: index)
    }

    private func start(kind: TransferItem.Kind, subject: String, link: String) -> TransferItem {
        let item = TransferItem(
            id: UUID(), kind: kind, subject: subject, link: link, started: Date())
        items.insert(item, at: 0)
        log.notice("\(String(describing: kind), privacy: .public) started: \(subject, privacy: .public)")
        return item
    }

    /// Runs the blocking core call on its own thread, since it holds that
    /// thread for the whole transfer and the cooperative pool is only a few
    /// wide. Every view comes back through the listener's main-queue hop,
    /// and the last one carries the outcome, so the call's own error is not
    /// needed; the finish lands on the same queue after it.
    private func run(
        _ id: UUID,
        _ work: @escaping @Sendable (Transfer, Listener) -> [String]
    ) {
        let transfer = Transfer()
        handles[id] = transfer
        let listener = Listener(store: self, id: id)
        let thread = Thread {
            let landed = work(transfer, listener)
            DispatchQueue.main.async {
                MainActor.assumeIsolated { listener.finished(landed: landed) }
            }
        }
        thread.name = "votport transfer"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    func apply(_ view: TransferView, to id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].view = view
    }

    func finished(_ id: UUID, landed: [String]) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].running = false
        items[index].landed = landed
        handles[id] = nil
        let item = items[index]
        log.notice("ended: \(String(describing: item.view?.phase), privacy: .public)")
        Notifier.transferEnded(item)
        Snapshot.writeIfRequested()
    }
}

/// The core's callback target for one transfer. Called on the core's thread;
/// hops to the main actor before touching the store.
final class Listener: TransferListener, @unchecked Sendable {
    private let store: TransferStore
    private let id: UUID

    init(store: TransferStore, id: UUID) {
        self.store = store
        self.id = id
    }

    func update(view: TransferView) {
        // The main queue is FIFO, so views apply in the order the core sent
        // them; independent Tasks carry no such guarantee.
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.store.apply(view, to: self.id) }
        }
    }

    @MainActor
    func finished(landed: [String]) {
        store.finished(id, landed: landed)
    }
}

/// `--snapshot <png>` writes the window's own rendering when a transfer
/// ends, so a headless run (over ssh) still leaves a picture of what the
/// user would see.
enum Snapshot {
    @MainActor
    static func writeIfRequested(_ arguments: [String] = CommandLine.arguments) {
        guard let flag = arguments.firstIndex(of: "--snapshot"), arguments.count > flag + 1 else {
            return
        }
        let path = arguments[flag + 1]
        // One more layout pass so the final phase is drawn before it is read.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            guard let view = (NSApp.keyWindow ?? NSApp.windows.first)?.contentView,
                let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds)
            else { return }
            view.cacheDisplay(in: view.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { return }
            do {
                try png.write(to: URL(fileURLWithPath: path))
                log.notice("snapshot written to \(path, privacy: .public)")
            } catch {
                log.error("snapshot failed: \(String(describing: error), privacy: .public)")
            }
        }
    }
}
