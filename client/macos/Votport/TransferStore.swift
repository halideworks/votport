import AppKit
import Foundation
import IOKit
import IOKit.pwr_mgt
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
    var subject: String
    let link: String
    let started: Date
    var files: [TransferFile] = []
    var filesByIndex: [UInt64: TransferFile] = [:]
    var view: TransferView?
    var running = true
    /// One file to select, or the receive destination for multiple files.
    var landed: String?
    var revealDestinationFolder = false
    /// The journal id, once the core recorded the transfer.
    var journalId: String?
    /// A transfer the journal held at launch, cut by a quit or a failure and
    /// not yet resumed.
    var interrupted = false
    /// The entry was started with a password the journal does not keep.
    var needsPassword = false
    /// The core still holds the entry, so Retry or Resume can run it again.
    var journalled = false

    var canResume: Bool { !running && journalled }
    var canReveal: Bool { !running && kind == .receive && landed != nil }
    var revealLabel: String {
        revealDestinationFolder ? "Show destination folder" : "Reveal in Finder"
    }

    mutating func setRevealDestination(_ paths: [String]) {
        switch paths.count {
        case 0:
            landed = nil
            revealDestinationFolder = false
        case 1:
            landed = paths[0]
            revealDestinationFolder = false
        default:
            landed = subject
            revealDestinationFolder = true
        }
    }

    mutating func compactStopped(landed paths: [String]) {
        setRevealDestination(paths)
        guard !running && !journalled else { return }
        files.removeAll(keepingCapacity: false)
        filesByIndex.removeAll(keepingCapacity: false)
        if var retainedView = view {
            retainedView.files.removeAll(keepingCapacity: false)
            view = retainedView
        }
    }
}

@MainActor
final class TransferFile: ObservableObject, Identifiable {
    let id: UInt64
    @Published var view: FileView

    init(view: FileView) {
        id = view.index
        self.view = view
    }
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

    /// The menu bar glyph: full while bytes move, plain after a clean end,
    /// and a warning when the last settled transfer failed or was cut, so a
    /// failure reads differently from idle. The menu bar has no tooltip.
    var menuBarSymbol: String {
        if !active.isEmpty { return "sailboat.fill" }
        guard let last = items.first(where: { !$0.running }) else { return "sailboat" }
        return last.interrupted || last.view?.phase == .failed ? "exclamationmark.triangle" : "sailboat"
    }

    func send(link: String, password: String?, paths: [String]) {
        let item = start(kind: .send, subject: Self.subject(for: paths), link: link)
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

    /// Ships a settled drop of a watched folder, as a send of that one path;
    /// the core moves it into the folder's `shipped` subfolder afterwards.
    func ship(watchId: String, path: String, admission: WatchAdmission) {
        let item = start(kind: .send, subject: Self.subject(for: [path]), link: "")
        run(item.id) { transfer, listener in
            _ = try? VotportCore.ship(
                watchId: watchId, path: path, admission: admission,
                transfer: transfer, listener: listener)
            return []
        }
    }

    /// Stops a transfer and keeps its journal entry, so the card ends as
    /// Paused with Resume.
    func pause(_ id: UUID) {
        handles[id]?.pause()
    }

    private var watcher: Watcher?

    /// Starts the watch folder scan for the life of the app. The listener
    /// is called on the core's thread and hops to the main actor to start
    /// the ship like any other transfer.
    func startWatching() {
        guard watcher == nil else { return }
        watcher = VotportCore.watchAll(listener: WatchHandoff(store: self))
    }

    /// Lists the transfers the journal held over from an earlier run, as
    /// interrupted cards. Called once at launch.
    func loadPending() {
        for entry in VotportCore.pending() {
            let kind: TransferItem.Kind = entry.kind == .send ? .send : .receive
            let subject = kind == .send ? Self.subject(for: entry.paths) : (entry.dest ?? "")
            var item = TransferItem(
                id: UUID(), kind: kind, subject: subject, link: entry.link,
                started: Date(timeIntervalSince1970: TimeInterval(entry.startedUnix)))
            item.running = false
            item.journalId = entry.id
            item.interrupted = true
            item.needsPassword = entry.needsPassword
            item.journalled = true
            // Oldest first from the journal into a newest-first list.
            items.insert(item, at: 0)
        }
    }

    /// Runs a journalled transfer again under its id, with the password
    /// supplied afresh when the entry needs one. A receive's `destination`
    /// overrides the journalled folder and is remembered as its folder; the
    /// card re-asks for it on retry, so a refusal like an existing file is
    /// answered by choosing an empty one.
    func resume(_ id: UUID, password: String?, destination: URL?) {
        guard let index = items.firstIndex(where: { $0.id == id }),
            let journalId = items[index].journalId, items[index].canResume
        else { return }
        if let destination {
            items[index].subject = destination.path
        }
        items[index].running = true
        items[index].interrupted = false
        items[index].view = nil
        items[index].files = []
        items[index].filesByIndex = [:]
        items[index].landed = nil
        items[index].revealDestinationFolder = false
        run(id) { transfer, listener in
            let report = try? VotportCore.resume(
                id: journalId, password: password, dest: destination?.path,
                transfer: transfer, listener: listener)
            if case .received(let received)? = report { return received.files }
            return []
        }
    }

    private static func subject(for paths: [String]) -> String {
        paths.count == 1 ? (paths[0] as NSString).lastPathComponent : "\(paths.count) items"
    }

    func cancel(_ id: UUID) {
        handles[id]?.cancel()
    }

    /// Drops a finished or interrupted transfer from the list, and from the
    /// journal, so it is not offered again.
    func remove(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }), !items[index].running else {
            return
        }
        if let journalId = items[index].journalId {
            VotportCore.forget(id: journalId)
        }
        items.remove(at: index)
    }

    var hasFinished: Bool { items.contains { !$0.running && !$0.journalled } }

    func clearFinished() {
        items.removeAll { !$0.running && !$0.journalled }
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
        // Bytes are moving: hold the machine awake until the last transfer
        // and library upload end.
        Power.transfer(true)
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
        if view.filesReset {
            let rows = view.files.map { TransferFile(view: $0) }
            items[index].files = rows
            items[index].filesByIndex = Dictionary(rows.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        } else {
            for file in view.files {
                items[index].filesByIndex[file.index]?.view = file
            }
        }
        items[index].view = view
        updateDockTile()
    }

    /// Dock progress from the active transfers' moved bytes over their
    /// totals; zero hides the bar. Every view and every finish lands here,
    /// straight from the store's main-actor updates.
    private func updateDockTile() {
        var moved: UInt64 = 0
        var total: UInt64 = 0
        for item in active {
            moved += item.view?.movedBytes ?? 0
            total += item.view?.totalBytes ?? 0
        }
        // The dock progress tile postdates the SDKs this builds against;
        // the badge draw is the portable signal.
        NSApp.dockTile.display()
    }

    func finished(_ id: UUID, landed: [String]) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].running = false
        // Another transfer may still be moving bytes.
        Power.transfer(!active.isEmpty)
        if let handle = handles[id] {
            items[index].journalId = handle.journalId()
            // The core keeps the entry only for a failure worth trying again,
            // and says whether the next run must ask for a password.
            items[index].journalled = handle.journalKept()
            items[index].needsPassword = handle.journalNeedsPassword()
        }
        items[index].compactStopped(landed: landed)
        handles[id] = nil
        updateDockTile()
        let item = items[index]
        log.notice("ended: \(String(describing: item.view?.phase), privacy: .public)")
        Notifier.transferEnded(item)
        Snapshot.writeIfRequested()
    }
}

/// The core's callback for a drop that settled in a watched folder. Called
/// on the watcher's thread; hops to the main actor to start the ship.
final class WatchHandoff: WatchListener, @unchecked Sendable {
    private let store: TransferStore

    init(store: TransferStore) {
        self.store = store
    }

    func ready(watchId: String, path: String, admission: WatchAdmission) {
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                self.store.ship(watchId: watchId, path: path, admission: admission)
            }
        }
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
    static var mainWindow: NSWindow?

    @MainActor
    static func writeIfRequested(_ arguments: [String] = CommandLine.arguments) {
        guard let flag = arguments.firstIndex(of: "--snapshot"), arguments.count > flag + 1 else {
            return
        }
        let path = arguments[flag + 1]
        // One more layout pass so the final phase is drawn before it is read.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            guard let view = mainWindow?.contentView else {
                log.error("snapshot skipped: main window unavailable")
                return
            }
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                log.error("snapshot skipped: main window has no drawable content")
                return
            }
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

/// Keeps the machine awake while bytes move: the first active transfer or
/// library upload takes one IOKit assertion (PreventUserIdleSystemSleep: the
/// display may still sleep) and the last releases it, so an overnight send
/// does not die to idle sleep. Linux has no equivalent; the shell only runs
/// here and on Windows.
@MainActor
enum Power {
    private static var transfers = false
    private static var libraryUpload = false
    private static var assertion: IOPMAssertionID = 0

    static func transfer(_ active: Bool) {
        transfers = active
        apply()
    }

    static func libraryUpload(_ active: Bool) {
        libraryUpload = active
        apply()
    }

    private static func apply() {
        let wanted = transfers || libraryUpload
        guard wanted != (assertion != 0) else { return }
        if wanted {
            var id: IOPMAssertionID = 0
            let status = IOPMAssertionCreateWithName(
                kIOPMAssertionTypePreventUserIdleSystemSleep as CFString,
                IOPMAssertionLevel(kIOPMAssertionLevelOn),
                "votport is transferring files" as CFString,
                &id)
            assertion = status == kIOReturnSuccess ? id : 0
            if status != kIOReturnSuccess {
                log.error("power assertion refused: \(status, privacy: .public)")
            }
        } else {
            IOPMAssertionRelease(assertion)
            assertion = 0
        }
    }
}
