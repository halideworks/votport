import AppKit
import Foundation
import OSLog
import VotportCore

private let log = Logger(subsystem: "com.halideworks.votport", category: "receive")

/// One file of the current transfer, as the core planned it and as far as it
/// has come. The core owns every number here; the view only draws them.
struct FileRow: Identifiable {
    let id: UInt64
    let path: String
    var bytes: UInt64
    var received: UInt64 = 0
    var verified = false
}

/// Drives one receive through the core and holds what the window shows.
@MainActor
final class ReceiveModel: ObservableObject {
    enum Phase: Equatable {
        case idle
        case running
        case done(files: Int)
        case failed(String)
    }

    @Published var link = ""
    @Published var password = ""
    @Published var destination: URL?
    @Published var phase: Phase = .idle
    @Published var files: [FileRow] = []
    // Process-wide: a second window (Cmd+N, Dock reopen) must not rerun it.
    private static var launched = false

    var canStart: Bool {
        phase != .running && !link.isEmpty && destination != nil
    }

    /// `Votport --receive <link> <dir>` fills the screen and starts at launch,
    /// the same path an "Open in the app" link will take.
    func startFromLaunchArguments(_ arguments: [String] = CommandLine.arguments) {
        guard !Self.launched, let flag = arguments.firstIndex(of: "--receive"),
            arguments.count > flag + 2
        else { return }
        Self.launched = true
        link = arguments[flag + 1]
        destination = URL(fileURLWithPath: arguments[flag + 2])
        start()
    }

    func start() {
        guard let destination, phase != .running else { return }
        phase = .running
        files = []
        log.notice("receive started into \(destination.path, privacy: .public)")
        let link = link
        let password = password.isEmpty ? nil : password
        let listener = Listener(model: self)
        // The core blocks for the whole transfer, so it runs off the main
        // actor; every tick comes back through the listener's hop.
        Task.detached(priority: .userInitiated) {
            do {
                let report = try receive(
                    link: link, password: password,
                    dest: destination.path, listener: listener)
                await listener.finish(.done(files: report.files.count))
            } catch {
                await listener.finish(.failed(Self.message(of: error)))
            }
        }
    }

    func apply(_ event: TransferEvent) {
        switch event {
        case .planned(let planned):
            files = planned.map { FileRow(id: $0.index, path: $0.path, bytes: $0.bytes) }
        case .downloading(let index, let received, let total):
            if let row = files.firstIndex(where: { $0.id == index }) {
                files[row].received = received
                files[row].bytes = total
            }
        case .fileVerified(let index, _):
            if let row = files.firstIndex(where: { $0.id == index }) {
                files[row].verified = true
            }
        case .sessionCreated, .chunk, .entryComplete, .rebegin, .finished:
            break
        }
    }

    /// The core's message for an error, which is the only text a screen shows
    /// for one. Every VotportError case carries it as its one payload.
    static func message(of error: Error) -> String {
        if let payload = Mirror(reflecting: error).children.first?.value as? String {
            return payload
        }
        return String(describing: error)
    }
}

/// The core's callback target. Called on the core's thread; hops to the main
/// actor before touching the model.
final class Listener: ProgressListener, @unchecked Sendable {
    private let model: ReceiveModel

    init(model: ReceiveModel) {
        self.model = model
    }

    func event(event: TransferEvent) {
        // The main queue is FIFO, so ticks apply in the order the core sent
        // them; independent Tasks carry no such guarantee.
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.model.apply(event) }
        }
    }

    @MainActor
    func finish(_ phase: ReceiveModel.Phase) {
        log.notice("receive ended: \(String(describing: phase), privacy: .public)")
        model.phase = phase
        Snapshot.writeIfRequested()
    }
}

/// `--snapshot <png>` writes the window's own rendering when the transfer
/// ends, so a headless run (over ssh, where screen capture needs a
/// permission grant) still leaves a picture of what the user would see.
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
