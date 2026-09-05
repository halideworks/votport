import AppKit
import Foundation
import OSLog
import VotportCore

private let log = Logger(subsystem: "com.halideworks.votport", category: "receive")

/// Drives one receive through the core and holds the view the core hands
/// back. The core owns every number and state here; the screen only draws.
@MainActor
final class ReceiveModel: ObservableObject {
    @Published var link = ""
    @Published var password = ""
    @Published var destination: URL?
    @Published var view: TransferView?
    @Published var running = false

    // Process-wide: a second window (Cmd+N, Dock reopen) must not rerun it.
    private static var launched = false
    private var transfer: Transfer?

    var canStart: Bool {
        !running && !link.isEmpty && destination != nil
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
        guard let destination, !running else { return }
        running = true
        view = nil
        log.notice("receive started into \(destination.path, privacy: .public)")
        let link = link
        let password = password.isEmpty ? nil : password
        let transfer = Transfer()
        self.transfer = transfer
        let listener = Listener(model: self)
        // The core blocks for the whole transfer, so it runs off the main
        // actor; every view comes back through the listener's hop, and the
        // last one carries the outcome.
        Task.detached(priority: .userInitiated) {
            _ = try? receive(
                link: link, password: password,
                dest: destination.path, transfer: transfer, listener: listener)
            await listener.finished()
        }
    }

    func cancel() {
        transfer?.cancel()
    }

    func apply(_ view: TransferView) {
        self.view = view
    }

    func finished() {
        running = false
        transfer = nil
        log.notice("receive ended: \(String(describing: self.view?.phase), privacy: .public)")
        Snapshot.writeIfRequested()
    }
}

/// The core's callback target. Called on the core's thread; hops to the main
/// actor before touching the model.
final class Listener: TransferListener, @unchecked Sendable {
    private let model: ReceiveModel

    init(model: ReceiveModel) {
        self.model = model
    }

    func update(view: TransferView) {
        // The main queue is FIFO, so views apply in the order the core sent
        // them; independent Tasks carry no such guarantee.
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.model.apply(view) }
        }
    }

    @MainActor
    func finished() {
        model.finished()
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
