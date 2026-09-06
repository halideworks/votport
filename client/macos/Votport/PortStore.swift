import Foundation
import OSLog
import VotportCore

private let log = Logger(subsystem: "com.halideworks.votport", category: "port")

/// The home port: the votport the operator signed in to, and what the core
/// lists there. Every core call runs on its own thread and lands back on
/// the main actor; the core owns the session, this only carries results.
@MainActor
final class PortStore: ObservableObject {
    static let shared = PortStore()

    @Published private(set) var port: VotportCore.Port?
    @Published private(set) var requests: [RequestLink] = []
    @Published private(set) var deliveries: [Delivery] = []
    @Published private(set) var watches: [Watch] = []
    /// A core call is in flight; the screens disable their primary action.
    @Published private(set) var busy = false
    /// Calls in flight; `busy` follows it, so two overlapping calls do not
    /// re-enable a form when the first one lands.
    private var inFlight = 0
    /// The last failure's headline, for the line under the form that made
    /// the call, named by `problemScope`.
    @Published var problem: String?
    @Published private(set) var problemScope: Scope?

    /// Which form a failure belongs under.
    enum Scope { case port, watch, links, deliver }

    /// The headline to show under a form, when the failure was its own.
    func problem(for scope: Scope) -> String? {
        problemScope == scope ? problem : nil
    }

    var signedIn: Bool { port != nil }

    /// Reads the stored port without a round trip, then asks the server
    /// whether the session still holds. Called once at launch.
    func load() {
        port = VotportCore.port()
        watches = VotportCore.watches()
        guard port != nil else { return }
        run(.port) { try checkPort() } then: { [weak self] result in
            guard let self else { return }
            if case .success(let port) = result {
                self.port = port
                if port != nil { self.refresh() }
            }
        }
    }

    func signIn(base: String, password: String) {
        run(.port) { try VotportCore.signIn(base: base, password: password) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let port):
                self.port = port
                self.problem = nil
                self.refresh()
            case .failure(let error):
                self.take(error, .port)
            }
        }
    }

    func signOut() {
        run(.port) { VotportCore.signOut() } then: { [weak self] _ in
            self?.port = nil
            self?.requests = []
            self?.deliveries = []
        }
    }

    /// Reloads the request links and deliveries.
    func refresh() {
        run(.links) { (try VotportCore.requests(), try VotportCore.deliveries()) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let (requests, deliveries)):
                self.requests = requests
                self.deliveries = deliveries
            case .failure(let error):
                self.take(error, .links)
            }
        }
    }

    func issueRequest(_ spec: RequestSpec, done: @escaping (RequestLink?) -> Void) {
        run(.links) { try VotportCore.issueRequest(spec: spec) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let link):
                self.requests.insert(link, at: 0)
                done(link)
            case .failure(let error):
                self.take(error, .links)
                done(nil)
            }
        }
    }

    func closeRequest(_ id: String) {
        run(.links) { try VotportCore.closeRequest(id: id) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success: self.requests.removeAll { $0.id == id }
            case .failure(let error): self.take(error, .links)
            }
        }
    }

    func revokeDelivery(_ id: String) {
        run(.links) { try VotportCore.revokeDelivery(id: id) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success: self.refresh()
            case .failure(let error): self.take(error, .links)
            }
        }
    }

    func library(_ directory: String, done: @escaping (Library?) -> Void) {
        run(.deliver) { try VotportCore.library(directory: directory) } then: { [weak self] result in
            switch result {
            case .success(let listing): done(listing)
            case .failure(let error):
                self?.take(error, .deliver)
                done(nil)
            }
        }
    }

    func issueDelivery(_ spec: DeliverySpec, done: @escaping (IssuedDelivery?) -> Void) {
        run(.deliver) { try VotportCore.issueDelivery(spec: spec) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let issued):
                self.deliveries.insert(issued.delivery, at: 0)
                done(issued)
            case .failure(let error):
                self.take(error, .deliver)
                done(nil)
            }
        }
    }

    func addWatch(dir: String, link: String, password: String?, done: @escaping (Bool) -> Void) {
        run(.watch) { try VotportCore.addWatch(dir: dir, link: link, password: password) } then: { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.watches = VotportCore.watches()
                done(true)
            case .failure(let error):
                self.take(error, .watch)
                done(false)
            }
        }
    }

    func removeWatch(_ id: String) {
        run(.watch) { try VotportCore.removeWatch(id: id) } then: { [weak self] _ in
            self?.watches = VotportCore.watches()
        }
    }

    /// A session the server ended clears the port so the screens fold. The
    /// scope is stamped here, at the failure, so a slow call that lands
    /// after a later one still reports under its own form.
    private func take(_ error: PortError, _ scope: Scope) {
        guard case let .Failed(headline, detail, signedOut) = error else { return }
        problem = headline
        problemScope = scope
        if signedOut {
            port = nil
            requests = []
            deliveries = []
        }
        log.notice("port call failed: \(detail, privacy: .public)")
    }

    /// Runs `work` on its own thread (a core call blocks for its round trips
    /// and through the retry budget) and hands the result to `then` on the
    /// main actor, in order.
    private func run<T>(
        _ scope: Scope,
        _ work: @escaping @Sendable () throws -> T,
        then: @escaping @MainActor (Result<T, PortError>) -> Void
    ) where T: Sendable {
        inFlight += 1
        busy = true
        // A problem belongs to the call that failed; the next call clears it.
        problem = nil
        problemScope = scope
        let thread = Thread {
            let result: Result<T, PortError>
            do {
                result = .success(try work())
            } catch let error as PortError {
                result = .failure(error)
            } catch {
                result = .failure(.Failed(headline: String(describing: error), detail: String(describing: error), signedOut: false))
            }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    let store = PortStore.shared
                    store.inFlight -= 1
                    store.busy = store.inFlight > 0
                    then(result)
                }
            }
        }
        thread.name = "votport port"
        thread.start()
    }
}
