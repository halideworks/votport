import Foundation
import XCTest
import VotportCore
@testable import Votport

@MainActor
final class PortStoreTests: XCTestCase {
    func testStaleResultSettlesWithoutReplacingCurrentProblem() async {
        let store = PortStore.shared
        let started = expectation(description: "previous account call started")
        let settled = expectation(description: "previous account cleanup completed")
        let release = DispatchSemaphore(value: 0)
        defer { release.signal(); store.problem = nil }
        store.run(.links) {
            started.fulfill()
            guard release.wait(timeout: .now() + 10) == .success else {
                throw PortError.Failed(headline: "Timed out", detail: "Test worker was not released", signedOut: false)
            }
            return "previous account result"
        } then: { result in
            if case .failure(let error) = result { store.take(error, .links) }
            if case .success = result { XCTFail("A stale success reached the current account") }
            settled.fulfill()
        }
        await fulfillment(of: [started], timeout: 5)
        store.sessionEnded()
        store.problem = "Current account problem"
        release.signal()
        await fulfillment(of: [settled], timeout: 5)
        XCTAssertEqual(store.problem, "Current account problem")
        XCTAssertFalse(store.busy)
    }

    func testCurrentFailureStillReportsItsProblem() async {
        let store = PortStore.shared
        let settled = expectation(description: "current account failure completed")
        defer { store.problem = nil }
        store.run(.links) {
            throw PortError.Failed(headline: "Current failure", detail: "Current request failed", signedOut: false)
        } then: { (result: Result<Void, PortStore.CallError>) in
            if case .failure(let error) = result { store.take(error, .links) }
            settled.fulfill()
        }
        await fulfillment(of: [settled], timeout: 5)
        XCTAssertEqual(store.problem, "Current failure")
        XCTAssertTrue(store.problemScope == .links)
        XCTAssertFalse(store.busy)
    }

    func testStaleSignedOutFailureCannotResetTheReplacementSession() async {
        let store = PortStore.shared
        let started = expectation(description: "old session call started")
        let settled = expectation(description: "old session failure settled")
        let release = DispatchSemaphore(value: 0)
        defer { release.signal(); store.problem = nil }
        store.run(.links) {
            started.fulfill()
            guard release.wait(timeout: .now() + 10) == .success else {
                throw PortError.Failed(headline: "Timed out", detail: "Worker release timed out", signedOut: false)
            }
            throw PortError.Failed(headline: "Old session expired", detail: "Old session expired", signedOut: true)
        } then: { (result: Result<Void, PortStore.CallError>) in
            if case .failure(let error) = result { store.take(error, .links) }
            if case .success = result { XCTFail("Old session failure became a success") }
            settled.fulfill()
        }
        await fulfillment(of: [started], timeout: 5)
        store.sessionEnded()
        let replacement = store.sessionGeneration
        store.problem = "Replacement account problem"
        release.signal()
        await fulfillment(of: [settled], timeout: 5)
        XCTAssertEqual(store.sessionGeneration, replacement)
        XCTAssertEqual(store.problem, "Replacement account problem")
        XCTAssertFalse(store.busy)
    }

    func testOverlappingCallsKeepActionsBusyUntilBothComplete() async {
        let store = PortStore.shared
        let started = [expectation(description: "first started"), expectation(description: "second started")]
        let settled = [expectation(description: "first settled"), expectation(description: "second settled")]
        let release = [DispatchSemaphore(value: 0), DispatchSemaphore(value: 0)]
        defer { release.forEach { $0.signal() } }
        for index in 0..<2 {
            let entered = started[index]
            let finished = settled[index]
            let gate = release[index]
            store.run(.links) {
                entered.fulfill()
                guard gate.wait(timeout: .now() + 10) == .success else {
                    throw PortError.Failed(headline: "Timed out", detail: "Worker release timed out", signedOut: false)
                }
                return index
            } then: { result in
                if case .failure = result { XCTFail("Current call did not succeed") }
                finished.fulfill()
            }
        }
        await fulfillment(of: started, timeout: 5)
        XCTAssertTrue(store.busy)
        release[0].signal()
        await fulfillment(of: [settled[0]], timeout: 5)
        XCTAssertTrue(store.busy)
        release[1].signal()
        await fulfillment(of: [settled[1]], timeout: 5)
        XCTAssertFalse(store.busy)
    }

    func testCancellationInvalidatesQueuedAccountResultsAndReconcilesCoreSession() async {
        let store = PortStore.shared
        let entered = expectation(description: "old sign-in entered")
        let settled = expectation(description: "old sign-in settled")
        let release = DispatchSemaphore(value: 0)
        defer { release.signal(); store.problem = nil }
        store.run(.links) {
            entered.fulfill()
            guard release.wait(timeout: .now() + 10) == .success else {
                throw PortError.Failed(headline: "Timed out", detail: "Worker release timed out", signedOut: false)
            }
            return "old sign-in result"
        } then: { result in
            if case .success = result { XCTFail("Cancelled sign-in reached the current session") }
            settled.fulfill()
        }
        await fulfillment(of: [entered], timeout: 5)
        let previous = store.sessionGeneration
        store.cancelSso()
        XCTAssertGreaterThan(store.sessionGeneration, previous)
        store.problem = "Current cancellation problem"
        release.signal()
        await fulfillment(of: [settled], timeout: 5)
        let deadline = Date().addingTimeInterval(5)
        while store.busy && Date() < deadline { await Task.yield() }
        XCTAssertFalse(store.busy)
        XCTAssertEqual(store.port, VotportCore.port())
        XCTAssertEqual(store.problem, "Current cancellation problem")
    }
}
