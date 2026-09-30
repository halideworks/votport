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
}
