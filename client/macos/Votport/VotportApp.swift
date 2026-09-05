import SwiftUI

@main
struct VotportApp: App {
    var body: some Scene {
        WindowGroup {
            ReceiveView()
                .frame(minWidth: 560, minHeight: 420)
        }
    }
}
