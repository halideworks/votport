import Foundation
import UserNotifications

/// Done and failed notifications through the notification centre, when the
/// setting allows and the user granted them. Permission is asked once at
/// launch: asking inside `transferEnded` left the first transfer without a
/// banner, since macOS answers the request asynchronously.
enum Notifier {
    /// Written on the main queue from the launch callback, read on the main
    /// actor, so no lock is needed.
    private static var authorized = false
    private static let delegate = Frontmost()

    /// Installs the delegate and asks for permission. Called once at launch.
    static func start() {
        let centre = UNUserNotificationCenter.current()
        // Without a delegate macOS drops the banner and sound of every
        // notification raised while Votport is frontmost, which is exactly
        // when a finished transfer is watched.
        centre.delegate = delegate
        centre.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            DispatchQueue.main.async { authorized = granted }
        }
    }

    @MainActor
    static func transferEnded(_ item: TransferItem) {
        guard authorized,
            UserDefaults.standard.object(forKey: Prefs.notifyKey) as? Bool ?? true,
            let view = item.view
        else { return }
        let content = UNMutableNotificationContent()
        content.title = item.subject
        content.body = Format.statusLine(item)
        content.sound = UNNotificationSound(named: UNNotificationSoundName("completion.wav"))
        switch view.phase {
        case .done, .failed: break
        default: return
        }
        UNUserNotificationCenter.current().add(UNNotificationRequest(
            identifier: item.id.uuidString, content: content, trigger: nil))
    }

    /// Shows banners and plays the sound even while the app is frontmost.
    private final class Frontmost: NSObject, UNUserNotificationCenterDelegate {
        func userNotificationCenter(
            _ centre: UNUserNotificationCenter,
            willPresent notification: UNNotification,
            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
        ) {
            completionHandler([.banner, .sound])
        }
    }
}
