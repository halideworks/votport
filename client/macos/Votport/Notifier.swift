import Foundation
import UserNotifications

/// Done and failed notifications through the notification centre, when the
/// setting allows and the user granted them.
enum Notifier {
    @MainActor
    static func transferEnded(_ item: TransferItem) {
        guard UserDefaults.standard.object(forKey: Prefs.notifyKey) as? Bool ?? true,
            let view = item.view
        else { return }
        let content = UNMutableNotificationContent()
        content.title = item.subject
        content.body = Format.statusLine(item)
        switch view.phase {
        case .done, .failed: break
        default: return
        }
        let centre = UNUserNotificationCenter.current()
        centre.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            centre.add(UNNotificationRequest(
                identifier: item.id.uuidString, content: content, trigger: nil))
        }
    }
}
