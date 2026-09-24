import Foundation
import Security

/// Minimal Keychain wrapper for small app-side secrets, such as the abuse.ch
/// Auth-Key for ThreatFox/URLhaus feeds. Secrets are kept out of the App Group
/// so they never sit in a shared plaintext file; the tunnel doesn't need them.
///
/// One `kSecClassGenericPassword` item per `account` under a fixed service,
/// readable after first unlock so background blocklist refreshes can use it.
public enum KeychainStore {
    private static let service = "fluxmoat.credentials"

    /// Reads the stored secret for `account`, or nil when absent/unreadable.
    public static func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        return value
    }

    /// Stores the secret for `account`, or clears it when nil or empty.
    /// Delete-then-add keeps the write idempotent.
    @discardableResult
    public static func set(_ value: String?, for account: String) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        guard let value, !value.isEmpty else { return true }

        var attributes = base
        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
    }
}
