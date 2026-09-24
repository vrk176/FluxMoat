import Foundation
import os

/// Finds the utun file descriptor behind this `NEPacketTunnelProvider` so
/// leaf's tun inbound can read and write packets on it directly.
///
/// NetworkExtension has no public API for this fd. Instead of KVC on
/// `packetFlow`'s private `socket.fileDescriptor`, this scans open fds and asks
/// each for `UTUN_OPT_IFNAME` via `getsockopt`, so no private symbols are used.
/// It still relies on undocumented behavior; recheck on each major iOS release.
enum TunnelInterface {
    // From <sys/kern_control.h> and <net/if_utun.h>, which Swift does not
    // always import.
    private static let sysprotoControl: Int32 = 2   // SYSPROTO_CONTROL
    private static let utunOptIfname: Int32 = 2      // UTUN_OPT_IFNAME
    private static let ifNameSize = 16               // IFNAMSIZ

    private static let log = Logger(subsystem: "fluxmoat", category: "tun-fd")

    /// Returns the highest-numbered `utun*` fd, which is this tunnel's
    /// interface in a freshly started provider. Nil if none is found.
    static func currentUTunFD() -> Int32? {
        var found: Int32?
        var foundName = ""
        // The provider process has few open fds; a small scan is cheap and
        // avoids depending on any specific fd number.
        for fd in Int32(0)..<Int32(1024) {
            var name = [CChar](repeating: 0, count: ifNameSize)
            var len = socklen_t(ifNameSize)
            let rc = getsockopt(fd, sysprotoControl, utunOptIfname, &name, &len)
            guard rc == 0 else { continue }
            // Decode up to the NUL terminator; String(cString:) is deprecated.
            let ifname = String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if ifname.hasPrefix("utun") {
                // Keep the highest fd: the provider's tun is created last.
                if found == nil || fd > found! {
                    found = fd
                    foundName = ifname
                }
            }
        }
        if let found {
            log.notice("✅ tun-fd resolved fd=\(found, privacy: .public) if=\(foundName, privacy: .public)")
        } else {
            log.error("❌ tun-fd not found (no utun SYSPROTO_CONTROL socket)")
        }
        return found
    }
}
