import Foundation

/// Reads the extension's physical footprint, the metric jetsam uses to enforce
/// the NetworkExtension memory limit (about 50 MB on current iOS).
/// `resident_size` overcounts shared pages, so it is not a substitute.
enum MemoryFootprint {
    /// Current `phys_footprint` in bytes, or nil if the syscall failed.
    static func currentBytes() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size
        )
        let kr = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        return UInt64(info.phys_footprint)
    }

    /// Current footprint in MB, or nil on failure.
    static func currentMB() -> Double? {
        currentBytes().map { Double($0) / 1_048_576.0 }
    }
}
