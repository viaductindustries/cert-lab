import Foundation

/// Writes secrets (private keys) to disk without ever making them readable by others.
public enum PrivateFile {
    /// The temporary file is created with mode 0600 *before* any bytes go in (so the
    /// umask can't widen it), then renamed over the destination.
    public static func write(_ data: Data, to url: URL) throws {
        // Short and independent of the destination name, so long file names still work.
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".certlab-\(UUID().uuidString.prefix(8)).tmp")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, url.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            unlink(temporary.path)
            throw error
        }
    }
}
