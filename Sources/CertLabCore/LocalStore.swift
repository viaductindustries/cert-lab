import Foundation

/// A CA known to this Mac. Only public data is kept locally; the key stays in 1Password.
/// `item.vaultID` is the CA's own vault, which also holds its issued certificates.
public struct CARecord: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var item: OPItemRef
    public var certificatePEM: String
    public var fingerprint: String
    /// Whether the key in 1Password needs a passphrase to issue.
    public var keyEncrypted: Bool
    public var addedAt: Date

    public init(name: String, item: OPItemRef, certificatePEM: String, fingerprint: String, keyEncrypted: Bool,
                addedAt: Date = Date()) {
        self.id = UUID()
        self.name = name
        self.item = item
        self.certificatePEM = certificatePEM
        self.fingerprint = fingerprint
        self.keyEncrypted = keyEncrypted
        self.addedAt = addedAt
    }
}

/// JSON files in ~/Library/Application Support/Cert Lab (or $CERT_LAB_DATA_DIR).
public struct LocalStore: Sendable {
    public var directory: URL

    public init(directory: URL? = nil) {
        let override = ProcessInfo.processInfo.environment["CERT_LAB_DATA_DIR"].map { URL(fileURLWithPath: $0) }
        self.directory = directory ?? override ?? Self.defaultDirectory()
    }

    /// ~/Library/Application Support/Cert Lab, moved from "CA Manager" (the app's old name) if needed.
    private static func defaultDirectory() -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let current = support.appendingPathComponent("Cert Lab", isDirectory: true)
        let legacy = support.appendingPathComponent("CA Manager", isDirectory: true)
        let fm = FileManager.default
        if !fm.fileExists(atPath: current.path), fm.fileExists(atPath: legacy.path) {
            try? fm.moveItem(at: legacy, to: current)
        }
        return current
    }

    private var casURL: URL { directory.appendingPathComponent("authorities.json") }
    private var logURL: URL { directory.appendingPathComponent("issued.json") }

    public func loadAuthorities() throws -> [CARecord] { try load(casURL) ?? [] }
    public func saveAuthorities(_ records: [CARecord]) throws { try save(records, to: casURL, as: [CARecord].self) }
    public func loadLog() throws -> [IssuedRecord] { try load(logURL) ?? [] }
    public func saveLog(_ records: [IssuedRecord]) throws { try save(records, to: logURL, as: [IssuedRecord].self) }

    /// Loads a JSON file. A file that exists but can't be decoded is moved aside (never
    /// overwritten) and reported, so its contents can be recovered by hand.
    private func load<T: Decodable>(_ url: URL) throws -> T? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            return try JSONCoding.decoder().decode(T.self, from: Data(contentsOf: url))
        } catch {
            let underlying = error.localizedDescription
            let aside = try moveAside(url, underlying: underlying)
            throw LocalStoreError.unreadable(file: url.lastPathComponent, movedTo: aside, underlying: underlying)
        }
    }

    /// Moves an unreadable file to a unique name next to it. Throws if it can't, so the
    /// caller never goes on to replace data that wasn't preserved.
    private func moveAside(_ url: URL, underlying: String) throws -> URL {
        let stamp = Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false)
            .dateTimeSeparator(.standard)).replacingOccurrences(of: ":", with: "")
        let unique = UUID().uuidString.prefix(8)
        let aside = url.deletingPathExtension().appendingPathExtension("unreadable-\(stamp)-\(unique).json")
        do {
            try FileManager.default.moveItem(at: url, to: aside)
        } catch {
            throw LocalStoreError.unreadableNotMoved(file: url.lastPathComponent, underlying: underlying)
        }
        return aside
    }

    /// Refuses to replace an existing file that can't be decoded, unless it can first be moved aside.
    private func save<T: Codable>(_ value: T, to url: URL, as type: T.Type) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: url.path),
           (try? JSONCoding.decoder().decode(T.self, from: Data(contentsOf: url))) == nil {
            _ = try moveAside(url, underlying: "found unreadable while saving")
        }
        try JSONCoding.encoder().encode(value).write(to: url, options: .atomic)
    }
}

/// JSON with readable, millisecond-precision ISO 8601 dates.
enum JSONCoding {
    private static let dateFormat = Date.ISO8601FormatStyle(includingFractionalSeconds: true)

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(date.formatted(dateFormat))
        }
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let string = try decoder.singleValueContainer().decode(String.self)
            guard let date = try? Date(string, strategy: dateFormat) ?? Date(string, strategy: .iso8601) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Bad date \(string)"))
            }
            return date
        }
        return decoder
    }
}

public enum LocalStoreError: LocalizedError {
    case unreadable(file: String, movedTo: URL, underlying: String)
    case unreadableNotMoved(file: String, underlying: String)

    public var errorDescription: String? {
        switch self {
        case .unreadable(let file, let movedTo, let underlying):
            "\(file) couldn’t be read (\(underlying)). It was moved to \(movedTo.path) so nothing is lost; Cert Lab is starting with an empty copy."
        case .unreadableNotMoved(let file, let underlying):
            "\(file) couldn’t be read (\(underlying)) and couldn’t be moved aside. It has been left untouched, and changes to it won’t be saved until it’s fixed or removed."
        }
    }
}
