import Foundation

public struct OPVault: Codable, Sendable, Identifiable, Hashable {
    public var id: String
    public var name: String
}

/// A reference to the 1Password item holding a CA.
public struct OPItemRef: Codable, Sendable, Hashable {
    public var itemID: String
    public var vaultID: String
    public var vaultName: String
    public var title: String
}

/// Where CA material and issued certificates live. `OnePasswordCLI` is the real implementation.
/// Each CA gets its own vault holding the CA item and one item per issued certificate.
public protocol CAVault: Sendable {
    func listVaults() async throws -> [OPVault]
    func createVault(name: String) async throws -> OPVault
    func listCAItems() async throws -> [OPItemRef]
    func save(_ material: CAMaterial, title: String, fingerprint: String, vaultID: String) async throws -> OPItemRef
    func load(_ ref: OPItemRef) async throws -> CAMaterial
    /// Saves an issued certificate (never its key) and returns the new item's ID.
    func saveIssued(_ record: IssuedRecord, vaultID: String) async throws -> String
    func listIssuedItemIDs(vaultID: String) async throws -> [String]
    func loadIssued(itemID: String, vaultID: String) async throws -> IssuedRecord
}

/// Talks to 1Password through the `op` CLI. With 1Password's desktop app
/// integration enabled, every call is authorised by the app (Touch ID etc.).
public struct OnePasswordCLI: CAVault {
    /// Nested tags show up as "cert-lab › ca" in 1Password's sidebar.
    public static let tag = "cert-lab/ca"
    public static let issuedTag = "cert-lab/certificate"
    /// Tags written by earlier versions (when the app was called CA Manager); still recognised.
    static let legacyTag = "ca-manager"
    static let legacyIssuedTag = "ca-manager-cert"
    static let certificateField = "certificate"
    static let privateKeyField = "private_key"
    static let fingerprintField = "sha256_fingerprint"
    static let recordField = "record"

    public var executablePath: String
    public var account: String?

    public init(executablePath: String, account: String? = nil) {
        self.executablePath = executablePath
        self.account = account
    }

    public static func locate(override: String? = nil) -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = [override, "/opt/homebrew/bin/op", "/usr/local/bin/op", "\(home)/.local/bin/op", "/usr/bin/op"]
        return candidates.compactMap { $0 }.first { !$0.isEmpty && FileManager.default.isExecutableFile(atPath: $0) }
    }

    // MARK: CAVault

    public func listVaults() async throws -> [OPVault] {
        try JSONDecoder().decode([OPVault].self, from: try await run(["vault", "list", "--format", "json"]))
    }

    public func createVault(name: String) async throws -> OPVault {
        let data = try await run(["vault", "create", name, "--icon", "vault-door",
                                  "--description", "Certificate authority managed by Cert Lab", "--format", "json"])
        return try JSONDecoder().decode(OPVault.self, from: data)
    }

    public func listCAItems() async throws -> [OPItemRef] {
        async let current = run(["item", "list", "--tags", Self.tag, "--format", "json"])
        async let legacy = run(["item", "list", "--tags", Self.legacyTag, "--format", "json"])
        let items = try JSONDecoder().decode([ItemSummary].self, from: try await current)
            + JSONDecoder().decode([ItemSummary].self, from: try await legacy)
        var seen = Set<String>()
        return items.filter { seen.insert($0.id).inserted }.map(\.ref)
    }

    public func save(_ material: CAMaterial, title: String, fingerprint: String, vaultID: String) async throws -> OPItemRef {
        let keyNote = material.isKeyEncrypted
            ? "private_key is a PKCS#8 key encrypted with your CA passphrase (PBES2: PBKDF2-SHA256 + AES-256-CBC). Decrypt it with: openssl pkey -in ca.key"
            : "private_key is an unencrypted PKCS#8 key, protected by 1Password. It works directly with OpenSSL and other tools."
        let item = ItemTemplate(
            title: title,
            category: "SECURE_NOTE",
            tags: [Self.tag],
            fields: [
                .init(id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: """
                    Certificate authority managed by Cert Lab. Certificates it issues are saved as items in this vault.

                    \(keyNote)
                    """),
                .init(id: Self.certificateField, type: "STRING", label: Self.certificateField, value: material.certificatePEM),
                .init(id: Self.privateKeyField, type: "CONCEALED", label: Self.privateKeyField, value: material.keyPEM),
                .init(id: Self.fingerprintField, type: "STRING", label: Self.fingerprintField, value: fingerprint),
            ]
        )
        let data = try await run(["item", "create", "--vault", vaultID, "--format", "json", "-"],
                                 stdin: try JSONEncoder().encode(item))
        return try JSONDecoder().decode(ItemSummary.self, from: data).ref
    }

    public func load(_ ref: OPItemRef) async throws -> CAMaterial {
        let data = try await run(["item", "get", ref.itemID, "--vault", ref.vaultID, "--format", "json"])
        return try Self.material(fromItemJSON: data)
    }

    static func material(fromItemJSON data: Data) throws -> CAMaterial {
        let item = try JSONDecoder().decode(Item.self, from: data)
        return CAMaterial(certificatePEM: try item.field(certificateField), keyPEM: try item.field(privateKeyField))
    }

    public func saveIssued(_ record: IssuedRecord, vaultID: String) async throws -> String {
        var stored = record
        stored.opItemID = nil
        let recordJSON = String(decoding: try JSONCoding.encoder().encode(stored), as: UTF8.self)
        let expires = record.notAfter.formatted(.iso8601.year().month().day())
        let item = ItemTemplate(
            title: "\(record.commonName) (expires \(expires))",
            category: "SECURE_NOTE",
            tags: [Self.issuedTag],
            fields: [
                .init(id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: """
                    Certificate issued by Cert Lab. The private key is not stored.

                    Names: \(record.sans.joined(separator: ", "))
                    \(record.note.isEmpty ? "" : "Note: \(record.note)")
                    """),
                .init(id: Self.certificateField, type: "STRING", label: Self.certificateField, value: record.certificatePEM),
                .init(id: "serial", type: "STRING", label: "serial", value: record.serialNumber),
                .init(id: "expires", type: "STRING", label: "expires", value: expires),
                .init(id: Self.recordField, type: "STRING", label: Self.recordField, value: recordJSON),
            ]
        )
        let data = try await run(["item", "create", "--vault", vaultID, "--format", "json", "-"],
                                 stdin: try JSONEncoder().encode(item))
        return try JSONDecoder().decode(ItemSummary.self, from: data).id
    }

    public func listIssuedItemIDs(vaultID: String) async throws -> [String] {
        // One call for the whole vault, then filter: covers current and legacy tags.
        let data = try await run(["item", "list", "--vault", vaultID, "--format", "json"])
        return try JSONDecoder().decode([ItemSummary].self, from: data)
            .filter { !Set($0.tags ?? []).isDisjoint(with: [Self.issuedTag, Self.legacyIssuedTag]) }
            .map(\.id)
    }

    public func loadIssued(itemID: String, vaultID: String) async throws -> IssuedRecord {
        let data = try await run(["item", "get", itemID, "--vault", vaultID, "--format", "json"])
        let item = try JSONDecoder().decode(Item.self, from: data)
        var record = try JSONCoding.decoder().decode(IssuedRecord.self, from: Data(try item.field(Self.recordField).utf8))
        record.opItemID = itemID
        return record
    }

    // MARK: JSON shapes

    struct ItemTemplate: Encodable {
        struct Field: Encodable {
            var id: String
            var type: String
            var purpose: String?
            var label: String
            var value: String
        }
        var title: String
        var category: String
        var tags: [String]
        var fields: [Field]
    }

    struct ItemSummary: Decodable {
        var id: String
        var title: String
        var vault: OPVault
        var tags: [String]?
        var ref: OPItemRef { OPItemRef(itemID: id, vaultID: vault.id, vaultName: vault.name, title: title) }
    }

    struct Item: Decodable {
        struct Field: Decodable {
            var id: String?
            var label: String?
            var value: String?
        }
        var title: String
        var fields: [Field]?

        func field(_ name: String) throws -> String {
            guard let value = fields?.first(where: { $0.id == name || $0.label == name })?.value, !value.isEmpty else {
                throw CAError.onePassword("item “\(title)” has no \(name) field")
            }
            return value
        }
    }

    // MARK: Process

    func run(_ arguments: [String], stdin: Data? = nil) async throws -> Data {
        var arguments = arguments
        if let account, !account.isEmpty { arguments += ["--account", account] }
        let executable = URL(fileURLWithPath: executablePath)
        let finalArguments = arguments

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try Self.runSync(executable: executable, arguments: finalArguments, stdin: stdin)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private final class Box: @unchecked Sendable { var data = Data() }

    private static func runSync(executable: URL, arguments: [String], stdin: Data?) throws -> Data {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        let input = stdin.map { _ in Pipe() }
        // Never leave stdin attached: `op item get` reads item IDs from piped stdin.
        process.standardInput = input ?? FileHandle.nullDevice

        do { try process.run() } catch { throw CAError.onePasswordNotFound }

        // Waiting on the 1Password approval prompt is fine; hanging forever is not.
        DispatchQueue.global().asyncAfter(deadline: .now() + 180) { [process] in
            if process.isRunning { process.terminate() }
        }
        if let input, let stdin {
            input.fileHandleForWriting.write(stdin)
            try? input.fileHandleForWriting.close()
        }
        let errBox = Box()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            errBox.data = stderr.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw CAError.onePassword(cleanError(String(decoding: errBox.data, as: UTF8.self),
                                                 status: process.terminationStatus))
        }
        return output
    }

    static func cleanError(_ stderr: String, status: Int32) -> String {
        // "[ERROR] 2026/10/25 10:00:00 message" → "message"
        let lines = stderr.split(whereSeparator: \.isNewline).map { line -> String in
            var line = String(line)
            if line.hasPrefix("[ERROR] ") {
                let parts = line.split(separator: " ", maxSplits: 3)
                line = parts.count == 4 ? String(parts[3]) : line
            }
            return line
        }
        let message = lines.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        return message.isEmpty ? "op exited with status \(status)" : message
    }
}
