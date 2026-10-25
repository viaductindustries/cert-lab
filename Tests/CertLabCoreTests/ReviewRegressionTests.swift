import Foundation
import SwiftASN1
import Testing
import X509
@testable import CertLabCore

// Regression tests for the issues found in the first code review (F-numbers in the commit log).

private let passphrase = "correct horse battery staple"
private let soon = Date().addingTimeInterval(86400)

@discardableResult
private func openssl(_ args: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/openssl")
        ? "/opt/homebrew/bin/openssl" : "/usr/bin/openssl")
    process.arguments = args
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    try process.run()
    let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    let error = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw CAError.invalidRequest("openssl failed: \(error)") }
    return output
}

private func tempDir() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("review-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

@Suite struct NameConstraintRegressionTests {
    // F2
    @Test func wildcardCannotCoverExcludedName() throws {
        let constraints = NameConstraints(permittedDNSDomains: ["home.arpa"], excludedDNSDomains: ["admin.home.arpa"])
        #expect(throws: CAError.self) { try Names.check(dns: ["admin.home.arpa"], ips: [], against: constraints) }
        #expect(throws: CAError.self) { try Names.check(dns: ["*.home.arpa"], ips: [], against: constraints) }
        // Wildcards that can't match the excluded name are fine.
        try Names.check(dns: ["*.lab.home.arpa", "nas.home.arpa"], ips: [], against: constraints)
        // Excluding a whole subtree also blocks a wildcard at its parent level only when it can match into it.
        let subtree = NameConstraints(excludedDNSDomains: [".admin.home.arpa"])
        try Names.check(dns: ["*.home.arpa"], ips: [], against: subtree)
        #expect(throws: CAError.self) { try Names.check(dns: ["*.admin.home.arpa"], ips: [], against: subtree) }
    }

    // F2
    @Test func wildcardUnderLeadingDotPermission() throws {
        let constraints = NameConstraints(permittedDNSDomains: [".home.arpa"])
        try Names.check(dns: ["*.home.arpa", "nas.home.arpa"], ips: [], against: constraints)
        #expect(throws: CAError.self) { try Names.check(dns: ["home.arpa"], ips: [], against: constraints) }
    }

    // F13
    @Test func malformedCIDRsThrowInsteadOfCrashing() {
        for bad in ["/", "/8", "10.0.0.0/", "10.0.0.0/8/8", "", "nope/8"] {
            #expect(throws: CAError.self) { try Names.cidrBytes(bad) }
        }
    }

    // F18
    @Test func commonNameIsTheFirstEntry() throws {
        let ca = try CertificateAuthority.generate(.init(commonName: "CA", algorithm: .p256), passphrase: nil)
        let bundle = try CertificateAuthority.issue(IssueRequest(names: ["192.168.1.2", "nas.home.arpa"], notAfter: soon),
                                                    material: ca, passphrase: nil)
        #expect(bundle.record.commonName == "192.168.1.2")
        #expect(Names.commonName(for: ["NAS.Home.Arpa.", "10.0.0.1"]) == "nas.home.arpa")
    }
}

@Suite struct CertificateRegressionTests {
    // F16
    @Test func serialsFitIn20Octets() throws {
        for _ in 0..<2000 {
            let serial = CertificateAuthority.randomSerial()
            #expect(serial.bytes.count == 20)
            #expect(serial.bytes.first! & 0x80 == 0 && serial.bytes.first! != 0)
        }
        let ca = try CertificateAuthority.generate(.init(commonName: "CA", algorithm: .p256), passphrase: nil)
        let bundle = try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: soon), material: ca, passphrase: nil)
        let path = try tempDir().appendingPathComponent("leaf.crt").path
        try bundle.certificatePEM.write(toFile: path, atomically: true, encoding: .utf8)
        let dump = try openssl(["asn1parse", "-in", path])
        // tbsCertificate: version [0], then the serial INTEGER.
        let serialLine = try #require(dump.split(separator: "\n").first { $0.contains("prim: INTEGER") && !$0.contains(":02") })
        #expect(serialLine.contains("l=  20"))
    }

    // F9
    @Test func rejectsCANotYetValid() throws {
        let future = try CertificateAuthority.generate(.init(commonName: "Future CA", algorithm: .p256), passphrase: nil,
                                                       now: Date().addingTimeInterval(2 * 86400))
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: soon), material: future, passphrase: nil)
        }
    }

    // F8
    @Test func parentChainConstraintsAreEnforcedAndOrderChecked() throws {
        let dir = try tempDir()
        func path(_ name: String) -> String { dir.appendingPathComponent(name).path }
        try """
        [root]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign
        nameConstraints = critical,permitted;DNS:home.arpa
        [intermediate]
        basicConstraints = critical,CA:TRUE,pathlen:0
        keyUsage = critical,keyCertSign,cRLSign
        """.write(toFile: path("ext.cnf"), atomically: true, encoding: .utf8)
        try openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-keyout", path("root.key"), "-out", path("root.crt"), "-days", "30", "-subj", "/CN=Root",
                     "-extensions", "root", "-config", path("ext.cnf")])
        try openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-keyout", path("int.key"), "-out", path("int.csr"), "-subj", "/CN=Intermediate"])
        try openssl(["x509", "-req", "-in", path("int.csr"), "-CA", path("root.crt"), "-CAkey", path("root.key"),
                     "-out", path("int.crt"), "-days", "20", "-extfile", path("ext.cnf"), "-extensions", "intermediate"])
        let intermediate = try String(contentsOfFile: path("int.crt"), encoding: .utf8)
        let root = try String(contentsOfFile: path("root.crt"), encoding: .utf8)
        let key = try String(contentsOfFile: path("int.key"), encoding: .utf8)

        let material = try CertificateAuthority.prepareImport(certificatePEM: intermediate + root, keyPEM: key,
                                                              currentPassphrase: nil, newPassphrase: nil)
        _ = try CertificateAuthority.issue(IssueRequest(names: ["nas.home.arpa"], notAfter: soon), material: material, passphrase: nil)
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["outside.example.com"], notAfter: soon), material: material, passphrase: nil)
        }
        // Expiry is capped by the shortest-lived certificate in the chain (the intermediate, 20 days).
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["nas.home.arpa"], notAfter: Date().addingTimeInterval(25 * 86400)),
                                           material: material, passphrase: nil)
        }
        // A chain in the wrong order (or with an unrelated certificate) is rejected at import.
        let unrelated = try CertificateAuthority.generate(.init(commonName: "Other", algorithm: .p256), passphrase: nil)
        #expect(throws: CAError.self) {
            try CertificateAuthority.prepareImport(certificatePEM: intermediate + unrelated.certificatePEM, keyPEM: key,
                                                   currentPassphrase: nil, newPassphrase: nil)
        }
    }

    // F5
    @Test(arguments: [-1, 0, 31, 1_000_000_000])
    func bogusPBKDF2KeyLengthIsRejected(keyLength: Int) throws {
        func octets(_ count: Int) -> ASN1OctetString { ASN1OctetString(contentBytes: ArraySlice(repeating: 7, count: count)) }
        var s = DER.Serializer()
        try s.appendConstructedNode(identifier: .sequence) { s in
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(ASN1ObjectIdentifier("1.2.840.113549.1.5.13"))
                try s.appendConstructedNode(identifier: .sequence) { s in
                    try s.appendConstructedNode(identifier: .sequence) { s in
                        try s.serialize(ASN1ObjectIdentifier("1.2.840.113549.1.5.12"))
                        try s.appendConstructedNode(identifier: .sequence) { s in
                            try s.serialize(octets(16))
                            try s.serialize(1000)
                            try s.serialize(keyLength)
                        }
                    }
                    try s.appendConstructedNode(identifier: .sequence) { s in
                        try s.serialize(ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.42"))
                        try s.serialize(octets(16))
                    }
                }
            }
            try s.serialize(octets(32))
        }
        #expect(throws: CAError.self) { try EncryptedPKCS8.decrypt(Data(s.serializedBytes), passphrase: passphrase) }
    }
}

@Suite struct ProcessRegressionTests {
    // F3: a CLI that exits without reading stdin must produce an error, not SIGPIPE the app.
    @Test func earlyExitWithLargeStdinThrows() async throws {
        let cli = OnePasswordCLI(executablePath: "/usr/bin/false")
        let payload = Data(repeating: 0x41, count: 4 << 20)
        await #expect(throws: CAError.self) { try await cli.run(["item", "create", "-"], stdin: payload) }
    }
}

@Suite struct FileRegressionTests {
    // F4
    @Test func privateFilesAreNeverWorldReadable() throws {
        let old = umask(0o022)
        defer { umask(old) }
        let url = try tempDir().appendingPathComponent("leaf.key")
        try "old".write(to: url, atomically: true, encoding: .utf8)
        try PrivateFile.write(Data("secret".utf8), to: url)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(try String(contentsOf: url, encoding: .utf8) == "secret")
        #expect(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path) == ["leaf.key"])
    }

    // F14
    @Test func unreadableLogIsMovedAsideNotOverwritten() throws {
        let dir = try tempDir()
        let store = LocalStore(directory: dir)
        try "{ not json".write(to: dir.appendingPathComponent("issued.json"), atomically: true, encoding: .utf8)
        #expect(throws: LocalStoreError.self) { try store.loadLog() }
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        let aside = try #require(files.first { $0.hasPrefix("issued.unreadable-") })
        #expect(try String(contentsOf: dir.appendingPathComponent(aside), encoding: .utf8) == "{ not json")
        try store.saveLog([])
        #expect(try String(contentsOf: dir.appendingPathComponent(aside), encoding: .utf8) == "{ not json")
    }
}

/// An in-memory vault with switchable failures, for sync edge cases.
private actor MockVault: CAVault {
    var items: [String: IssuedRecord] = [:]
    var hiddenFromListing: Set<String> = []  // e.g. its tag was removed
    var unreadable: Set<String> = []
    var failListing = false
    var failSaving = false
    var failExistsCheck = false
    var saves = 0

    func setFailListing(_ value: Bool) { failListing = value }
    func setFailSaving(_ value: Bool) { failSaving = value }
    func setFailExistsCheck(_ value: Bool) { failExistsCheck = value }
    func hide(_ id: String) { hiddenFromListing.insert(id) }
    func makeUnreadable(_ id: String) { unreadable.insert(id) }
    func delete(_ id: String) { items[id] = nil }
    func add(_ record: IssuedRecord) -> String {
        let id = UUID().uuidString
        items[id] = record
        return id
    }

    func listVaults() async throws -> [OPVault] { [] }
    func createVault(name: String) async throws -> OPVault { OPVault(id: "v", name: name) }
    func listCAItems() async throws -> [OPItemRef] { [] }
    func save(_ material: CAMaterial, title: String, fingerprint: String, vaultID: String) async throws -> OPItemRef {
        OPItemRef(itemID: "ca", vaultID: vaultID, vaultName: "v", title: title)
    }
    func load(_ ref: OPItemRef) async throws -> CAMaterial { throw CAError.onePasswordNotFound }
    func saveIssued(_ record: IssuedRecord, vaultID: String) async throws -> String {
        if failSaving { throw CAError.onePassword("save failed") }
        saves += 1
        var stored = record
        stored.opItemID = nil
        return add(stored)
    }
    func listIssuedItemIDs(vaultID: String) async throws -> [String] {
        if failListing { throw CAError.onePassword("list failed") }
        return items.keys.filter { !hiddenFromListing.contains($0) }
    }
    func itemExists(itemID: String, vaultID: String) async throws -> Bool {
        if failExistsCheck { throw CAError.onePassword("network error") }
        return items[itemID] != nil
    }
    func loadIssued(itemID: String, vaultID: String) async throws -> IssuedRecord {
        if unreadable.contains(itemID) { throw CAError.onePassword("temporarily unavailable") }
        guard var record = items[itemID] else { throw CAError.onePassword("missing") }
        record.opItemID = itemID
        return record
    }
}

@Suite struct SyncRegressionTests {
    let material: CAMaterial
    let caFingerprint: String

    init() throws {
        material = try CertificateAuthority.generate(.init(commonName: "Sync CA", algorithm: .p256), passphrase: nil)
        caFingerprint = try CertificateAuthority.info(certificatePEM: material.certificatePEM).fingerprint
    }

    func issue(_ name: String) throws -> IssuedRecord {
        try CertificateAuthority.issue(IssueRequest(names: [name], notAfter: soon), material: material, passphrase: nil).record
    }

    // F1
    @Test func mergeKeepsRecordsAddedDuringSync() async throws {
        let vault = MockVault()
        let pending = try issue("a.test")
        let snapshot = [pending]
        let result = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: snapshot, vault: vault)
        // Meanwhile, another certificate was issued whose 1Password save failed.
        let issuedDuringSync = try issue("b.test")
        let merged = IssuanceSync.merge(result, snapshot: snapshot, into: snapshot + [issuedDuringSync])
        #expect(merged.map(\.commonName) == ["a.test", "b.test"])
        #expect(merged[0].opItemID != nil)
        #expect(merged[1].opItemID == nil)
    }

    // F6
    @Test func listingFailureChangesNothingAndPushesNothing() async throws {
        let vault = MockVault()
        await vault.setFailListing(true)
        let log = [try issue("a.test")]
        let result = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: log, vault: vault)
        #expect(result.failures.count == 1)
        #expect(result.log == log)
        #expect(await vault.saves == 0)
    }

    // F6: a save that reached 1Password but wasn't recorded locally isn't pushed again.
    @Test func adoptsExistingRemoteCopyInsteadOfDuplicating() async throws {
        let vault = MockVault()
        let record = try issue("a.test")
        let remoteID = await vault.add(record)
        let result = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: [record], vault: vault)
        #expect(result.pushed == 0 && result.pulled == 0)
        #expect(result.log.first?.opItemID == remoteID)
        #expect(await vault.items.count == 1)
    }

    // F7
    @Test func deletionInOnePasswordRemovesLocalRecord() async throws {
        let vault = MockVault()
        let kept = try issue("kept.test")
        let deleted = try issue("deleted.test")
        let first = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: [kept, deleted], vault: vault)
        #expect(first.pushed == 2)
        let deletedID = try #require(first.log.first { $0.commonName == "deleted.test" }?.opItemID)
        await vault.delete(deletedID)

        let second = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: first.log, vault: vault)
        #expect(second.removed == 1)
        #expect(second.log.map(\.commonName) == ["kept.test"])
        let merged = IssuanceSync.merge(second, snapshot: first.log, into: first.log)
        #expect(merged.map(\.commonName) == ["kept.test"])
    }

    // Failed pushes stay pending and are retried.
    @Test func failedPushStaysPending() async throws {
        let vault = MockVault()
        await vault.setFailSaving(true)
        let result = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: [try issue("a.test")], vault: vault)
        #expect(result.failures.count == 1 && result.log.first?.opItemID == nil)
        await vault.setFailSaving(false)
        let retry = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: result.log, vault: vault)
        #expect(retry.pushed == 1 && retry.failures.isEmpty)
    }
}

// MARK: - Round 2 (R-numbers)

@Suite struct RoundTwoRegressionTests {
    let material: CAMaterial
    let caFingerprint: String

    init() throws {
        material = try CertificateAuthority.generate(.init(commonName: "Sync CA", algorithm: .p256), passphrase: nil)
        caFingerprint = try CertificateAuthority.info(certificatePEM: material.certificatePEM).fingerprint
    }

    func issue(_ name: String) throws -> IssuedRecord {
        try CertificateAuthority.issue(IssueRequest(names: [name], notAfter: soon), material: material, passphrase: nil).record
    }

    // R1: an unreadable file that can't be moved aside is never overwritten.
    @Test func saveNeverOverwritesUnreadableFile() throws {
        let dir = try tempDir()
        let store = LocalStore(directory: dir)
        let url = dir.appendingPathComponent("issued.json")
        try "{ broken".write(to: url, atomically: true, encoding: .utf8)
        // Make the directory read-only so moving the file aside fails.
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: dir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path) }
        #expect(throws: LocalStoreError.self) { try store.loadLog() }
        #expect(throws: (any Error).self) { try store.saveLog([]) }
        #expect(try String(contentsOf: url, encoding: .utf8) == "{ broken")
    }

    // R2: if an unknown remote item can't be read, pending records aren't pushed (it may be their copy).
    @Test func unreadableRemoteItemBlocksPushes() async throws {
        let vault = MockVault()
        let record = try issue("a.test")
        let remoteID = await vault.add(record)  // saved earlier, but the ID was never recorded locally
        await vault.makeUnreadable(remoteID)
        let result = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: [record], vault: vault)
        #expect(result.pushed == 0)
        #expect(await vault.items.count == 1)
        #expect(!result.failures.isEmpty)
    }

    // R4: missing from the (tag-filtered) list isn't deletion; only a confirmed missing item is.
    @Test func onlyConfirmedDeletionsRemoveRecords() async throws {
        let vault = MockVault()
        let first = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v",
                                            log: [try issue("untagged.test"), try issue("flaky.test")], vault: vault)
        let untagged = try #require(first.log.first { $0.commonName == "untagged.test" }?.opItemID)
        await vault.hide(untagged)
        var second = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: first.log, vault: vault)
        #expect(second.removed == 0 && second.log.count == 2)

        await vault.delete(untagged)
        await vault.setFailExistsCheck(true)
        second = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: first.log, vault: vault)
        #expect(second.removed == 0 && !second.failures.isEmpty)

        await vault.setFailExistsCheck(false)
        second = await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: "v", log: first.log, vault: vault)
        #expect(second.removed == 1)
        #expect(second.log.map(\.commonName) == ["flaky.test"])
    }

    // R5: merge takes a changed item ID from the sync when nothing else changed it.
    @Test func mergeAdoptsReplacementItemID() throws {
        var record = try issue("a.test")
        record.opItemID = "deleted"
        var synced = record
        synced.opItemID = "replacement"
        let result = IssuanceSync.Result(log: [synced])
        #expect(IssuanceSync.merge(result, snapshot: [record], into: [record]).first?.opItemID == "replacement")
    }

    // R3: path length limits and key usage apply to every certificate in the chain.
    @Test func pathLengthAndKeyUsageAreEnforced() throws {
        let dir = try tempDir()
        func path(_ name: String) -> String { dir.appendingPathComponent(name).path }
        try """
        [root]
        basicConstraints = critical,CA:TRUE,pathlen:0
        keyUsage = critical,keyCertSign,cRLSign
        [intermediate]
        basicConstraints = critical,CA:TRUE,pathlen:0
        keyUsage = critical,keyCertSign,cRLSign
        """.write(toFile: path("ext.cnf"), atomically: true, encoding: .utf8)
        try openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-keyout", path("root.key"), "-out", path("root.crt"), "-days", "30", "-subj", "/CN=Root",
                     "-extensions", "root", "-config", path("ext.cnf")])
        try openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-keyout", path("int.key"), "-out", path("int.csr"), "-subj", "/CN=Intermediate"])
        try openssl(["x509", "-req", "-in", path("int.csr"), "-CA", path("root.crt"), "-CAkey", path("root.key"),
                     "-out", path("int.crt"), "-days", "20", "-extfile", path("ext.cnf"), "-extensions", "intermediate"])
        let chain = try String(contentsOfFile: path("int.crt"), encoding: .utf8) + String(contentsOfFile: path("root.crt"), encoding: .utf8)
        let key = try String(contentsOfFile: path("int.key"), encoding: .utf8)
        // The root's pathlen:0 forbids any intermediate below it.
        #expect(throws: CAError.self) {
            try CertificateAuthority.prepareImport(certificatePEM: chain, keyPEM: key, currentPassphrase: nil, newPassphrase: nil)
        }
        let smuggled = CAMaterial(certificatePEM: chain, keyPEM: key)
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: soon), material: smuggled, passphrase: nil)
        }
        // A leaf certificate and its key can't act as a CA, even if they reach 1Password some other way.
        let leaf = try CertificateAuthority.issue(IssueRequest(names: ["leaf.test"], notAfter: soon), material: material, passphrase: nil)
        let fakeCA = CAMaterial(certificatePEM: leaf.certificatePEM, keyPEM: leaf.privateKeyPEM)
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: soon), material: fakeCA, passphrase: nil)
        }
    }

    // R6
    @Test func longFileNamesCanBeWrittenPrivately() throws {
        let name = String(repeating: "a", count: 220) + ".key"
        let url = try tempDir().appendingPathComponent(name)
        try PrivateFile.write(Data("k".utf8), to: url)
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    // R7: a process killed by a signal right away isn't reported as a timeout.
    @Test func signalIsNotReportedAsTimeout() async throws {
        let script = try tempDir().appendingPathComponent("die.sh")
        try "#!/bin/sh\nkill -TERM $$\n".write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        do {
            _ = try await OnePasswordCLI(executablePath: script.path).run(["vault", "list"])
            Issue.record("expected an error")
        } catch CAError.onePassword(let message) {
            #expect(message.contains("signal"))
            #expect(!message.contains("didn’t respond"))
        }
    }
}
