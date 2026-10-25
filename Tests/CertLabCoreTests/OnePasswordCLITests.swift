import Foundation
import Testing
@testable import CertLabCore

/// Exercises the real Process plumbing against a fake `op` that mimics the
/// 1Password CLI's JSON shapes and stores vaults and items in a temp directory.
@Suite struct OnePasswordCLITests {
    static let fakeOp = #"""
    #!/usr/bin/env python3
    import json, os, sys, uuid
    store = os.path.join(os.path.dirname(sys.argv[0]), "store.json")
    data = json.load(open(store)) if os.path.exists(store) else {"vaults": [{"id": "v1", "name": "Private"}], "items": {}}
    args = sys.argv[1:]
    def opt(name):
        return args[args.index(name) + 1] if name in args else None
    def fail(msg):
        sys.stderr.write("[ERROR] 2026/10/25 10:00:00 %s\n" % msg); sys.exit(1)
    def save():
        json.dump(data, open(store, "w"))
    if args[:2] == ["vault", "list"]:
        print(json.dumps(data["vaults"]))
    elif args[:2] == ["vault", "create"]:
        vault = {"id": uuid.uuid4().hex[:26], "name": args[2]}
        data["vaults"].append(vault); save()
        print(json.dumps(vault))
    elif args[:2] == ["item", "create"]:
        assert "-" in args
        tmpl = json.load(sys.stdin)
        vault = next((v for v in data["vaults"] if v["id"] == opt("--vault")), None) or fail("vault not found")
        item = dict(tmpl, id=uuid.uuid4().hex[:26], vault=vault)
        for f in item["fields"]:
            if f["id"] != "notesPlain": f["id"] = uuid.uuid4().hex[:10]  # real op may reassign ids
        data["items"][item["id"]] = item; save()
        print(json.dumps(item))
    elif args[:2] == ["item", "get"]:
        item = data["items"].get(args[2])
        if not item or item["vault"]["id"] != opt("--vault"):
            fail("\"%s\" isn't an item in the \"%s\" vault." % (args[2], opt("--vault")))
        print(json.dumps(item))
    elif args[:2] == ["item", "list"]:
        tag, vault = opt("--tags"), opt("--vault")
        print(json.dumps([{k: i[k] for k in ("id", "title", "vault", "tags")} for i in data["items"].values()
                          if (tag is None or tag in i.get("tags", [])) and (vault is None or i["vault"]["id"] == vault)]))
    else:
        fail("unknown command")
    """#

    static func makeClient() throws -> OnePasswordCLI {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fake-op-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("op").path
        try fakeOp.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        return OnePasswordCLI(executablePath: path)
    }

    @Test func caInItsOwnVault() async throws {
        let op = try Self.makeClient()
        let vault = try await op.createVault(name: "CA: 1P Test CA")
        #expect(try await op.listVaults().map(\.name) == ["Private", "CA: 1P Test CA"])

        let material = try CertificateAuthority.generate(.init(commonName: "1P Test CA", algorithm: .p256), passphrase: nil)
        let info = try CertificateAuthority.info(certificatePEM: material.certificatePEM)
        let ref = try await op.save(material, title: "CA: 1P Test CA", fingerprint: info.fingerprint, vaultID: vault.id)
        #expect(ref.vaultName == "CA: 1P Test CA")
        #expect(try await op.load(ref) == material)
        #expect(try await op.listCAItems() == [ref])
    }

    @Test func issuedCertificatesRoundTrip() async throws {
        let op = try Self.makeClient()
        let vault = try await op.createVault(name: "CA")
        let material = try CertificateAuthority.generate(.init(commonName: "CA", algorithm: .p256), passphrase: nil)
        let bundle = try CertificateAuthority.issue(
            IssueRequest(names: ["svc.test", "10.0.0.5"], notAfter: Date().addingTimeInterval(86400), note: "hello"),
            material: material, passphrase: nil)

        let itemID = try await op.saveIssued(bundle.record, vaultID: vault.id)
        #expect(try await op.listIssuedItemIDs(vaultID: vault.id) == [itemID])
        #expect(try await op.listCAItems().isEmpty)  // cert items aren't mistaken for CAs

        let loaded = try await op.loadIssued(itemID: itemID, vaultID: vault.id)
        #expect(loaded.opItemID == itemID)
        #expect(loaded.fingerprint == bundle.record.fingerprint)
        #expect(loaded.sans == ["svc.test", "10.0.0.5"])
        #expect(loaded.note == "hello")
        #expect(loaded.certificatePEM == bundle.certificatePEM)
        #expect(abs(loaded.notAfter.timeIntervalSince(bundle.record.notAfter)) < 0.001)
    }

    @Test func syncBetweenTwoMacs() async throws {
        let op = try Self.makeClient()
        let vault = try await op.createVault(name: "CA")
        let material = try CertificateAuthority.generate(.init(commonName: "CA", algorithm: .p256), passphrase: nil)
        let caFingerprint = try CertificateAuthority.info(certificatePEM: material.certificatePEM).fingerprint
        func issue(_ name: String) throws -> IssuedRecord {
            try CertificateAuthority.issue(IssueRequest(names: [name], notAfter: Date().addingTimeInterval(86400)),
                                           material: material, passphrase: nil).record
        }

        // Mac A issued two certs while 1Password writes failed; sync pushes them.
        let macA = try await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: vault.id,
                                               log: [try issue("a.test"), try issue("b.test")], vault: op)
        #expect(macA.pushed == 2 && macA.pulled == 0)
        #expect(macA.log.allSatisfy { $0.opItemID != nil })

        // Mac B has one cert of its own; sync pushes it and pulls A's two.
        let macB = try await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: vault.id,
                                               log: [try issue("c.test")], vault: op)
        #expect(macB.pushed == 1 && macB.pulled == 2)
        #expect(Set(macB.log.map(\.commonName)) == ["a.test", "b.test", "c.test"])

        // Syncing again is a no-op, and other CAs' records aren't touched.
        let other = IssuedRecord(id: UUID(), caFingerprint: "OTHER", serialNumber: "01", fingerprint: "X", commonName: "x",
                                 dnsNames: ["x"], ipAddresses: [], keyAlgorithm: .p256, includeClientAuth: false,
                                 notBefore: Date(), notAfter: Date(), issuedAt: Date(), note: "", certificatePEM: "")
        let again = try await IssuanceSync.sync(caFingerprint: caFingerprint, vaultID: vault.id,
                                                log: macB.log + [other], vault: op)
        #expect(again.pushed == 0 && again.pulled == 0 && again.failures.isEmpty)
        #expect(again.log.count == 4)
        #expect(again.log.last?.opItemID == nil)
    }

    @Test func recognisesLegacyTags() async throws {
        let op = try Self.makeClient()
        let vault = try await op.createVault(name: "Old CA")
        // Write items the way the CA Manager-era app tagged them.
        let legacy = OnePasswordCLI.ItemTemplate(title: "CA: Old", category: "SECURE_NOTE", tags: ["ca-manager"], fields: [
            .init(id: "certificate", type: "STRING", label: "certificate", value: "x"),
        ])
        let cert = OnePasswordCLI.ItemTemplate(title: "old.test", category: "SECURE_NOTE", tags: ["ca-manager-cert"], fields: [])
        let other = OnePasswordCLI.ItemTemplate(title: "Unrelated", category: "SECURE_NOTE", tags: ["misc"], fields: [])
        for item in [legacy, cert, other] {
            _ = try await op.run(["item", "create", "--vault", vault.id, "--format", "json", "-"], stdin: JSONEncoder().encode(item))
        }
        #expect(try await op.listCAItems().map(\.title) == ["CA: Old"])
        #expect(try await op.listIssuedItemIDs(vaultID: vault.id).count == 1)
    }

    @Test func surfacesCLIErrors() async throws {
        let op = try Self.makeClient()
        let missing = OPItemRef(itemID: "nope", vaultID: "v1", vaultName: "Private", title: "x")
        await #expect(throws: CAError.onePassword("\"nope\" isn't an item in the \"v1\" vault.")) {
            try await op.load(missing)
        }
        let absent = OnePasswordCLI(executablePath: "/nonexistent/op")
        await #expect(throws: CAError.onePasswordNotFound) { try await absent.listVaults() }
    }

    @Test func localStoreRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("store-\(UUID().uuidString)")
        let store = LocalStore(directory: dir)
        #expect(try store.loadAuthorities().isEmpty)
        let record = CARecord(name: "X", item: OPItemRef(itemID: "i", vaultID: "v", vaultName: "V", title: "t"),
                              certificatePEM: "pem", fingerprint: "AA", keyEncrypted: false)
        try store.saveAuthorities([record])
        let loaded = try #require(try store.loadAuthorities().first)
        #expect(abs(loaded.addedAt.timeIntervalSince(record.addedAt)) < 0.001)
        var normalized = loaded
        normalized.addedAt = record.addedAt
        #expect(normalized == record)
    }
}
