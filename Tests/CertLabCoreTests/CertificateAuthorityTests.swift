import Foundation
import Testing
@testable import CertLabCore

private let passphrase = "correct horse battery staple"

/// Runs openssl (Homebrew's OpenSSL 3 if present) and returns stdout.
@discardableResult
private func openssl(_ args: [String], stdin: String? = nil) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/openssl")
        ? "/opt/homebrew/bin/openssl" : "/usr/bin/openssl")
    process.arguments = args
    let out = Pipe(), err = Pipe(), input = Pipe()
    process.standardOutput = out
    process.standardError = err
    process.standardInput = input
    try process.run()
    if let stdin { input.fileHandleForWriting.write(Data(stdin.utf8)) }
    try input.fileHandleForWriting.close()
    let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    let error = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw CAError.invalidRequest("openssl \(args.joined(separator: " ")) failed: \(error)")
    }
    return output + error
}

private func tempDir() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ca-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

@Suite struct EncryptionTests {
    @Test func roundTrip() throws {
        let key = try SigningKey.generate(.p256)
        let pem = try key.encryptedPEM(passphrase: passphrase)
        #expect(pem.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        let decoded = try SigningKey(pem: pem, passphrase: passphrase)
        #expect(decoded.pkcs8DER == key.pkcs8DER)
        #expect(throws: CAError.incorrectPassphrase) { try SigningKey(pem: pem, passphrase: "wrong passphrase!!") }
    }

    @Test func survivesMangledWhitespace() throws {
        let key = try SigningKey.generate(.p256)
        let pem = try key.encryptedPEM(passphrase: passphrase)
        let mangled = pem.replacingOccurrences(of: "\n", with: " ")
        #expect(try SigningKey(pem: mangled, passphrase: passphrase).pkcs8DER == key.pkcs8DER)
    }

    @Test func opensslCanDecryptOurKeys() throws {
        let dir = try tempDir()
        let key = try SigningKey.generate(.p384)
        let path = dir.appendingPathComponent("enc.pem").path
        try key.encryptedPEM(passphrase: passphrase).write(toFile: path, atomically: true, encoding: .utf8)
        let out = try openssl(["pkey", "-in", path, "-passin", "pass:\(passphrase)"])
        #expect(try SigningKey(pem: out, passphrase: nil).pkcs8DER == key.pkcs8DER)
    }

    @Test(arguments: ["aes-256-cbc", "aes-128-cbc"])
    func weCanDecryptOpenSSLKeys(cipher: String) throws {
        let dir = try tempDir()
        let plain = dir.appendingPathComponent("plain.pem").path
        let enc = dir.appendingPathComponent("enc.pem").path
        try openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", plain])
        try openssl(["pkcs8", "-topk8", "-v2", cipher, "-in", plain, "-out", enc, "-passout", "pass:\(passphrase)"])
        let decrypted = try SigningKey(pem: String(contentsOfFile: enc, encoding: .utf8), passphrase: passphrase)
        let original = try SigningKey(pem: String(contentsOfFile: plain, encoding: .utf8), passphrase: nil)
        #expect(decrypted.pkcs8DER == original.pkcs8DER)
    }
}

@Suite struct IssuanceTests {
    func makeCA(_ algorithm: KeyAlgorithm = .p384, dns: [String] = [], ips: [String] = []) throws -> CAMaterial {
        try CertificateAuthority.generate(
            .init(commonName: "Test Home CA", organization: "Test", algorithm: algorithm,
                  permittedDNS: dns, permittedIPRanges: ips),
            passphrase: passphrase)
    }

    @Test(arguments: [(KeyAlgorithm.p384, KeyAlgorithm.p256), (.rsa3072, .rsa2048), (.p256, .rsa2048)])
    func issuedCertificateVerifiesWithOpenSSL(caAlg: KeyAlgorithm, leafAlg: KeyAlgorithm) throws {
        let ca = try makeCA(caAlg)
        let expiry = Date().addingTimeInterval(86400 * 90)
        let bundle = try CertificateAuthority.issue(
            IssueRequest(names: ["nas.home.arpa", "*.nas.home.arpa", "192.168.1.10", "fd00::1"],
                         notAfter: expiry, keyAlgorithm: leafAlg, includeClientAuth: true),
            material: ca, passphrase: passphrase)

        let dir = try tempDir()
        func write(_ name: String, _ text: String) throws -> String {
            let path = dir.appendingPathComponent(name).path
            try text.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let caPath = try write("ca.crt", ca.certificatePEM)
        let leafPath = try write("leaf.crt", bundle.certificatePEM)
        let keyPath = try write("leaf.key", bundle.privateKeyPEM)

        let verify = try openssl(["verify", "-CAfile", caPath, "-purpose", "sslserver", leafPath])
        #expect(verify.contains("OK"))
        let text = try openssl(["x509", "-in", leafPath, "-noout", "-text"])
        #expect(text.contains("DNS:nas.home.arpa"))
        #expect(text.contains("DNS:*.nas.home.arpa"))
        #expect(text.contains("IP Address:192.168.1.10"))
        #expect(text.contains("IP Address:FD00:0:0:0:0:0:0:1"))
        #expect(text.contains("TLS Web Server Authentication, TLS Web Client Authentication"))
        #expect(text.contains("CA:FALSE"))

        // Key matches cert.
        let certPub = try openssl(["x509", "-in", leafPath, "-noout", "-pubkey"])
        let keyPub = try openssl(["pkey", "-in", keyPath, "-pubout"])
        #expect(certPub == keyPub)

        #expect(bundle.fullChainPEM.components(separatedBy: "BEGIN CERTIFICATE").count == 3)
        #expect(bundle.record.dnsNames == ["nas.home.arpa", "*.nas.home.arpa"])
        #expect(bundle.record.ipAddresses == ["192.168.1.10", "fd00::1"])
        #expect(abs(bundle.record.notAfter.timeIntervalSince(expiry)) < 1)
    }

    @Test func caCertificateHasExpectedExtensions() throws {
        let ca = try makeCA(dns: ["home.arpa", ".internal"], ips: ["192.168.0.0/16", "fd00::/8"])
        let dir = try tempDir()
        let path = dir.appendingPathComponent("ca.crt").path
        try ca.certificatePEM.write(toFile: path, atomically: true, encoding: .utf8)
        let text = try openssl(["x509", "-in", path, "-noout", "-text"])
        #expect(text.contains("CA:TRUE, pathlen:0"))
        #expect(text.contains("Certificate Sign, CRL Sign"))
        #expect(text.contains("DNS:home.arpa"))
        #expect(text.contains("IP:192.168.0.0/255.255.0.0"))

        let info = try CertificateAuthority.info(certificatePEM: ca.certificatePEM)
        #expect(info.commonName == "Test Home CA")
        #expect(info.permittedDNS == ["home.arpa", ".internal"])
        #expect(info.permittedIPRanges == ["192.168.0.0/16", "fd00::/8"])
    }

    @Test func enforcesNameConstraints() throws {
        let ca = try makeCA(dns: ["home.arpa"], ips: ["10.0.0.0/8"])
        let expiry = Date().addingTimeInterval(86400)
        _ = try CertificateAuthority.issue(IssueRequest(names: ["a.b.home.arpa", "home.arpa", "10.1.2.3"], notAfter: expiry),
                                           material: ca, passphrase: passphrase)
        for bad in ["example.com", "evilhome.arpa", "192.168.1.1", "::1"] {
            #expect(throws: CAError.self) {
                try CertificateAuthority.issue(IssueRequest(names: [bad], notAfter: expiry), material: ca, passphrase: passphrase)
            }
        }
    }

    @Test func rejectsBadRequests() throws {
        let ca = try makeCA(.p256)
        let soon = Date().addingTimeInterval(86400)
        #expect(throws: CAError.incorrectPassphrase) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: soon), material: ca, passphrase: "nope nope nope")
        }
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: [], notAfter: soon), material: ca, passphrase: passphrase)
        }
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["bad_host!"], notAfter: soon), material: ca, passphrase: passphrase)
        }
        #expect(throws: CAError.self) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: Date().addingTimeInterval(86400 * 365 * 20)),
                                           material: ca, passphrase: passphrase)
        }
    }

    @Test func importsOpenSSLGeneratedCA() throws {
        let dir = try tempDir()
        let key = dir.appendingPathComponent("ca.key").path
        let cert = dir.appendingPathComponent("ca.crt").path
        try openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "365",
                     "-subj", "/CN=Imported CA", "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        let material = try CertificateAuthority.prepareImport(
            certificatePEM: String(contentsOfFile: cert, encoding: .utf8),
            keyPEM: String(contentsOfFile: key, encoding: .utf8),
            currentPassphrase: nil, newPassphrase: passphrase)
        #expect(material.keyPEM.contains("ENCRYPTED PRIVATE KEY"))

        let bundle = try CertificateAuthority.issue(IssueRequest(names: ["x.test"], notAfter: Date().addingTimeInterval(86400)),
                                                    material: material, passphrase: passphrase)
        let leaf = dir.appendingPathComponent("leaf.crt").path
        try bundle.certificatePEM.write(toFile: leaf, atomically: true, encoding: .utf8)
        #expect(try openssl(["verify", "-CAfile", cert, leaf]).contains("OK"))

        // Mismatched key is rejected; a non-CA cert is rejected.
        let otherKey = try SigningKey.generate(.rsa2048).pkcs8PEM
        #expect(throws: CAError.keyDoesNotMatchCertificate) {
            try CertificateAuthority.prepareImport(certificatePEM: String(contentsOfFile: cert, encoding: .utf8),
                                                   keyPEM: otherKey, currentPassphrase: nil, newPassphrase: passphrase)
        }
        #expect(throws: CAError.self) {
            try CertificateAuthority.prepareImport(certificatePEM: bundle.certificatePEM, keyPEM: bundle.privateKeyPEM,
                                                   currentPassphrase: nil, newPassphrase: passphrase)
        }
    }

    @Test func importsLegacySEC1AndEncryptedKeys() throws {
        let dir = try tempDir()
        let key = dir.appendingPathComponent("ca.key").path
        let sec1 = dir.appendingPathComponent("ca.sec1").path
        let enc = dir.appendingPathComponent("ca.enc").path
        let cert = dir.appendingPathComponent("ca.crt").path
        try openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", sec1])
        try openssl(["pkcs8", "-topk8", "-nocrypt", "-in", sec1, "-out", key])
        try openssl(["pkcs8", "-topk8", "-in", key, "-out", enc, "-passout", "pass:old passphrase 123"])
        try openssl(["req", "-x509", "-key", key, "-out", cert, "-days", "30", "-subj", "/CN=EC CA",
                     "-addext", "basicConstraints=critical,CA:TRUE"])
        let certPEM = try String(contentsOfFile: cert, encoding: .utf8)
        for (path, current) in [(sec1, nil), (enc, "old passphrase 123")] as [(String, String?)] {
            let pem = try String(contentsOfFile: path, encoding: .utf8)
            #expect(SigningKey.isEncrypted(pem: pem) == (current != nil))
            _ = try CertificateAuthority.prepareImport(certificatePEM: certPEM, keyPEM: pem,
                                                       currentPassphrase: current, newPassphrase: passphrase)
        }
    }
}

@Suite struct NamesTests {
    @Test func classify() throws {
        let (dns, ips) = try Names.classify(Names.tokens("Foo.Example.com, 10.0.0.1\n[::1]  foo.example.com bar"))
        #expect(dns == ["foo.example.com", "bar"])
        #expect(ips == ["10.0.0.1", "::1"])
    }

    @Test func cidr() throws {
        #expect(Names.cidrString(try Names.cidrBytes("192.168.1.77/24")) == "192.168.1.0/24")
        #expect(Names.cidrString(try Names.cidrBytes("10.0.0.0/8")) == "10.0.0.0/8")
        #expect(Names.cidrString(try Names.cidrBytes("fd00::/8")) == "fd00::/8")
        #expect(throws: CAError.self) { try Names.cidrBytes("10.0.0.0/33") }
    }
}

@Test func keyDescriptions() throws {
    #expect(CertificateAuthority.describe(try SigningKey.generate(.p384).publicKey) == "ECDSA P-384")
    #expect(CertificateAuthority.describe(try SigningKey.generate(.rsa2048).publicKey) == "RSA 2048")
}

@Suite struct UnencryptedCATests {
    @Test func issuesWithoutPassphrase() throws {
        let ca = try CertificateAuthority.generate(.init(commonName: "Plain CA", algorithm: .p256), passphrase: nil)
        #expect(!ca.isKeyEncrypted)
        #expect(ca.keyPEM.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        let bundle = try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: Date().addingTimeInterval(3600)),
                                                    material: ca, passphrase: nil)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("plain-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let caPath = dir.appendingPathComponent("ca.crt").path, leafPath = dir.appendingPathComponent("leaf.crt").path
        let keyPath = dir.appendingPathComponent("ca.key").path
        try ca.certificatePEM.write(toFile: caPath, atomically: true, encoding: .utf8)
        try bundle.certificatePEM.write(toFile: leafPath, atomically: true, encoding: .utf8)
        try ca.keyPEM.write(toFile: keyPath, atomically: true, encoding: .utf8)
        #expect(try openssl(["verify", "-CAfile", caPath, leafPath]).contains("OK"))
        try openssl(["pkey", "-in", keyPath, "-noout"])  // usable by OpenSSL as-is
    }

    @Test func encryptedCAStillNeedsPassphrase() throws {
        let ca = try CertificateAuthority.generate(.init(commonName: "Locked CA", algorithm: .p256), passphrase: passphrase)
        #expect(ca.isKeyEncrypted)
        #expect(throws: CAError.passphraseRequired) {
            try CertificateAuthority.issue(IssueRequest(names: ["a.test"], notAfter: Date().addingTimeInterval(3600)),
                                           material: ca, passphrase: nil)
        }
    }

    @Test func importCanDropOrAddPassphrase() throws {
        let encrypted = try CertificateAuthority.generate(.init(commonName: "X", algorithm: .p256), passphrase: passphrase)
        let plain = try CertificateAuthority.prepareImport(certificatePEM: encrypted.certificatePEM, keyPEM: encrypted.keyPEM,
                                                           currentPassphrase: passphrase, newPassphrase: nil)
        #expect(!plain.isKeyEncrypted)
        let again = try CertificateAuthority.prepareImport(certificatePEM: plain.certificatePEM, keyPEM: plain.keyPEM,
                                                           currentPassphrase: nil, newPassphrase: "another passphrase")
        #expect(again.isKeyEncrypted)
    }
}
