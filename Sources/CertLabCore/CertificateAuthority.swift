import Crypto
import Foundation
import SwiftASN1
import X509

/// What gets stored in 1Password: the CA certificate (plus any parent chain)
/// and the CA private key as PKCS#8, optionally encrypted with a passphrase.
public struct CAMaterial: Sendable, Equatable {
    public var certificatePEM: String
    public var keyPEM: String

    public init(certificatePEM: String, keyPEM: String) {
        self.certificatePEM = certificatePEM
        self.keyPEM = keyPEM
    }

    public var isKeyEncrypted: Bool { SigningKey.isEncrypted(pem: keyPEM) }
}

/// Public, display-only details of a CA certificate.
public struct CAInfo: Sendable, Equatable {
    public var subject: String
    public var commonName: String
    public var notBefore: Date
    public var notAfter: Date
    public var fingerprint: String
    public var keyDescription: String
    public var permittedDNS: [String]
    public var permittedIPRanges: [String]
    public var excludedDNS: [String]
    public var excludedIPRanges: [String]
    public var chainLength: Int
}

public struct IssueRequest: Sendable {
    public var names: [String]
    public var notAfter: Date
    public var keyAlgorithm: KeyAlgorithm
    public var includeClientAuth: Bool
    public var note: String

    public init(names: [String], notAfter: Date, keyAlgorithm: KeyAlgorithm = .p256,
                includeClientAuth: Bool = false, note: String = "") {
        self.names = names
        self.notAfter = notAfter
        self.keyAlgorithm = keyAlgorithm
        self.includeClientAuth = includeClientAuth
        self.note = note
    }
}

public struct IssuedRecord: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: UUID
    public var caFingerprint: String
    public var serialNumber: String
    public var fingerprint: String
    public var commonName: String
    public var dnsNames: [String]
    public var ipAddresses: [String]
    public var keyAlgorithm: KeyAlgorithm
    public var includeClientAuth: Bool
    public var notBefore: Date
    public var notAfter: Date
    public var issuedAt: Date
    public var note: String
    public var certificatePEM: String
    /// The 1Password item holding this certificate; nil until it's been saved there.
    public var opItemID: String?

    public var sans: [String] { dnsNames + ipAddresses }
}

/// The result of issuing a certificate. The private key exists only in this
/// value; nothing else in the app retains it.
public struct IssuedBundle: Sendable {
    public var privateKeyPEM: String
    public var certificatePEM: String
    /// The CA certificate(s), without the leaf.
    public var chainPEM: String
    public var record: IssuedRecord

    public var fullChainPEM: String { certificatePEM + chainPEM }
}

public enum CertificateAuthority {
    public static let minimumPassphraseLength = 12
    /// Certificates start this long before "now" to tolerate clock skew.
    public static let backdate: TimeInterval = 300
    /// Apple platforms reject TLS server certificates valid for longer than this.
    public static let appleMaximumValidityDays = 825

    // MARK: Create / import

    public struct NewCAParameters: Sendable {
        public var commonName: String
        public var organization: String
        public var algorithm: KeyAlgorithm
        public var validityYears: Int
        public var permittedDNS: [String]
        public var permittedIPRanges: [String]

        public init(commonName: String, organization: String = "", algorithm: KeyAlgorithm = .p384,
                    validityYears: Int = 10, permittedDNS: [String] = [], permittedIPRanges: [String] = []) {
            self.commonName = commonName
            self.organization = organization
            self.algorithm = algorithm
            self.validityYears = validityYears
            self.permittedDNS = permittedDNS
            self.permittedIPRanges = permittedIPRanges
        }
    }

    public static func validate(passphrase: String, confirmation: String) throws {
        guard passphrase.count >= minimumPassphraseLength else {
            throw CAError.weakPassphrase("Passphrase must be at least \(minimumPassphraseLength) characters.")
        }
        guard passphrase == confirmation else { throw CAError.weakPassphrase("Passphrases don’t match.") }
    }

    /// With a nil passphrase the key is stored unencrypted, relying on 1Password's own protection.
    public static func generate(_ params: NewCAParameters, passphrase: String?, now: Date = Date()) throws -> CAMaterial {
        let commonName = params.commonName.trimmingCharacters(in: .whitespaces)
        guard !commonName.isEmpty else { throw CAError.invalidRequest("A common name is required.") }
        guard (1...30).contains(params.validityYears) else { throw CAError.invalidRequest("Validity must be 1–30 years.") }

        let permittedDNS = try params.permittedDNS.map { entry -> String in
            let name = entry.lowercased().trimmingCharacters(in: .whitespaces)
            let bare = name.hasPrefix(".") ? String(name.dropFirst()) : name
            guard Names.isValidHostname(bare), !bare.contains("*") else {
                throw CAError.invalidRequest("“\(entry)” is not a valid domain constraint.")
            }
            return name
        }
        let permittedIPs = try params.permittedIPRanges.map { ASN1OctetString(contentBytes: ArraySlice(try Names.cidrBytes($0))) }

        let key = try SigningKey.generate(params.algorithm)
        let organization = params.organization.trimmingCharacters(in: .whitespaces)
        let subject = try DistinguishedName {
            CommonName(commonName)
            if !organization.isEmpty { OrganizationName(organization) }
        }
        let notAfter = Calendar(identifier: .gregorian).date(byAdding: .year, value: params.validityYears, to: now)!

        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
            Critical(KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true))
            SubjectKeyIdentifier(hash: key.publicKey)
            if !permittedDNS.isEmpty || !permittedIPs.isEmpty {
                Critical(NameConstraints(permittedDNSDomains: permittedDNS, permittedIPRanges: permittedIPs))
            }
        }

        let certificate = try Certificate(
            version: .v3,
            serialNumber: randomSerial(),
            publicKey: key.publicKey,
            notValidBefore: now.addingTimeInterval(-backdate),
            notValidAfter: notAfter,
            issuer: subject,
            subject: subject,
            extensions: extensions,
            issuerPrivateKey: key.certificateKey
        )
        return CAMaterial(certificatePEM: try certificate.serializeAsPEM().pemString + "\n",
                          keyPEM: try key.storagePEM(passphrase: passphrase))
    }

    /// Validates an existing CA certificate + key, storing the key encrypted with
    /// `newPassphrase` or unencrypted if it's nil.
    public static func prepareImport(certificatePEM: String, keyPEM: String, currentPassphrase: String?,
                                     newPassphrase: String?) throws -> CAMaterial {
        let chain = try certificates(fromPEM: certificatePEM)
        let key = try SigningKey(pem: keyPEM, passphrase: currentPassphrase)
        let ca = chain[0]
        guard case .isCertificateAuthority = try ca.extensions.basicConstraints else {
            throw CAError.invalidCertificate("the certificate is not a CA (basicConstraints CA:TRUE missing).")
        }
        if let usage = try ca.extensions.keyUsage, !usage.keyCertSign {
            throw CAError.invalidCertificate("the certificate's key usage does not allow certificate signing.")
        }
        guard key.publicKey == ca.publicKey else { throw CAError.keyDoesNotMatchCertificate }
        try validateChain(chain)
        return CAMaterial(certificatePEM: chain.map { (try? $0.serializeAsPEM().pemString) ?? "" }.joined(),
                          keyPEM: try key.storagePEM(passphrase: newPassphrase))
    }

    // MARK: Issue

    public static func issue(_ request: IssueRequest, material: CAMaterial, passphrase: String?,
                             now: Date = Date()) throws -> IssuedBundle {
        let chain = try certificates(fromPEM: material.certificatePEM)
        let ca = chain[0]
        let caKey = try SigningKey(pem: material.keyPEM, passphrase: passphrase)
        guard caKey.publicKey == ca.publicKey else { throw CAError.keyDoesNotMatchCertificate }

        try validateChain(chain)
        let (dns, ips) = try validate(names: request.names, chain: chain)
        // The leaf can't be valid outside any certificate in its chain.
        let chainNotBefore = chain.map(\.notValidBefore).max()!
        let chainNotAfter = chain.map(\.notValidAfter).min()!
        guard request.notAfter > now else { throw CAError.invalidRequest("Expiry must be in the future.") }
        guard chainNotAfter > now else { throw CAError.invalidRequest("The CA certificate has expired.") }
        guard chainNotBefore <= now else {
            throw CAError.invalidRequest("The CA certificate isn’t valid until \(chainNotBefore.formatted(date: .abbreviated, time: .shortened)).")
        }
        guard request.notAfter <= chainNotAfter else {
            throw CAError.invalidRequest("Expiry can’t be later than the CA’s own expiry (\(chainNotAfter.formatted(date: .abbreviated, time: .omitted))).")
        }
        let leafKey = try SigningKey.generate(request.keyAlgorithm)
        let commonName = Names.commonName(for: request.names) ?? dns.first ?? ips[0]
        let generalNames = dns.map { GeneralName.dnsName($0) }
            + ips.map { GeneralName.ipAddress(ASN1OctetString(contentBytes: ArraySlice(Names.ipBytes($0)!))) }
        let authorityKeyID = try ca.extensions.subjectKeyIdentifier?.keyIdentifier
            ?? SubjectKeyIdentifier(hash: ca.publicKey).keyIdentifier
        let usages: [ExtendedKeyUsage.Usage] = request.includeClientAuth ? [.serverAuth, .clientAuth] : [.serverAuth]

        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: true, keyEncipherment: request.keyAlgorithm.isRSA))
            try ExtendedKeyUsage(usages)
            SubjectKeyIdentifier(hash: leafKey.publicKey)
            AuthorityKeyIdentifier(keyIdentifier: authorityKeyID)
            SubjectAlternativeNames(generalNames)
        }

        let notBefore = max(now.addingTimeInterval(-backdate), chainNotBefore)
        guard notBefore < request.notAfter else { throw CAError.invalidRequest("Expiry must be after the start date.") }
        let serial = randomSerial()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: serial,
            publicKey: leafKey.publicKey,
            notValidBefore: notBefore,
            notValidAfter: request.notAfter,
            issuer: ca.subject,
            subject: try DistinguishedName { CommonName(commonName) },
            extensions: extensions,
            issuerPrivateKey: caKey.certificateKey
        )

        let certificatePEM = try certificate.serializeAsPEM().pemString + "\n"
        let record = IssuedRecord(
            id: UUID(),
            caFingerprint: try fingerprint(ca),
            serialNumber: serial.bytes.map { String(format: "%02X", $0) }.joined(),
            fingerprint: try fingerprint(certificate),
            commonName: commonName,
            dnsNames: dns,
            ipAddresses: ips,
            keyAlgorithm: request.keyAlgorithm,
            includeClientAuth: request.includeClientAuth,
            notBefore: certificate.notValidBefore,
            notAfter: certificate.notValidAfter,
            issuedAt: now,
            note: request.note.trimmingCharacters(in: .whitespacesAndNewlines),
            certificatePEM: certificatePEM,
            opItemID: nil
        )
        return IssuedBundle(
            privateKeyPEM: leafKey.pkcs8PEM,
            certificatePEM: certificatePEM,
            chainPEM: try chain.map { try $0.serializeAsPEM().pemString + "\n" }.joined(),
            record: record
        )
    }

    /// Classifies SAN input and checks it against the name constraints of every
    /// certificate in the CA's chain.
    public static func validate(names: [String], certificatePEM: String) throws -> (dns: [String], ips: [String]) {
        try validate(names: names, chain: certificates(fromPEM: certificatePEM))
    }

    static func validate(names: [String], chain: [Certificate]) throws -> (dns: [String], ips: [String]) {
        let (dns, ips) = try Names.classify(names)
        guard !dns.isEmpty || !ips.isEmpty else { throw CAError.invalidRequest("Add at least one hostname or IP address.") }
        for certificate in chain {
            if let constraints = try certificate.extensions.nameConstraints {
                try Names.check(dns: dns, ips: ips, against: constraints)
            }
        }
        return (dns, ips)
    }

    /// Each certificate after the first must be a CA that issued (and signed) the one before it.
    static func validateChain(_ chain: [Certificate]) throws {
        for (child, parent) in zip(chain, chain.dropFirst()) {
            guard child.issuer == parent.subject,
                  parent.publicKey.isValidSignature(child.signature, for: child) else {
                throw CAError.invalidCertificate("the chain is out of order: “\(parent.subject)” didn’t sign “\(child.subject)”. List the CA certificate first, then each issuer in turn.")
            }
            guard case .isCertificateAuthority = try parent.extensions.basicConstraints else {
                throw CAError.invalidCertificate("“\(parent.subject)” in the chain is not a CA.")
            }
        }
    }

    /// A positive serial of at most 20 DER octets (RFC 5280 §4.1.2.2): 20 random bytes
    /// with the top bit cleared (no sign octet needed) and the next bit set (no leading zero).
    static func randomSerial() -> Certificate.SerialNumber {
        var generator = SystemRandomNumberGenerator()
        var bytes = (0..<20).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        bytes[0] = (bytes[0] & 0x7F) | 0x40
        return Certificate.SerialNumber(bytes: bytes)
    }

    // MARK: Inspection

    public static func certificates(fromPEM pem: String) throws -> [Certificate] {
        let blocks = try PEMBlock.parseAll(pem).filter { $0.label == "CERTIFICATE" }
        guard !blocks.isEmpty else { throw CAError.invalidPEM("no CERTIFICATE block found") }
        return try blocks.map { block in
            do { return try Certificate(derEncoded: Array(block.der)) } catch {
                throw CAError.invalidCertificate("could not parse certificate (\(error))")
            }
        }
    }

    public static func fingerprint(_ certificate: Certificate) throws -> String {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return SHA256.hash(data: serializer.serializedBytes).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    /// "P384.PublicKey" → "ECDSA P-384", "RSA4096.PublicKey" → "RSA 4096"
    static func describe(_ key: Certificate.PublicKey) -> String {
        let raw = String(describing: key).replacingOccurrences(of: ".PublicKey", with: "")
        if raw.hasPrefix("RSA") { return "RSA " + raw.dropFirst(3) }
        if raw.hasPrefix("P"), raw.count == 4 { return "ECDSA P-" + raw.dropFirst() }
        return raw
    }

    public static func info(certificatePEM: String) throws -> CAInfo {
        let chain = try certificates(fromPEM: certificatePEM)
        let ca = chain[0]
        let constraints = try ca.extensions.nameConstraints
        let commonName = ca.subject.flatMap { $0 }
            .first { $0.type == .RDNAttributeType.commonName }
            .map { String(describing: $0.value) } ?? ca.subject.description
        return CAInfo(
            subject: ca.subject.description,
            commonName: commonName,
            notBefore: ca.notValidBefore,
            notAfter: ca.notValidAfter,
            fingerprint: try fingerprint(ca),
            keyDescription: describe(ca.publicKey),
            permittedDNS: constraints.map { Array($0.permittedDNSDomains) } ?? [],
            permittedIPRanges: constraints?.permittedIPRanges.map { Names.cidrString($0.bytes) } ?? [],
            excludedDNS: constraints.map { Array($0.excludedDNSDomains) } ?? [],
            excludedIPRanges: constraints?.excludedIPRanges.map { Names.cidrString($0.bytes) } ?? [],
            chainLength: chain.count
        )
    }
}
