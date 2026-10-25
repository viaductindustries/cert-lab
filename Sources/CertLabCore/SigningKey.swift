import Crypto
import _CryptoExtras
import Foundation
import X509

public enum KeyAlgorithm: String, Codable, CaseIterable, Identifiable, Sendable {
    case p256 = "ECDSA P-256"
    case p384 = "ECDSA P-384"
    case rsa2048 = "RSA 2048"
    case rsa3072 = "RSA 3072"
    case rsa4096 = "RSA 4096"

    public var id: String { rawValue }
    public var isRSA: Bool { self == .rsa2048 || self == .rsa3072 || self == .rsa4096 }
}

/// A private key we know how to sign with and serialise as PKCS#8.
public enum SigningKey: Sendable {
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case rsa(_RSA.Signing.PrivateKey)

    public static func generate(_ algorithm: KeyAlgorithm) throws -> SigningKey {
        switch algorithm {
        case .p256: .p256(P256.Signing.PrivateKey())
        case .p384: .p384(P384.Signing.PrivateKey())
        case .rsa2048: .rsa(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        case .rsa3072: .rsa(try _RSA.Signing.PrivateKey(keySize: .bits3072))
        case .rsa4096: .rsa(try _RSA.Signing.PrivateKey(keySize: .bits4096))
        }
    }

    /// Accepts PKCS#8, SEC1 (EC PRIVATE KEY) or PKCS#1 (RSA PRIVATE KEY) DER.
    public init(der: Data) throws {
        if let key = try? P256.Signing.PrivateKey(derRepresentation: der) {
            self = .p256(key)
        } else if let key = try? P384.Signing.PrivateKey(derRepresentation: der) {
            self = .p384(key)
        } else if let key = try? _RSA.Signing.PrivateKey(derRepresentation: der) {
            guard key.keySizeInBits >= 2048 else { throw CAError.unsupportedKey("RSA keys must be at least 2048 bits") }
            self = .rsa(key)
        } else {
            throw CAError.unsupportedKey("expected an ECDSA P-256/P-384 or RSA key")
        }
    }

    /// Parses an unencrypted or PBES2-encrypted private key from PEM text.
    public init(pem: String, passphrase: String?) throws {
        let blocks = try PEMBlock.parseAll(pem)
        guard let block = blocks.first(where: { $0.label.hasSuffix("PRIVATE KEY") }) else {
            throw CAError.invalidPEM("no PRIVATE KEY block found")
        }
        if block.headers["Proc-Type"]?.contains("ENCRYPTED") == true {
            throw CAError.unsupportedEncryption("legacy OpenSSL encryption. Convert with: openssl pkcs8 -topk8 -v2 aes-256-cbc -in key.pem")
        }
        if block.label == EncryptedPKCS8.pemLabel {
            guard let passphrase, !passphrase.isEmpty else { throw CAError.passphraseRequired }
            let plaintext = try EncryptedPKCS8.decrypt(block.der, passphrase: passphrase)
            do { try self.init(der: plaintext) } catch { throw CAError.incorrectPassphrase }
        } else {
            try self.init(der: block.der)
        }
    }

    public static func isEncrypted(pem: String) -> Bool {
        pem.contains("BEGIN \(EncryptedPKCS8.pemLabel)") || pem.contains("Proc-Type: 4,ENCRYPTED")
    }

    public var algorithm: KeyAlgorithm {
        switch self {
        case .p256: .p256
        case .p384: .p384
        case .rsa(let key):
            switch key.keySizeInBits {
            case ..<3072: .rsa2048
            case ..<4096: .rsa3072
            default: .rsa4096
            }
        }
    }

    public var certificateKey: Certificate.PrivateKey {
        switch self {
        case .p256(let key): Certificate.PrivateKey(key)
        case .p384(let key): Certificate.PrivateKey(key)
        case .rsa(let key): Certificate.PrivateKey(key)
        }
    }

    public var publicKey: Certificate.PublicKey { certificateKey.publicKey }

    public var pkcs8DER: Data {
        switch self {
        case .p256(let key): key.derRepresentation
        case .p384(let key): key.derRepresentation
        case .rsa(let key): key.pkcs8DERRepresentation
        }
    }

    public var pkcs8PEM: String { PEMBlock(label: "PRIVATE KEY", der: pkcs8DER).pemString }

    public func encryptedPEM(passphrase: String) throws -> String {
        try EncryptedPKCS8.encrypt(pkcs8: pkcs8DER, passphrase: passphrase).pemString
    }

    /// Encrypted PKCS#8 if a passphrase is given, plain PKCS#8 otherwise.
    public func storagePEM(passphrase: String?) throws -> String {
        guard let passphrase, !passphrase.isEmpty else { return pkcs8PEM }
        return try encryptedPEM(passphrase: passphrase)
    }
}
