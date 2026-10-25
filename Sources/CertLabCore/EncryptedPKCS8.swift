import CommonCrypto
import Foundation
import SwiftASN1

/// PKCS#8 EncryptedPrivateKeyInfo using PBES2 (PBKDF2 + AES-CBC), the format
/// `openssl pkcs8 -topk8` produces by default. Keys stored in 1Password can
/// therefore be decrypted with plain OpenSSL if this app ever goes away.
public enum EncryptedPKCS8 {
    public static let pemLabel = "ENCRYPTED PRIVATE KEY"
    public static let defaultIterations = 600_000

    private static let pbes2: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 5, 13]
    private static let pbkdf2: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 5, 12]

    private static let prfs: [ASN1ObjectIdentifier: CCPseudoRandomAlgorithm] = [
        [1, 2, 840, 113549, 2, 7]: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
        [1, 2, 840, 113549, 2, 8]: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224),
        [1, 2, 840, 113549, 2, 9]: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
        [1, 2, 840, 113549, 2, 10]: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384),
        [1, 2, 840, 113549, 2, 11]: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
    ]
    private static let hmacSHA256: ASN1ObjectIdentifier = [1, 2, 840, 113549, 2, 9]
    private static let hmacSHA1: ASN1ObjectIdentifier = [1, 2, 840, 113549, 2, 7]

    private static let ciphers: [ASN1ObjectIdentifier: Int] = [
        [2, 16, 840, 1, 101, 3, 4, 1, 2]: kCCKeySizeAES128,
        [2, 16, 840, 1, 101, 3, 4, 1, 22]: kCCKeySizeAES192,
        [2, 16, 840, 1, 101, 3, 4, 1, 42]: kCCKeySizeAES256,
    ]
    private static let aes256CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 42]

    // MARK: Encrypt

    public static func encrypt(pkcs8 plaintext: Data, passphrase: String, iterations: Int = defaultIterations) throws -> PEMBlock {
        let salt = randomBytes(16)
        let iv = randomBytes(kCCBlockSizeAES128)
        let key = try deriveKey(passphrase: passphrase, salt: salt, iterations: iterations,
                                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), length: kCCKeySizeAES256)
        let ciphertext = try aesCBC(CCOperation(kCCEncrypt), key: key, iv: iv, data: plaintext)

        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { s in
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(pbes2)
                try s.appendConstructedNode(identifier: .sequence) { s in
                    try s.appendConstructedNode(identifier: .sequence) { s in
                        try s.serialize(pbkdf2)
                        try s.appendConstructedNode(identifier: .sequence) { s in
                            try s.serialize(ASN1OctetString(contentBytes: ArraySlice(salt)))
                            try s.serialize(iterations)
                            try s.appendConstructedNode(identifier: .sequence) { s in
                                try s.serialize(hmacSHA256)
                                try s.serialize(ASN1Null())
                            }
                        }
                    }
                    try s.appendConstructedNode(identifier: .sequence) { s in
                        try s.serialize(aes256CBC)
                        try s.serialize(ASN1OctetString(contentBytes: ArraySlice(iv)))
                    }
                }
            }
            try s.serialize(ASN1OctetString(contentBytes: ArraySlice(ciphertext)))
        }
        return PEMBlock(label: pemLabel, der: Data(serializer.serializedBytes))
    }

    // MARK: Decrypt

    private struct Params {
        var salt: [UInt8]
        var iterations: Int
        var keyLength: Int?
        var prf: CCPseudoRandomAlgorithm
        var cipherKeySize: Int
        var iv: [UInt8]
    }

    /// Returns the plaintext PKCS#8 PrivateKeyInfo DER.
    public static func decrypt(_ der: Data, passphrase: String) throws -> Data {
        let (params, ciphertext) = try parse(der)
        let key = try deriveKey(passphrase: passphrase, salt: params.salt, iterations: params.iterations,
                                prf: params.prf, length: params.keyLength ?? params.cipherKeySize)
        guard key.count == params.cipherKeySize else {
            throw CAError.unsupportedEncryption("key length does not match cipher")
        }
        do {
            return try aesCBC(CCOperation(kCCDecrypt), key: key, iv: params.iv, data: ciphertext)
        } catch {
            // Bad padding is the usual symptom of a wrong passphrase.
            throw CAError.incorrectPassphrase
        }
    }

    private static func parse(_ der: Data) throws -> (Params, [UInt8]) {
        let unsupportedHint = "only PBES2 with PBKDF2 and AES-CBC is supported. Convert with: openssl pkcs8 -topk8 -v2 aes-256-cbc -in key.pem"
        do {
            let root = try DER.parse(Array(der))
            return try DER.sequence(root, identifier: .sequence) { nodes in
                guard let algorithmNode = nodes.next(), let dataNode = nodes.next() else {
                    throw CAError.unsupportedEncryption("malformed EncryptedPrivateKeyInfo")
                }
                let params: Params = try DER.sequence(algorithmNode, identifier: .sequence) { alg in
                    guard try ASN1ObjectIdentifier(derEncoded: &alg) == pbes2, let pbes2Params = alg.next() else {
                        throw CAError.unsupportedEncryption(unsupportedHint)
                    }
                    return try DER.sequence(pbes2Params, identifier: .sequence) { p in
                        guard let kdfNode = p.next(), let encNode = p.next() else {
                            throw CAError.unsupportedEncryption("malformed PBES2 parameters")
                        }
                        var params: Params = try DER.sequence(kdfNode, identifier: .sequence) { kdf in
                            guard try ASN1ObjectIdentifier(derEncoded: &kdf) == pbkdf2, let kdfParams = kdf.next() else {
                                throw CAError.unsupportedEncryption(unsupportedHint)
                            }
                            return try DER.sequence(kdfParams, identifier: .sequence) { k in
                                let salt = try ASN1OctetString(derEncoded: &k)
                                let iterations = try Int(derEncoded: &k)
                                var keyLength: Int?
                                var prfOID = hmacSHA1
                                while let node = k.next() {
                                    if node.identifier == .integer {
                                        keyLength = try Int(derEncoded: node)
                                    } else if node.identifier == .sequence {
                                        prfOID = try DER.sequence(node, identifier: .sequence) { a in
                                            let oid = try ASN1ObjectIdentifier(derEncoded: &a)
                                            while a.next() != nil {}
                                            return oid
                                        }
                                    }
                                }
                                guard let prf = prfs[prfOID] else {
                                    throw CAError.unsupportedEncryption("PBKDF2 PRF \(prfOID)")
                                }
                                return Params(salt: Array(salt.bytes), iterations: iterations, keyLength: keyLength,
                                              prf: prf, cipherKeySize: 0, iv: [])
                            }
                        }
                        try DER.sequence(encNode, identifier: .sequence) { e in
                            let oid = try ASN1ObjectIdentifier(derEncoded: &e)
                            guard let keySize = ciphers[oid] else {
                                throw CAError.unsupportedEncryption("cipher \(oid); \(unsupportedHint)")
                            }
                            params.cipherKeySize = keySize
                            params.iv = Array(try ASN1OctetString(derEncoded: &e).bytes)
                        }
                        return params
                    }
                }
                return (params, Array(try ASN1OctetString(derEncoded: dataNode).bytes))
            }
        } catch let error as CAError {
            throw error
        } catch {
            throw CAError.unsupportedEncryption("could not parse encrypted key (\(error))")
        }
    }

    // MARK: CommonCrypto

    private static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return bytes
    }

    private static func deriveKey(passphrase: String, salt: [UInt8], iterations: Int,
                                  prf: CCPseudoRandomAlgorithm, length: Int) throws -> [UInt8] {
        guard iterations > 0, iterations <= 100_000_000 else {
            throw CAError.unsupportedEncryption("unreasonable PBKDF2 iteration count \(iterations)")
        }
        let password = Array(passphrase.utf8)
        var derived = [UInt8](repeating: 0, count: length)
        let status = password.withUnsafeBufferPointer { pw in
            pw.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pw.count) { pwPtr in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pwPtr, pw.count, salt, salt.count,
                                     prf, UInt32(iterations), &derived, length)
            }
        }
        guard status == kCCSuccess else { throw CAError.unsupportedEncryption("PBKDF2 failed (\(status))") }
        return derived
    }

    private static func aesCBC(_ operation: CCOperation, key: [UInt8], iv: [UInt8], data: some DataProtocol) throws -> Data {
        let input = Array(data)
        guard iv.count == kCCBlockSizeAES128 else { throw CAError.unsupportedEncryption("bad IV length") }
        var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var moved = 0
        let status = CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                             key, key.count, iv, input, input.count, &output, output.count, &moved)
        guard status == kCCSuccess else { throw CAError.incorrectPassphrase }
        return Data(output.prefix(moved))
    }
}
