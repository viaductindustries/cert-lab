import Foundation

public enum CAError: LocalizedError, Equatable {
    case invalidPEM(String)
    case unsupportedKey(String)
    case unsupportedEncryption(String)
    case incorrectPassphrase
    case passphraseRequired
    case weakPassphrase(String)
    case invalidCertificate(String)
    case keyDoesNotMatchCertificate
    case invalidRequest(String)
    case nameConstraintViolation(String)
    case onePassword(String)
    case onePasswordNotFound
    case caMismatch(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPEM(let reason): "Invalid PEM: \(reason)"
        case .unsupportedKey(let reason): "Unsupported private key: \(reason)"
        case .unsupportedEncryption(let reason): "Unsupported key encryption: \(reason)"
        case .incorrectPassphrase: "Incorrect passphrase."
        case .passphraseRequired: "This key is protected by a passphrase. Enter it to continue."
        case .weakPassphrase(let reason): reason
        case .invalidCertificate(let reason): "Invalid certificate: \(reason)"
        case .keyDoesNotMatchCertificate: "The private key does not match the CA certificate."
        case .invalidRequest(let reason): reason
        case .nameConstraintViolation(let reason): "Not permitted by the CA's name constraints: \(reason)"
        case .onePassword(let message): "1Password: \(message)"
        case .onePasswordNotFound: "1Password CLI (op) not found. Install it with `brew install 1password-cli` and enable “Integrate with 1Password CLI” in 1Password › Settings › Developer."
        case .caMismatch(let reason): reason
        }
    }
}
