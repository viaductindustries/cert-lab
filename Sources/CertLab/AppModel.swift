import CertLabCore
import Foundation
import Observation

enum Sheet: Identifiable {
    case newCA
    case importCA
    case linkCA
    case issue(CARecord, prefill: IssuedRecord?)
    case certificate(IssuedRecord)

    var id: String {
        switch self {
        case .newCA: "new"
        case .importCA: "import"
        case .linkCA: "link"
        case .issue(let ca, _): "issue-\(ca.id)"
        case .certificate(let record): "cert-\(record.id)"
        }
    }
}

/// Where a new or imported CA should live in 1Password.
enum VaultDestination: Sendable {
    case new(name: String)
    case existing(id: String)
}

@Observable @MainActor
final class AppModel {
    private(set) var authorities: [CARecord] = []
    private(set) var log: [IssuedRecord] = []
    var selection: CARecord.ID?
    var sheet: Sheet?
    var alert: String?
    var pendingRemoval: CARecord?
    private(set) var syncing: Set<CARecord.ID> = []
    private(set) var syncStatus: [CARecord.ID: SyncStatus] = [:]

    struct SyncStatus {
        var message: String
        var date: Date
        var failed: Bool
    }

    var opPathOverride: String = UserDefaults.standard.string(forKey: "opPath") ?? "" {
        didSet { UserDefaults.standard.set(opPathOverride, forKey: "opPath") }
    }
    var opAccount: String = UserDefaults.standard.string(forKey: "opAccount") ?? "" {
        didSet { UserDefaults.standard.set(opAccount, forKey: "opAccount") }
    }
    var lastVaultID: String = UserDefaults.standard.string(forKey: "lastVaultID") ?? "" {
        didSet { UserDefaults.standard.set(lastVaultID, forKey: "lastVaultID") }
    }

    @ObservationIgnored private let store = LocalStore()
    @ObservationIgnored private var infoCache: [String: CAInfo] = [:]

    init() {
        do {
            authorities = try store.loadAuthorities()
            log = try store.loadLog()
        } catch {
            alert = "Couldn’t read saved data from \(store.directory.path): \(error.localizedDescription)"
        }
        selection = authorities.first?.id
    }

    var selectedCA: CARecord? { authorities.first { $0.id == selection } }

    /// Parsed details of a CA's certificate (cached; certificates don't change).
    func info(_ ca: CARecord) -> CAInfo? {
        if let cached = infoCache[ca.fingerprint] { return cached }
        let info = try? CertificateAuthority.info(certificatePEM: ca.certificatePEM)
        infoCache[ca.fingerprint] = info
        return info
    }

    var detectedOPPath: String? { OnePasswordCLI.locate(override: opPathOverride) }

    func vault() throws -> any CAVault {
        guard let path = detectedOPPath else { throw CAError.onePasswordNotFound }
        return OnePasswordCLI(executablePath: path, account: opAccount)
    }

    func entries(for ca: CARecord) -> [IssuedRecord] {
        log.filter { $0.caFingerprint == ca.fingerprint }.sorted { $0.issuedAt > $1.issuedAt }
    }

    // MARK: CA lifecycle

    func listVaults() async throws -> [OPVault] { try await vault().listVaults() }

    func createCA(_ params: CertificateAuthority.NewCAParameters, passphrase: String?,
                  destination: VaultDestination) async throws {
        let material = try await Task.detached { try CertificateAuthority.generate(params, passphrase: passphrase) }.value
        try await store(material, title: "CA: \(params.commonName)", destination: destination)
    }

    func importCA(certificatePEM: String, keyPEM: String, currentPassphrase: String?, newPassphrase: String?,
                  title: String, destination: VaultDestination) async throws {
        let material = try await Task.detached {
            try CertificateAuthority.prepareImport(certificatePEM: certificatePEM, keyPEM: keyPEM,
                                                   currentPassphrase: currentPassphrase, newPassphrase: newPassphrase)
        }.value
        try await store(material, title: title, destination: destination)
    }

    private func store(_ material: CAMaterial, title: String, destination: VaultDestination) async throws {
        let info = try CertificateAuthority.info(certificatePEM: material.certificatePEM)
        try ensureNotAdded(info.fingerprint)
        let vault = try vault()
        let vaultID: String
        switch destination {
        case .new(let name):
            vaultID = try await vault.createVault(name: name).id
        case .existing(let id):
            vaultID = id
            lastVaultID = id
        }
        let ref = try await vault.save(material, title: title, fingerprint: info.fingerprint, vaultID: vaultID)
        add(CARecord(name: info.commonName, item: ref, certificatePEM: material.certificatePEM,
                     fingerprint: info.fingerprint, keyEncrypted: material.isKeyEncrypted))
    }

    /// Links a CA from 1Password and pulls its issuance history.
    func link(_ ref: OPItemRef) async throws {
        let material = try await vault().load(ref)
        let info = try CertificateAuthority.info(certificatePEM: material.certificatePEM)
        try ensureNotAdded(info.fingerprint)
        let record = CARecord(name: info.commonName, item: ref, certificatePEM: material.certificatePEM,
                              fingerprint: info.fingerprint, keyEncrypted: material.isKeyEncrypted)
        add(record)
        _ = try await sync(record)
    }

    // MARK: Sync

    /// Saves unsynced certificates to the CA's vault and pulls ones issued elsewhere.
    /// Returns a short human-readable summary.
    func sync(_ ca: CARecord) async throws -> String {
        let result = try await IssuanceSync.sync(caFingerprint: ca.fingerprint, vaultID: ca.item.vaultID,
                                                 log: log, vault: vault())
        log = result.log
        persistLog()
        var parts: [String] = []
        if result.pushed > 0 { parts.append("saved \(result.pushed) to 1Password") }
        if result.pulled > 0 { parts.append("found \(result.pulled) new") }
        if !result.failures.isEmpty {
            throw CAError.onePassword("sync incomplete. " + result.failures.joined(separator: "; "))
        }
        return parts.isEmpty ? "Up to date" : parts.joined(separator: ", ").capitalizedFirst
    }

    /// Runs a sync in the background, recording the outcome for display.
    func startSync(_ ca: CARecord) {
        guard !syncing.contains(ca.id) else { return }
        syncing.insert(ca.id)
        Task {
            defer { syncing.remove(ca.id) }
            do {
                syncStatus[ca.id] = SyncStatus(message: try await sync(ca), date: Date(), failed: false)
            } catch {
                syncStatus[ca.id] = SyncStatus(message: error.localizedDescription, date: Date(), failed: true)
            }
        }
    }

    /// Asks where to save the CA certificate (for installing on devices that should trust it).
    func exportCACertificate(_ ca: CARecord) {
        let name = FileExport.baseName(for: info(ca)?.commonName ?? ca.name) + ".crt"
        do { try FileExport.save(ca.certificatePEM, suggestedName: name) } catch { alert = error.localizedDescription }
    }

    func unsyncedCount(for ca: CARecord) -> Int {
        entries(for: ca).filter { $0.opItemID == nil }.count
    }

    func remove(_ ca: CARecord) {
        authorities.removeAll { $0.id == ca.id }
        if selection == ca.id { selection = authorities.first?.id }
        persistAuthorities()
    }

    func rename(_ ca: CARecord, to name: String) {
        guard let index = authorities.firstIndex(where: { $0.id == ca.id }), !name.isEmpty else { return }
        authorities[index].name = name
        persistAuthorities()
    }

    private func ensureNotAdded(_ fingerprint: String) throws {
        if let existing = authorities.first(where: { $0.fingerprint == fingerprint }) {
            throw CAError.invalidRequest("This CA is already in Cert Lab as “\(existing.name)”.")
        }
    }

    private func add(_ record: CARecord) {
        authorities.append(record)
        selection = record.id
        persistAuthorities()
    }

    private func persistAuthorities() {
        do { try store.saveAuthorities(authorities) } catch { alert = "Couldn’t save: \(error.localizedDescription)" }
    }

    private func persistLog() {
        do { try store.saveLog(log) } catch { alert = "Couldn’t save the issuance log: \(error.localizedDescription)" }
    }

    // MARK: Issuing

    struct IssueResult {
        var bundle: IssuedBundle
        /// Set if the certificate couldn't be saved to 1Password (it's kept locally and retried on Sync).
        var warning: String?
    }

    /// Always fetches the CA from 1Password: no 1Password, no certificate.
    func issue(_ request: IssueRequest, ca: CARecord, passphrase: String?) async throws -> IssueResult {
        let vault = try vault()
        let material = try await vault.load(ca.item)
        let info = try CertificateAuthority.info(certificatePEM: material.certificatePEM)
        guard info.fingerprint == ca.fingerprint else {
            throw CAError.caMismatch("The CA certificate in 1Password (“\(ca.item.title)”) no longer matches this CA. Remove and re-link it.")
        }
        if material.isKeyEncrypted != ca.keyEncrypted, let index = authorities.firstIndex(where: { $0.id == ca.id }) {
            // The key's protection was changed in 1Password; follow it.
            authorities[index].keyEncrypted = material.isKeyEncrypted
            persistAuthorities()
        }
        let bundle = try await Task.detached {
            try CertificateAuthority.issue(request, material: material, passphrase: passphrase)
        }.value

        var record = bundle.record
        var warning: String?
        do {
            record.opItemID = try await vault.saveIssued(record, vaultID: ca.item.vaultID)
        } catch {
            warning = "Not yet saved to 1Password (\(error.localizedDescription)). It’s in the local log and will be saved on the next Sync."
        }
        log.append(record)
        persistLog()
        return IssueResult(bundle: bundle, warning: warning)
    }
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
