import Foundation

/// Keeps the local issuance log and the CA's 1Password vault in step.
/// The vault is the source of truth: the local log is a cache of it plus any
/// certificates that haven't been saved there yet.
public enum IssuanceSync {
    public struct Result: Sendable {
        public var log: [IssuedRecord]
        public var pushed = 0
        public var pulled = 0
        public var removed = 0
        public var failures: [String] = []
    }

    /// 1. List the vault. Without a complete inventory nothing else is safe, so stop on failure.
    /// 2. Drop local records whose 1Password item was deleted (deletion in 1Password is how
    ///    certificates are removed from the log on every Mac).
    /// 3. Pull items not known locally; match them to unsynced local records by certificate
    ///    fingerprint, so a save that succeeded but wasn't recorded isn't pushed twice.
    /// 4. Push records that still aren't in 1Password.
    /// Progress is kept even when a step fails; failures are reported in `failures`.
    public static func sync(caFingerprint: String, vaultID: String, log: [IssuedRecord],
                            vault: any CAVault) async -> Result {
        var result = Result(log: log)

        let remoteIDs: [String]
        do {
            remoteIDs = try await vault.listIssuedItemIDs(vaultID: vaultID)
        } catch {
            result.failures.append("Couldn’t list certificates in 1Password: \(error.localizedDescription)")
            return result
        }
        let remote = Set(remoteIDs)

        let before = result.log.count
        result.log.removeAll { record in
            record.caFingerprint == caFingerprint && record.opItemID.map { !remote.contains($0) } == true
        }
        result.removed = before - result.log.count

        let known = Set(result.log.compactMap(\.opItemID))
        for itemID in remoteIDs where !known.contains(itemID) {
            do {
                let record = try await vault.loadIssued(itemID: itemID, vaultID: vaultID)
                guard record.caFingerprint == caFingerprint else { continue }
                if let index = result.log.firstIndex(where: { $0.fingerprint == record.fingerprint }) {
                    if result.log[index].opItemID == nil { result.log[index].opItemID = itemID }
                } else {
                    result.log.append(record)
                    result.pulled += 1
                }
            } catch {
                result.failures.append("Item \(itemID): \(error.localizedDescription)")
            }
        }

        for index in result.log.indices
        where result.log[index].caFingerprint == caFingerprint && result.log[index].opItemID == nil {
            do {
                result.log[index].opItemID = try await vault.saveIssued(result.log[index], vaultID: vaultID)
                result.pushed += 1
            } catch {
                result.failures.append("\(result.log[index].commonName): \(error.localizedDescription)")
            }
        }
        return result
    }

    /// Applies a sync result (computed from `snapshot`) to the log as it is *now*, so
    /// records added or changed while the sync was running aren't lost.
    public static func merge(_ result: Result, snapshot: [IssuedRecord], into current: [IssuedRecord]) -> [IssuedRecord] {
        let synced = Dictionary(result.log.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let snapshotIDs = Set(snapshot.map(\.id))
        var merged: [IssuedRecord] = []
        for record in current {
            if let updated = synced[record.id] {
                var record = record
                if record.opItemID == nil { record.opItemID = updated.opItemID }
                merged.append(record)
            } else if !snapshotIDs.contains(record.id) {
                merged.append(record)  // added during the sync
            }
            // else: removed by the sync (deleted in 1Password)
        }
        for record in result.log where !snapshotIDs.contains(record.id) {
            // pulled from 1Password
            if let index = merged.firstIndex(where: { $0.fingerprint == record.fingerprint }) {
                if merged[index].opItemID == nil { merged[index].opItemID = record.opItemID }
            } else {
                merged.append(record)
            }
        }
        return merged
    }
}
