import Foundation

/// Keeps the local issuance log and the CA's 1Password vault in step.
public enum IssuanceSync {
    public struct Result: Sendable {
        public var log: [IssuedRecord]
        public var pushed = 0
        public var pulled = 0
        public var failures: [String] = []
    }

    /// Pushes this CA's records that aren't in 1Password yet, then pulls any
    /// certificates issued elsewhere (e.g. from another Mac).
    public static func sync(caFingerprint: String, vaultID: String, log: [IssuedRecord],
                            vault: any CAVault) async throws -> Result {
        var result = Result(log: log)

        for index in result.log.indices
        where result.log[index].caFingerprint == caFingerprint && result.log[index].opItemID == nil {
            do {
                result.log[index].opItemID = try await vault.saveIssued(result.log[index], vaultID: vaultID)
                result.pushed += 1
            } catch {
                result.failures.append("\(result.log[index].commonName): \(error.localizedDescription)")
            }
        }

        let known = Set(result.log.compactMap(\.opItemID))
        for itemID in try await vault.listIssuedItemIDs(vaultID: vaultID) where !known.contains(itemID) {
            do {
                let record = try await vault.loadIssued(itemID: itemID, vaultID: vaultID)
                guard record.caFingerprint == caFingerprint else { continue }
                if let index = result.log.firstIndex(where: { $0.fingerprint == record.fingerprint }) {
                    result.log[index].opItemID = itemID
                } else {
                    result.log.append(record)
                    result.pulled += 1
                }
            } catch {
                result.failures.append("item \(itemID): \(error.localizedDescription)")
            }
        }
        return result
    }
}
