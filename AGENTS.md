# Agent guidance for Cert Lab

Cert Lab is a small macOS app that runs private certificate authorities for home labs, with each CA stored in 1Password. Read this before changing anything; it records decisions that aren't obvious from the code.

## Ground rules

- **Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/).**
  - `feat:` user-visible feature, `fix:` bug fix, `perf:` performance.
  - `refactor:`, `docs:`, `test:`, `ci:`, `build:`, `chore:` for everything else.
  - Breaking changes: `feat!:` / `fix!:` or a `BREAKING CHANGE:` footer.
  - Use a scope when it helps, e.g. `fix(sync): …`, `feat(ui): …`. Write the subject in the imperative mood, lower case, with no trailing full stop.
- **There are no releases for now.** People install by building from source (see README). Don't add release tooling, signing or notarization unless asked. `version.txt` is the app version, edited by hand.
- **Don't push, tag or change GitHub settings unless asked.** The remote is `viaductindustries/cert-lab` (public).
- Run `swift test` before committing. Tests must never touch a real 1Password account.

## Project layout

- Swift Package Manager only; there's no Xcode project. The app needs macOS 14 or later.
  - `Sources/CertLabCore`: all crypto, 1Password and storage logic, with no UI. Anything testable goes here.
  - `Sources/CertLab`: the SwiftUI app. `AppModel` is the single `@Observable` store, and the views are thin.
  - `Tests/CertLabCoreTests`: Swift Testing (`@Test`), not XCTest.
- `scripts/build-app.sh [--install]` bundles `build/Cert Lab.app`. It takes the version from `version.txt` and the build number from `$BUILD_NUMBER` or the git commit count.
- `scripts/make-icon.swift` regenerates `Resources/AppIcon.icns`.
- CI is `.github/workflows/ci.yml`: tests and an app build on every push and PR.

## Product decisions

- **Name:** "Cert Lab". We avoided names like "1CertLab" that suggest the app is an official 1Password product.
- **1Password access is only through the `op` CLI**, which is run as a subprocess and relies on 1Password's desktop app integration to approve access. There's no SDK and no service accounts.
- **Each CA lives in its own 1Password vault.** Vault access is the security boundary: anyone who can read the vault can issue certificates.
  - New vaults and CA items are both named `CA: <common name>` by default. Users can pick an existing vault instead.
  - The vault holds the CA item and one Secure Note per issued certificate. It never holds a leaf private key.
- **The CA passphrase is optional and off by default.** It only adds security if it's kept *outside* the CA's vault, and the UI says so. When it's on, the key is stored as encrypted PKCS#8 (PBES2, PBKDF2-SHA256 with 600k iterations, AES-256-CBC), which OpenSSL can read. When it's off, the key is plain PKCS#8 in a concealed field.
- **Every issuance loads the CA from 1Password.** The CA key is never cached in memory between issuances and never written to disk.
- **Leaf private keys are shown exactly once.** They aren't saved locally, in 1Password or in the log.
  - Copying only works through the Copy button, because the key text isn't selectable. That marks the clipboard entry as concealed, and clears it after 90 seconds or when the app quits.
  - Exported `.key` files are written with `PrivateFile.write`, which creates them as `0600` before writing any bytes.
  - While a certificate is being issued, the sheet can't be cancelled and menu commands can't replace it. Closing the result without saving the key needs confirmation.
- **Imported chains:** the CA certificate comes first, followed by each issuer in turn. The order and signatures are checked. Name constraints and validity from *every* certificate in the chain apply when issuing.
- **Certificate defaults:**
  - CAs get `pathLen 0` and optional name constraints. Name constraints are also enforced in the app before signing.
  - Leaf certificates get SANs and `serverAuth` (plus `clientAuth` when asked), SKI/AKI, and a common name equal to the first entry typed, whether it's a hostname or an IP.
  - Serials are 20 random octets with the top bit clear (`randomSerial`), the RFC 5280 maximum. Don't use `Certificate.SerialNumber()`, which can produce 21.
  - Wildcards are checked against excluded subtrees by overlap, not just containment.
  - The app warns about leaf lifetimes over 825 days, because Apple devices reject them.
- **The scope is deliberately small.** No revocation (CRL/OCSP), no ACME and no intermediate-CA creation. Discuss before adding any of them.

## 1Password storage format: treat it as a public API

Existing users' data depends on these names, so don't rename them without a migration.

| Thing | Value |
|---|---|
| CA item | Secure Note, tag `cert-lab/ca`, fields `certificate`, `private_key` (CONCEALED), `sha256_fingerprint` |
| Issued certificate item | Secure Note, tag `cert-lab/certificate`, fields `certificate`, `serial`, `expires`, `record` (JSON `IssuedRecord`) |
| Legacy tags (still read) | `ca-manager`, `ca-manager-cert`, from when the app was called "CA Manager" |

- Look up fields by `id` **or** `label`, because `op` may reassign IDs.
- Parse PEM tolerantly (ignore whitespace), because 1Password text fields can lose line breaks.
- New fields on `IssuedRecord` or `CARecord` must be optional, or decode with a default, so older JSON still loads.

## Local data

- Data lives in `~/Library/Application Support/Cert Lab/`, which is moved automatically from the old `CA Manager/` folder:
  - `authorities.json`: linked CAs (public certificate and 1Password reference only)
  - `issued.json`: a cache of the issuance log
- An `IssuedRecord` with `opItemID == nil` hasn't reached 1Password yet. **Sync** (`IssuanceSync`) works in this order:
  1. List the vault. If listing fails, stop without changing anything.
  2. Drop local records whose item was deleted in 1Password. Deleting the item is how a certificate is removed from the log on every Mac.
  3. Pull unknown items, matching them to unsynced local records by certificate fingerprint so nothing is pushed twice.
  4. Push what's still pending.
- Sync results are **merged** into the current log (`IssuanceSync.merge`), never assigned over it, because issuing or another sync can change the log while a sync is awaiting `op`.
- Local JSON that can't be decoded is moved aside to `*.unreadable-<timestamp>.json`, never overwritten.
- `CERT_LAB_DATA_DIR` points the app at a different data folder, e.g. for demo data. Passing `-opPath /path/to/op` as a launch argument overrides the `op` binary.

## Testing

- `swift test` covers the crypto, which is checked against OpenSSL (Homebrew `openssl` if present, otherwise `/usr/bin/openssl`). It also covers the `op` integration, using a fake `op` written in Python (`OnePasswordCLITests.fakeOp`) that mimics the CLI's JSON output.
- `ReviewRegressionTests.swift` pins the fixes from the first code review. Keep it passing.
- The `op` wrapper ignores SIGPIPE and reads stdout and stderr while it writes stdin. Otherwise an `op` that exits early would kill the app, along with any unsaved key.
- If you change how `op` is called, update the fake to match the real CLI's behaviour. Verify real `op` behaviour with `--help` or by asking the user. Never run commands that create or change items in their vaults.
- To check UI changes, run the app with demo data (`CERT_LAB_DATA_DIR` plus a fake `op` via `-opPath`). Screen recording may not be available, so a temporary in-app snapshot is fine. Remove it before committing.

## UI conventions

- Every sheet uses `SheetHeader` at the top and `SheetFooter` at the bottom, with a grouped `Form` in between.
- Use `Chip` and `FlowLayout` for facts and parsed names, `StatusBadge` and `ExpiryStatus` for validity, and `CopyButton` for anything copyable.
- Copy is short and plain. Explain security consequences in footers rather than in alerts.
- Don't show errors in an alert while a sheet is open. Show them inline in the sheet footer (`ErrorText`).

## Distribution

- There are no binary releases. Users clone the repo and run `scripts/build-app.sh --install`, which builds an ad-hoc-signed app for their own Mac. That's why there's no quarantine prompt and no notarization.
- The app isn't sandboxed and has no entitlements; it only needs to run `op`.
- Binary releases were tried and removed. Doing them properly needs Developer ID signing with the hardened runtime and notarization (the Viaduct Industries Developer ID is available on the maintainer's Mac). Discuss with the maintainer before reintroducing them.
