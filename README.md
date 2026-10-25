# Cert Lab

A small macOS app for running a private certificate authority, with the CA kept in 1Password.

## Requirements

- macOS 14+
- [1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`brew install 1password-cli`)
- 1Password app → Settings → Developer → **Integrate with 1Password CLI** turned on

## Build

```sh
scripts/build-app.sh            # → build/Cert Lab.app
scripts/build-app.sh --install  # also copies it to /Applications
swift test                      # core tests (uses openssl for interop checks)
```

## Releases

Releases are cut by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/) on `main`:

- `fix: …` bumps the patch version and `feat: …` the minor version. `feat!: …` or a `BREAKING CHANGE:` footer bumps the major version.
- release-please keeps a release PR open that updates `CHANGELOG.md` and `version.txt`. Merging it tags the release and creates the GitHub release.
- The Release workflow then builds `Cert-Lab-<version>.zip`, plus a `.sha256` file, and attaches them to that release.

CI (`.github/workflows/ci.yml`) runs the tests and builds the app on every push and pull request.

The app is ad-hoc signed, not notarized, so macOS blocks it the first time it's opened after downloading. Either right-click the app and choose **Open**, or run:

```sh
xattr -dr com.apple.quarantine "/Applications/Cert Lab.app"
```

## How it works

- **Each CA gets its own 1Password vault** (by default called `CA: <name>`; you can choose an existing vault instead). The vault contains:
  - **The CA item**, a Secure Note tagged `cert-lab/ca`, with fields `certificate`, `private_key` (concealed, PKCS#8) and `sha256_fingerprint`.
  - **One Secure Note per issued certificate**, tagged `cert-lab/certificate`, holding the certificate, serial number, expiry date and a `record` field with the log entry as JSON. These never contain private keys.
- **Access to the vault means you can issue.** By default the CA key is stored unencrypted inside 1Password, so issuing only needs 1Password's approval. You can optionally protect a CA's key with a passphrase (PBES2: PBKDF2-SHA256 with 600k iterations, AES-256-CBC). That's only useful if you keep the passphrase *outside* the CA's vault. Either way the key is in standard format and works with `openssl`.
- **Every issuance fetches the CA from 1Password.** The app never caches the CA key or writes it to disk.
- **Leaf keys are shown once.** You can copy them (marked concealed, and cleared from the clipboard after 90 seconds) or export them (`.key` with mode 0600, `.crt`, `.fullchain.crt`, `ca.crt`). After that they're gone.
- **History syncs through the vault.** `~/Library/Application Support/Cert Lab/issued.json` is a local cache. If saving a certificate to 1Password fails, it's flagged and saved on the next **Sync**. Sync also pulls in certificates issued from other Macs. **Link CA from 1Password** sets up a CA on a new Mac, including its history.

## Defaults worth knowing

- New CAs get `pathlen:0`, so they can sign leaf certificates but not intermediates. Name constraints are optional and enforced by the app at issuance.
- Leaf certificates get SANs, `serverAuth` (plus `clientAuth` if you choose it), and SKI/AKI. The common name is the first SAN.
- The app warns about lifetimes over 825 days, because Apple devices reject those TLS certificates.
