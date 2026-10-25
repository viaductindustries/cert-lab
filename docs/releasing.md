# Releasing Cert Lab

## How a release happens

1. Commit to `main` using [Conventional Commits](https://www.conventionalcommits.org/).
2. release-please keeps a release PR open that bumps `version.txt` and `CHANGELOG.md`.
3. Merging that PR tags `vX.Y.Z` and creates the GitHub release.
4. The **Release** workflow then:
   - runs the tests
   - builds the app
   - signs it with Developer ID and notarizes it, if the secrets below are set
   - attaches `Cert-Lab-X.Y.Z.zip` and its `.sha256` file to the release

If the signing secrets are missing, the release still happens. The app is ad-hoc signed and the workflow logs a warning.

## Repository secrets for signing and notarization

| Secret | What it is |
|---|---|
| `MACOS_CERTIFICATE_P12` | Your **Developer ID Application** certificate *and its private key*, exported from Keychain Access as a `.p12`, base64-encoded |
| `MACOS_CERTIFICATE_PASSWORD` | The password you set when exporting the `.p12` |
| `APPLE_API_KEY_P8` | The contents of an App Store Connect API key file (`AuthKey_XXXXXXXXXX.p8`) |
| `APPLE_API_KEY_ID` | That key's ID (the `XXXXXXXXXX` in the file name) |
| `APPLE_API_ISSUER_ID` | The issuer ID shown above the key list in App Store Connect |

### Setting them up

1. **Export the certificate.** In Keychain Access, open *login › My Certificates* and find "Developer ID Application: Viaduct Industries Limited (CP6L5J2ZTS)". Right-click it, choose *Export…*, save it as `.p12` and set a password.
2. **Create an API key.** In [App Store Connect](https://appstoreconnect.apple.com/access/integrations/api), go to *Users and Access › Integrations › Team Keys* and create a key with the **Developer** role. Download the `.p8`; Apple only lets you download it once.
3. **Store the secrets** with the GitHub CLI. Values are read from files or prompts, so they never appear in your shell history:

   ```sh
   REPO=viaductindustries/cert-lab
   base64 -i DeveloperID.p12 | gh secret set MACOS_CERTIFICATE_P12 -R $REPO
   gh secret set MACOS_CERTIFICATE_PASSWORD -R $REPO          # prompts for the value
   gh secret set APPLE_API_KEY_P8 -R $REPO < AuthKey_XXXXXXXXXX.p8
   gh secret set APPLE_API_KEY_ID -R $REPO                    # prompts
   gh secret set APPLE_API_ISSUER_ID -R $REPO                 # prompts
   ```

4. Delete the exported `.p12` afterwards.

The workflow imports the certificate into a temporary keychain that's deleted when the job finishes, whether it succeeds or fails.

## Signing and notarizing locally

```sh
# One-off: save notary credentials in your keychain
xcrun notarytool store-credentials cert-lab \
  --key AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-id>

# Build, sign, notarize, staple and zip
CODESIGN_IDENTITY="Developer ID Application: Viaduct Industries Limited (CP6L5J2ZTS)" \
NOTARY_KEYCHAIN_PROFILE=cert-lab \
scripts/build-app.sh --notarize --zip
```

Without `--notarize`, setting `CODESIGN_IDENTITY` still gives a hardened-runtime Developer ID signature, which is useful for checking the signing step on its own. Gatekeeper rejects that build as "Unnotarized Developer ID" until it's notarized.
