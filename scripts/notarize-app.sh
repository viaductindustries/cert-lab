#!/bin/bash
# Sign and notarize the universal app built by build-app.sh on a GitHub-hosted runner.
set -euo pipefail
cd "$(dirname "$0")/.."

for name in RUNNER_TEMP APPLE_CERTIFICATE_BASE64 APPLE_CERTIFICATE_PASSWORD APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_PRIVATE_KEY_BASE64; do
    if [[ -z "${!name:-}" ]]; then
        echo "Missing required environment variable: $name" >&2
        exit 1
    fi
done

APP="build/Cert Lab.app"
VERSION="$(tr -d '[:space:]' < version.txt)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version.txt must contain X.Y.Z" >&2; exit 1; }
ARCHITECTURES="$(lipo -archs "$APP/Contents/MacOS/CertLab")"
for architecture in arm64 x86_64; do
    if [[ " $ARCHITECTURES " != *" $architecture "* ]]; then
        echo "Release app is missing required architecture: $architecture" >&2
        exit 1
    fi
done

# Private material exists only in a temporary directory and a dedicated keychain.
umask 077
CREDENTIAL_DIR="$(mktemp -d "$RUNNER_TEMP/cert-lab-signing.XXXXXX")"
KEYCHAIN="$CREDENTIAL_DIR/signing.keychain-db"
cleanup() {
    security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
    rm -rf "$CREDENTIAL_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
KEYCHAIN_PASSWORD="$(openssl rand -hex 32)"
printf '%s' "$APPLE_CERTIFICATE_BASE64" | base64 --decode > "$CREDENTIAL_DIR/certificate.p12"
printf '%s' "$APPLE_API_PRIVATE_KEY_BASE64" | base64 --decode > "$CREDENTIAL_DIR/AuthKey.p8"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 7200 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$CREDENTIAL_DIR/certificate.p12" -P "$APPLE_CERTIFICATE_PASSWORD" \
    -k "$KEYCHAIN" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null
# codesign also resolves identities through the user keychain search list.
# This script runs on a disposable GitHub-hosted runner.
security list-keychains -d user -s "$KEYCHAIN"

# Select exactly one valid Developer ID Application identity from the uploaded P12.
IDENTITIES="$(security find-identity -v -p codesigning "$KEYCHAIN" | sed -n '/"Developer ID Application:/s/.*) \([A-Fa-f0-9]\{40\}\) .*/\1/p')"
if [[ ! "$IDENTITIES" =~ ^[A-Fa-f0-9]{40}$ ]]; then
    echo "Upload a P12 containing exactly one valid Developer ID Application identity and its private key." >&2
    exit 1
fi
codesign --force --sign "$IDENTITIES" --keychain "$KEYCHAIN" --options runtime --timestamp "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

NOTARY_ARGS=(--key "$CREDENTIAL_DIR/AuthKey.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
ditto -c -k --sequesterRsrc --keepParent "$APP" "$CREDENTIAL_DIR/submission.zip"
mkdir -p build/notarization
# Preserve the response and Apple's diagnostic log, including rejected submissions.
SUBMIT_EXIT=0
xcrun notarytool submit "$CREDENTIAL_DIR/submission.zip" "${NOTARY_ARGS[@]}" \
    --wait --timeout 30m --output-format json > build/notarization/result.json || SUBMIT_EXIT=$?
SUBMISSION_ID="$(python3 -c 'import json; print(json.load(open("build/notarization/result.json")).get("id", ""))')"
if [[ -n "$SUBMISSION_ID" ]]; then
    echo "Notarization submission: $SUBMISSION_ID"
    xcrun notarytool log "$SUBMISSION_ID" "${NOTARY_ARGS[@]}" build/notarization/log.json || true
fi
if [[ "$SUBMIT_EXIT" -ne 0 ]]; then
    echo "Notarization failed or timed out; see the notarization artifact." >&2
    exit "$SUBMIT_EXIT"
fi
python3 - <<'PY'
import json
result = json.load(open('build/notarization/result.json'))
if result.get('status') != 'Accepted':
    raise SystemExit(f"Notarization was not accepted: {result.get('status')}. See the notarization artifact.")
PY

xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
spctl --assess --type execute --verbose=2 "$APP"

# Repackage after stapling so the download works with Gatekeeper offline too.
mkdir -p build/release
ARCHIVE="Cert-Lab-${VERSION}-universal.zip"
ditto -c -k --sequesterRsrc --keepParent "$APP" "build/release/$ARCHIVE"
(cd build/release && shasum -a 256 "$ARCHIVE" > SHA256SUMS.txt)
