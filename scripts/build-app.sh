#!/bin/bash
# Builds "Cert Lab.app" into ./build.
# Usage: scripts/build-app.sh [--notarize] [--zip] [--install]
#   --notarize  notarize with Apple and staple the ticket (needs a Developer ID identity
#               and notary credentials, see below)
#   --zip       also write build/Cert-Lab-<version>.zip and a .sha256 file
#   --install   copy the app to /Applications
#
# Signing: ad-hoc by default. Set CODESIGN_IDENTITY to a "Developer ID Application: …"
# identity to sign for distribution (hardened runtime, secure timestamp).
#
# Notary credentials, either:
#   NOTARY_KEYCHAIN_PROFILE  a profile saved with `xcrun notarytool store-credentials`, or
#   NOTARY_KEY_PATH, NOTARY_KEY_ID, NOTARY_ISSUER_ID  an App Store Connect API key (.p8)
#
# The version comes from version.txt (maintained by release-please); the build
# number from $BUILD_NUMBER or the git commit count.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

INSTALL=false
ZIP=false
NOTARIZE=false
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=true ;;
        --zip) ZIP=true ;;
        --notarize) NOTARIZE=true ;;
        *) echo "Unknown option: $arg" >&2; exit 64 ;;
    esac
done

SIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
if $NOTARIZE; then
    [[ "$SIGN_IDENTITY" != "-" ]] || die "--notarize needs CODESIGN_IDENTITY set to a Developer ID Application identity"
    if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
        NOTARY_AUTH=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
    elif [[ -n "${NOTARY_KEY_PATH:-}" && -n "${NOTARY_KEY_ID:-}" && -n "${NOTARY_ISSUER_ID:-}" ]]; then
        NOTARY_AUTH=(--key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID")
    else
        die "--notarize needs NOTARY_KEYCHAIN_PROFILE, or NOTARY_KEY_PATH + NOTARY_KEY_ID + NOTARY_ISSUER_ID"
    fi
fi

VERSION="$(tr -d '[:space:]' < version.txt)"
BUILD="${BUILD_NUMBER:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}"

swift build -c release
BIN="$(swift build -c release --show-bin-path)/CertLab"

APP="build/Cert Lab.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/CertLab"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Cert Lab</string>
    <key>CFBundleDisplayName</key><string>Cert Lab</string>
    <key>CFBundleIdentifier</key><string>local.CertLab</string>
    <key>CFBundleExecutable</key><string>CertLab</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleVersion</key><string>${BUILD}</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>NSHumanReadableCopyright</key><string>Certificates for your home lab, signed by a CA kept in 1Password.</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

if [[ "$SIGN_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$APP"
    echo "Built $APP (version $VERSION, build $BUILD, ad-hoc signed)"
else
    # Hardened runtime + secure timestamp are required for notarization.
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
    codesign --verify --strict --verbose=2 "$APP"
    echo "Built $APP (version $VERSION, build $BUILD, signed by $SIGN_IDENTITY)"
fi

if $NOTARIZE; then
    SUBMISSION="build/notary-submission.zip"
    RESULT="build/notary-result.json"
    rm -f "$SUBMISSION" "$RESULT"
    ditto -c -k --keepParent "$APP" "$SUBMISSION"
    echo "Submitting to Apple's notary service (this usually takes a few minutes)…"
    xcrun notarytool submit "$SUBMISSION" "${NOTARY_AUTH[@]}" --wait --timeout 30m --output-format json > "$RESULT" || true
    STATUS="$(plutil -extract status raw -o - "$RESULT" 2>/dev/null || echo unknown)"
    if [[ "$STATUS" != "Accepted" ]]; then
        cat "$RESULT" >&2 || true
        if SUBMISSION_ID="$(plutil -extract id raw -o - "$RESULT" 2>/dev/null)"; then
            xcrun notarytool log "$SUBMISSION_ID" "${NOTARY_AUTH[@]}" >&2 || true
        fi
        die "notarization failed (status: $STATUS)"
    fi
    rm -f "$SUBMISSION"
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP"
    spctl --assess --type execute --verbose=2 "$APP"
    echo "Notarized and stapled $APP"
fi

if $ZIP; then
    ZIPFILE="build/Cert-Lab-${VERSION}.zip"
    rm -f "$ZIPFILE"
    ditto -c -k --keepParent "$APP" "$ZIPFILE"
    (cd build && shasum -a 256 "$(basename "$ZIPFILE")" > "$(basename "$ZIPFILE").sha256")
    echo "Wrote $ZIPFILE"
fi

if $INSTALL; then
    rm -rf "/Applications/Cert Lab.app"
    cp -R "$APP" /Applications/
    echo "Installed to /Applications/Cert Lab.app"
fi
