#!/bin/bash
# Builds "Cert Lab.app" into ./build.
# Usage: scripts/build-app.sh [--install] [--zip]
#   --install  copy the app to /Applications
#   --zip      also write build/Cert-Lab-<version>.zip and a .sha256 file
# The version comes from version.txt (maintained by release-please); the build
# number from $BUILD_NUMBER or the git commit count.
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL=false
ZIP=false
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=true ;;
        --zip) ZIP=true ;;
        *) echo "Unknown option: $arg" >&2; exit 64 ;;
    esac
done

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

codesign --force --sign - "$APP"
echo "Built $APP (version $VERSION, build $BUILD)"

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
