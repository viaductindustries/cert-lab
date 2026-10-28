#!/bin/bash
# Builds "Cert Lab.app" into ./build (ad-hoc signed).
# Usage: scripts/build-app.sh [--install] [--universal]
#   --install  also copy the app to /Applications
#   --universal  build for both Apple Silicon and Intel
# The version comes from version.txt (maintained by Release Please); the build number from $BUILD_NUMBER or the git commit count.
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL=false
BUILD_ARGS=(-c release)
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=true ;;
        --universal) BUILD_ARGS+=(--arch arm64 --arch x86_64) ;;
        *) echo "Unknown option: $arg" >&2; exit 64 ;;
    esac
done

VERSION="$(tr -d '[:space:]' < version.txt)"
BUILD="${BUILD_NUMBER:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}"

swift build "${BUILD_ARGS[@]}"
BIN="$(swift build "${BUILD_ARGS[@]}" --show-bin-path)/CertLab"

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

if $INSTALL; then
    rm -rf "/Applications/Cert Lab.app"
    cp -R "$APP" /Applications/
    echo "Installed to /Applications/Cert Lab.app"
fi
