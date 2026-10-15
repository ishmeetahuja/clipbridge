#!/bin/bash
# Builds ClipBridge.app and installs it into ~/Applications, then launches it.
set -euo pipefail
cd "$(dirname "$0")"

if ! xcrun --find swift >/dev/null 2>&1; then
  echo "Swift not found. Run:  xcode-select --install   then re-run this script."
  exit 1
fi

echo "▶ Building ClipBridge (release)…"
swift build -c release
BIN="$(swift build -c release --show-bin-path)/ClipBridge"

APP="build/ClipBridge.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/ClipBridge"
cp Info.plist "$APP/Contents/Info.plist"
codesign --force --deep -s - "$APP" >/dev/null 2>&1 || true

DEST="$HOME/Applications"
mkdir -p "$DEST"
pkill -x ClipBridge 2>/dev/null || true
sleep 0.5
rm -rf "$DEST/ClipBridge.app"
cp -R "$APP" "$DEST/"

echo "✅ Installed: $DEST/ClipBridge.app"
echo "   Look for the clipboard icon in your menu bar."
open "$DEST/ClipBridge.app"
