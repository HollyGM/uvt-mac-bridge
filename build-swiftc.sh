#!/bin/bash
# Compila o UVTMacBridge.app só com as Command Line Tools (sem Xcode) e o registra no macOS.
set -euo pipefail
cd "$(dirname "$0")"

APP="$PWD/build/UVTMacBridge.app"
ARCH="$(uname -m)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "Compilando ($ARCH)…"
swiftc -O -swift-version 5 -parse-as-library \
  -target "$ARCH-apple-macos13.0" \
  -o "$APP/Contents/MacOS/UVTMacBridge" \
  $(find UVTMacBridge -name '*.swift')

# Resolve as variáveis do Xcode no Info.plist.
sed -e 's/\$(DEVELOPMENT_LANGUAGE)/en/' \
    -e 's/\$(EXECUTABLE_NAME)/UVTMacBridge/' \
    -e 's/\$(PRODUCT_BUNDLE_IDENTIFIER)/br.local.uvtmacbridge/' \
    -e 's/\$(PRODUCT_NAME)/UVTMacBridge/' \
    -e 's/\$(MACOSX_DEPLOYMENT_TARGET)/13.0/' \
    UVTMacBridge/Info.plist > "$APP/Contents/Info.plist"

codesign --force --sign - "$APP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP"

echo
echo "App gerado e registrado para sefazrnuvt:// em:"
echo "$APP"
