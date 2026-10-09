#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
xcodebuild \
  -project UVTMacBridge.xcodeproj \
  -scheme UVTMacBridge \
  -configuration Release \
  -derivedDataPath "$PWD/build" \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=YES \
  build

echo
echo "App gerado em:"
echo "$PWD/build/Build/Products/Release/UVTMacBridge.app"
