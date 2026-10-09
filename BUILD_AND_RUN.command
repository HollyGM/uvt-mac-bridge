#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")"

# Com Xcode completo usa o xcodebuild; só com as Command Line Tools, compila direto com o swiftc.
if xcodebuild -version >/dev/null 2>&1; then
  ./build-local.sh
  APP="$PWD/build/Build/Products/Release/UVTMacBridge.app"
elif command -v swiftc >/dev/null 2>&1; then
  ./build-swiftc.sh
  APP="$PWD/build/UVTMacBridge.app"
else
  echo "Nem Xcode nem as Command Line Tools foram encontrados."
  echo "Instale as ferramentas com:  xcode-select --install"
  read -k 1 "?Pressione uma tecla para fechar..."
  exit 1
fi

open "$APP"
echo
echo "UVTMacBridge.app compilado e aberto."
read -k 1 "?Pressione uma tecla para fechar..."
