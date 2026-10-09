#!/bin/bash
# Testes de protocolo e criptografia do UVT Mac Bridge. Não precisam de Xcode nem de rede externa.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

WORK="$(mktemp -d)"
cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${IIS_PID:-}" ] && kill "$IIS_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

OPENSSL="${OPENSSL:-openssl}"
cd "$WORK"

# --- Fixtures: CA, servidor local, usuário (cliente) e "certificado da UVT" usado no fluxo ---
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=UVT Test CA" -days 2 2>/dev/null
mkcert() { # nome, CN, extensões
  "$OPENSSL" req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  printf "%s\n" "$3" > "$1.ext"
  "$OPENSSL" x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$1.pem" -days 2 -extfile "$1.ext" 2>/dev/null
}
mkcert server "127.0.0.1" $'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth'
mkcert user "USUARIO TESTE:12345678901" $'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth'
mkcert uvt "api.sefaz.rn.gov.br" $'keyUsage=digitalSignature,keyEncipherment'
# Cadeia de quatro níveis (raiz ← mid1 ← mid2 ← folha com AIA), como a do e-CPF real
mkca() { # nome, CN, assinante
  "$OPENSSL" req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  printf "basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n" > "$1.ext"
  "$OPENSSL" x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -out "$1.pem" -days 2 -extfile "$1.ext" 2>/dev/null
}
mkca mid1 "Test Mid 1" ca
mkca mid2 "Test Mid 2" mid1
"$OPENSSL" req -newkey rsa:2048 -nodes -keyout chainleaf.key -out chainleaf.csr -subj "/CN=CHAIN LEAF:11111111111" 2>/dev/null
printf "keyUsage=digitalSignature\nauthorityInfoAccess=caIssuers;URI:http://repo.test/ac/chain.p7b\n" > chainleaf.ext
"$OPENSSL" x509 -req -in chainleaf.csr -CA mid2.pem -CAkey mid2.key -CAcreateserial -out chainleaf.pem -days 2 -extfile chainleaf.ext 2>/dev/null
"$OPENSSL" crl2pkcs7 -nocrl -certfile mid1.pem -certfile mid2.pem -certfile ca.pem -outform der -out chain.p7b

"$OPENSSL" pkcs12 -export -legacy -inkey user.key -in user.pem -out user.p12 -passout pass:test 2>/dev/null \
  || "$OPENSSL" pkcs12 -export -inkey user.key -in user.pem -out user.p12 -passout pass:test
"$OPENSSL" pkcs12 -export -legacy -inkey uvt.key -in uvt.pem -out uvt.p12 -passout pass:test 2>/dev/null \
  || "$OPENSSL" pkcs12 -export -inkey uvt.key -in uvt.pem -out uvt.p12 -passout pass:test

python3 -I "$ROOT/Tests/support/test_servers.py" "$WORK" > python.log 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 300); do [ -s http.port ] && [ -s https.port ] && break; sleep 0.1; done
if ! [ -s http.port ] || ! [ -s https.port ]; then
  echo "erro: os servidores de teste (python) não subiram em 30 s" >&2
  cat python.log >&2
  exit 1
fi

# Servidor que imita o IIS da UVT (recusa h2 e pede o certificado por renegociação TLS 1.2). Opcional: precisa de Node.
if command -v node >/dev/null 2>&1; then
  node "$ROOT/Tests/support/iis_like_server.js" "$WORK" > node.log 2>&1 &
  IIS_PID=$!
  for _ in $(seq 1 100); do [ -s port ] && break; sleep 0.1; done
  if [ -s port ]; then
    mv port reneg.port
  else
    echo "aviso: o servidor node não subiu; o teste de renegociação TLS será ignorado" >&2
    cat node.log >&2
  fi
else
  echo "aviso: node não encontrado; o teste de renegociação TLS será ignorado"
fi

# --- Compila as fontes do app (sem a interface) junto com os testes ---
cd "$ROOT"
SOURCES=$(find UVTMacBridge -name '*.swift' ! -name 'UVTMacBridgeApp.swift' ! -name 'ContentView.swift' ! -name 'AppModel.swift')
swiftc -swift-version 5 -target "$(uname -m)-apple-macos13.0" -o "$WORK/tests" $SOURCES Tests/main.swift

UVT_TEST_DIR="$WORK" UVT_TEST_OPENSSL="$OPENSSL" "$WORK/tests"
