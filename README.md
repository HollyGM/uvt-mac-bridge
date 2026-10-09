# UVT Mac Bridge

[![CI](https://github.com/HollyGM/uvt-mac-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/HollyGM/uvt-mac-bridge/actions/workflows/ci.yml)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)

Cliente **não oficial** para macOS do *Módulo de Segurança UVT* da SEFAZ/RN. Ele permite entrar na Unidade Virtual de Tributação (<https://uvt.sefaz.rn.gov.br>) pelo Mac, usando certificado digital ICP-Brasil (A1 no Keychain ou A3 em token).

A UVT aciona o módulo de segurança pelo protocolo `sefazrnuvt://`; o módulo oficial só existe para Windows. Este app registra o mesmo protocolo no macOS e faz o que a página espera: usa o seu certificado, cadastra a senha do SIGAT no primeiro acesso e devolve o resultado ao navegador.

> **Aviso.** Este projeto é independente e **não tem vínculo com a SEFAZ/RN**. Não é software oficial, não é homologado e não tem garantia de qualquer tipo. Você o usa por sua conta e risco, com o seu certificado e a sua senha, e deve respeitar os termos de uso dos serviços da SEFAZ/RN. Mudanças no servidor da UVT podem quebrá-lo sem aviso.

## O que funciona

| | Situação |
|---|---|
| Login com e-CPF A3 em token (SafeNet), pelo Safari | ✅ confirmado |
| Cadastro da senha do SIGAT no primeiro acesso | ✅ confirmado |
| Certificado A1 (arquivo `.pfx` importado no Keychain) | ⚠️ não testado; deve funcionar (chave de software) |
| e-CNPJ | ⚠️ não testado |
| Chrome, Firefox, Edge | ⚠️ não testados |
| Mac com Intel | ⚠️ o build é nativo da arquitetura da máquina; só Apple Silicon foi testado |
| Assinatura de XML (`sign`) | ❌ não suportada |
| Assinatura de PDF (`signPdf`) | ❌ não suportada |

Quem testar combinações marcadas com ⚠️ pode abrir uma *issue* contando o resultado.

## Requisitos

- macOS 13 ou superior.
- Ferramentas de linha de comando da Apple (`xcode-select --install`) ou o Xcode. O Xcode completo **não** é necessário.
- Certificado digital ICP-Brasil (e-CPF ou e-CNPJ). Para token A3, o driver do fabricante precisa expor o certificado ao macOS (CryptoTokenKit); com o SafeNet Authentication Client isso funciona.
- A senha do SIGAT (pedida uma vez por certificado).

## Instalação

Não há binário pronto: o app não é assinado nem notarizado pela Apple, então a instalação é compilar no próprio Mac.

```bash
git clone https://github.com/HollyGM/uvt-mac-bridge.git
cd uvt-mac-bridge
./build-swiftc.sh
```

Isso gera `build/UVTMacBridge.app` e o registra como tratador de `sefazrnuvt://`. Para deixá-lo junto dos outros aplicativos:

```bash
cp -R build/UVTMacBridge.app /Applications/
open /Applications/UVTMacBridge.app
```

Abra o app uma vez depois de copiar, para o macOS associar o protocolo ao novo local. Ao recompilar, copie de novo; como o app é assinado "ad hoc", o macOS volta a pedir confirmações do Keychain a cada build novo.

Quem preferir o Xcode pode abrir `UVTMacBridge.xcodeproj`, mas o caminho testado é o `build-swiftc.sh`.

## Como usar

1. Abra o **UVT Mac Bridge** e confira, em **Certificado**, se o seu e-CPF/e-CNPJ está selecionado. O app lembra da escolha e, por padrão, sugere um certificado emitido por AC e dentro da validade. Certificados autoassinados são recusados.
2. Entre na UVT normalmente pelo navegador. Quando a página acionar o módulo de segurança, o navegador pergunta se pode abrir o `UVTMacBridge`; confirme.
3. Se usa token A3, informe o PIN quando o macOS pedir.
4. No **primeiro acesso de cada certificado**, o app pede a senha do SIGAT. Depois disso, o login não pede mais.

Para testar só o registro do protocolo (sem rede), com o app já aberto uma vez:

```bash
open 'sefazrnuvt://eyJtZXRob2QiOiJ2ZXJzaW9uIn0='
```

O log deve mostrar `Método: version`.

## Solução de problemas

O log fica em `~/Library/Logs/UVTMacBridge/uvt-mac-bridge.log` (e na janela do app). Ele não contém senhas, cabeçalhos de autenticação nem o conteúdo das respostas do login.

| Sintoma | O que fazer |
|---|---|
| O macOS pede a **senha do chaveiro "login"** | É a senha do seu usuário do Mac, não a do certificado. Vale para certificados com chave de software no Keychain; "Permitir Sempre" evita repetir. Token A3 pede o **PIN**, não esta senha. |
| "O certificado selecionado é autoassinado…" | Selecione o seu e-CPF/e-CNPJ emitido por uma AC. Autoassinados nunca são aceitos pela UVT. |
| `403 - Acesso Negado` no `requestpass` | O servidor não aceitou o certificado. Veja no log a linha "intermediários enviados": deve ser maior que zero para certificados com cadeia de AC. Sem internet, o app não consegue completar a cadeia. |
| "Senha do SIGAT inválida" | O app pergunta de novo. Evite tentar senhas por palpite. |
| O navegador não abre o app | Rode `./build-swiftc.sh` de novo (ele registra o protocolo) ou abra o app uma vez a partir da pasta definitiva. |
| Quero só registrar as chamadas, sem conexão | Desligue **Processar e responder à UVT**: o app registra o método e os nomes dos parâmetros e não abre nenhuma conexão. |

Ao abrir uma *issue*, anexe o log, mas **revise-o antes**: ele contém nomes de host e de parâmetros. Nunca cole tokens, senhas ou certificados.

## Como funciona

Esta seção é para quem quer contribuir.

**Chamada.** O navegador abre `sefazrnuvt://<Base64 de um JSON>` com `host`, `token`, `method`, `url`, `params` etc. O app aceita Base64 padrão e URL-safe, com ou sem barra final.

**Antes de qualquer método**, o app checa a versão: `GET <esquema>://<host>/autbasic/version?client_id=e7a9be83&client_version=1.0.11`. Só HTTP 200/300 passa; se falhar, nada é respondido ao navegador.

**`version`** responde `1.0.11`. Em todo `proxyRequest`, a resposta `version` é enviada antes do resultado do login.

**`proxyRequest` (login).** Sempre com `GET url?<params>&action=<ação>` e o certificado de cliente no TLS:

```
requestpass ─┬─ 302 ─▶ decifra result.password (RSA PKCS#1 v1.5, chave do usuário),
             │         recifra com result.certificado (chave do servidor)
             │         ─▶ authenticate (header SET-CERPWD) ─▶ resposta final (200)
             ├─ 407 ─▶ pede a senha do SIGAT ─▶ register ─▶ 201 ─▶ requestpass
             └─ 400/404 (senha inválida) ─▶ avisa ─▶ pede a senha ─▶ register
```

No `register`, a senha do SIGAT é cifrada com DES-CBC (chave e IV aleatórios, enviados em `SET-CERPWD-KEY` e `SET-CERPWD-IV`) e o resultado é cifrado com a chave pública do próprio certificado do usuário em `SET-CERPWD`. DES é fraco, mas é o formato que o servidor espera.

**Resposta ao navegador.** `POST <host>v1/notificacao/view/enviar` com `{"Titulo":"uvt-ms-action:<método>","Conteudo":"uvt-ms-action:<método>","Contexto":"","Dados":{"payload":"<Base64 de {type,error,data}>"},"UserSystem":true,"Token":"<token>"}`. O `host` só pode ser um destes: `apidev`, `apihom`, `apihom2` ou `api` em `sefaz.rn.gov.br` / `set.rn.gov.br`, terminando em `/usuarios/`.

**Particularidades do servidor de autenticação:**

- **Renegociação TLS.** O `aut.sefaz.rn.gov.br` é um IIS que só pede o certificado de cliente *depois* da requisição, por renegociação TLS 1.2, e recusa HTTP/2 nesse caso. O `URLSession` do macOS atual falha aí com `NSURLErrorDomain -1206`, mesmo com credencial válida. Por isso as chamadas autenticadas usam um cliente HTTP/1.1 mínimo sobre o Secure Transport (`SecureTransportClient.swift`). A API é marcada como obsoleta pela Apple, mas continua no sistema. A checagem de versão e a notificação usam `URLSession`.
- **Cadeia do certificado.** O macOS só envia a cadeia que já conhece. Num e-CPF ela costuma ter três níveis; sem o intermediário que falta, o servidor devolve `403`. O app completa a cadeia seguindo o ponteiro AIA "CA Issuers" do certificado (download por HTTP, porque os repositórios das ACs não têm HTTPS) e guarda o resultado em `~/Library/Application Support/UVTMacBridge/chain-cache`.
- **O 302 do `requestpass` não é seguido:** o resultado vem no corpo dele.

### Estrutura

```
UVTMacBridge/
  AppModel.swift, ContentView.swift, UVTMacBridgeApp.swift   interface e orquestração
  Protocol/URLSchemeParser.swift                             decodifica sefazrnuvt://
  Handlers/                                                  version, proxyRequest e o fluxo de login
  Services/
    SecureTransportClient.swift                              HTTP/1.1 com renegociação TLS
    UVTHTTPClient.swift                                      URLSession (versão e notificação)
    CertificateService.swift, CertificateChainBuilder.swift  identidades, chave privada e cadeia
    NotificationClient.swift, VersionChecker.swift           resposta ao navegador e checagem de versão
    UVTCrypto.swift                                          RSA PKCS#1 e DES-CBC
  Support/                                                   log e diálogos de senha
Tests/                                                       testes de protocolo e criptografia
```

## Testes

```bash
./Tests/run-tests.sh
```

Não precisam de Xcode nem de acesso à rede. Requerem `openssl` e `python3`; se houver `node`, também roda um servidor que se comporta como o IIS da UVT (recusa HTTP/2 e pede o certificado por renegociação), que reproduz o erro `-1206` do `URLSession`.

Os testes geram uma CA e certificados de teste, sobem servidores locais (HTTP e HTTPS com certificado de cliente obrigatório) e cobrem: o parser, o envelope de resposta, a criptografia conferida contra o `openssl`, o fluxo de login completo contra uma UVT simulada (primeiro acesso, acessos seguintes, senha errada, cancelamento, laços infinitos, erros HTTP), a montagem da cadeia por AIA, as notificações e a política de hosts. Os certificados de teste vão para um Keychain temporário, nunca para o seu.

A UVT simulada prova que o app é coerente com o protocolo descrito acima, não que o servidor real o aceita; essa parte só se confirma com certificado e senha reais.

## Segurança e privacidade

- A chave privada nunca sai do Keychain ou do token; as operações passam pelo `Security.framework`. Nada de chave privada é gravado em disco.
- A senha do SIGAT só existe em memória durante o diálogo e é enviada cifrada.
- O certificado de cliente só é apresentado a hosts da SEFAZ/RN e da SET/RN, por HTTPS.
- O login para depois de 12 chamadas HTTP, para evitar laços infinitos.
- Mensagens de erro do servidor são truncadas antes de irem ao navegador.

Para relatar uma vulnerabilidade, use **Security → Report a vulnerability** neste repositório (relato privado), em vez de abrir uma *issue* pública.

## Contribuindo

Contribuições são bem-vindas: veja o [CONTRIBUTING.md](CONTRIBUTING.md). Algumas ideias:

- suporte a `sign` (assinatura de XML);
- testes com e-CNPJ, certificados A1 e outros navegadores;
- build universal (arm64 + x86_64), assinatura e notarização;
- validar e manter o projeto do Xcode;
- tratar outros ambientes da SEFAZ/RN (homologação) de forma explícita.

## Licença

[MIT](LICENSE).
