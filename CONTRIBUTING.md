# Contribuindo

Obrigado pelo interesse! Este é um projeto pequeno e independente; qualquer ajuda é bem-vinda: relatos de teste, correções, documentação e novas funcionalidades.

## Antes de começar

- Leia o [README](README.md), principalmente a seção **Como funciona**.
- Para mudanças grandes (por exemplo, suporte à assinatura de XML), abra uma *issue* antes, para alinharmos o desenho.

## Compilando e testando

Só são necessárias as ferramentas de linha de comando da Apple (`xcode-select --install`):

```bash
./build-swiftc.sh        # gera build/UVTMacBridge.app
./Tests/run-tests.sh     # testes de protocolo e criptografia (sem rede externa)
```

Os testes exigem `openssl` e `python3`; com `node` instalado, também rodam o servidor que imita o IIS da UVT. Eles usam um Keychain temporário e **não** mexem no seu Keychain de login. Se um teste mudar esse comportamento, ele não será aceito.

## Regras do projeto

1. **Nunca versione credenciais.** Nada de certificados, `.pfx`/`.p12`, chaves, tokens, senhas, CPF/CNPJ reais ou logs com dados pessoais, nem em testes, exemplos ou *issues*. Os testes geram os seus próprios certificados.
2. **Não inclua material proprietário de terceiros** (binários, código-fonte, documentação interna) nem código sem licença compatível com a MIT. Contribua apenas com o que você escreveu ou pode licenciar.
3. **Segredos fora dos logs.** O log nunca deve receber senhas, cabeçalhos de autenticação (`SET-CERPWD*`) nem o corpo das respostas de login.
4. **O certificado de cliente só vai para hosts da SEFAZ/RN e da SET/RN.** Mudanças em `NotificationClient.isAllowed(…)` precisam de justificativa.
5. **Teste o que mudar.** Correções de bug devem vir com um teste que falhava antes. Se o teste exigir um servidor, estenda `Tests/support/`.

## Estilo

- Swift 5 (modo de linguagem 5), sem dependências externas.
- Comentários e mensagens ao usuário em português; nomes de tipos e funções em inglês.
- Comentários explicam o *porquê* (o comportamento do servidor, a armadilha), não o *o quê*.

## Pull requests

- Um assunto por PR, com descrição do problema, da solução e de como foi testado (inclua o tipo de certificado e o navegador, se for o caso).
- O CI roda `./Tests/run-tests.sh`; o PR precisa passar.

## Relatando problemas

Abra uma *issue* com: versão do macOS, tipo de certificado (A1/A3, token), navegador, o que esperava e o que aconteceu. Anexe o log (`~/Library/Logs/UVTMacBridge/uvt-mac-bridge.log`) **depois de revisá-lo**. Vulnerabilidades devem ser relatadas em particular (**Security → Report a vulnerability**).
