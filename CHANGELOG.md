# Histórico de versões

## 0.2.0 — 2026-11-16

### Ajustes

- **Certificado vencido não segue mais para o login.** Antes, o app pedia o PIN e o servidor recusava com "403 – Acesso negado", sem explicar o motivo. Agora a página recebe "O certificado selecionado venceu em dd/mm/aaaa…". Certificado que ainda não começou a valer também é recusado.
- **Aviso de vencimento:** quando faltam menos de 30 dias, o aviso aparece na janela, abaixo do certificado, e também no log.
- **Log mais enxuto e sem dados da requisição:**
  - um link malformado registra só os nomes dos campos, nunca os valores (o token da sessão ficava no log);
  - respostas de erro do servidor são cortadas em 300 caracteres no log e na janela;
  - a janela mostra só as últimas 500 linhas do log, e o arquivo continua completo.
- A versão do app aparece no topo da janela.
- Comentários do código descrevem só o comportamento do protocolo.
- Removidas duas funções que não eram usadas.

### Manutenção

- A verificação no GitHub usa a versão atual do `actions/checkout` e roda também uma vez por mês, para avisar cedo se uma mudança no macOS afetar o app.

## 0.1.0 — 2026-10-09

- Primeira versão: login na UVT com e-CPF A3 em token (SafeNet) pelo Safari e cadastro da senha do SIGAT no primeiro acesso.
