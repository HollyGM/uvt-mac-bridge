// Emula o IIS da UVT (aut.sefaz.rn.gov.br). Uso: node iis_like_server.js <pasta-com-certificados>
// Emula o IIS real: ALPN h2 aceito; em h2 a rota protegida responde HTTP_1_1_REQUIRED; em HTTP/1.1 pede o certificado por renegociação.
const http2 = require('http2'), fs = require('fs'), path = require('path');
process.chdir(process.argv[2]);
const server = http2.createSecureServer({ key: fs.readFileSync('server.key'), cert: fs.readFileSync('server.pem'), ca: fs.readFileSync('ca.pem'),
  allowHTTP1: true, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', requestCert: false }, (req, res) => {
  if (!req.url.startsWith('/who')) { res.writeHead(200); return res.end('ok ' + req.httpVersion); }
  if (req.httpVersion === '2.0') { req.stream.close(http2.constants.NGHTTP2_HTTP_1_1_REQUIRED); return; }
  req.socket.renegotiate({ requestCert: true, rejectUnauthorized: false }, (err) => {
    if (err) { res.writeHead(500); return res.end('reneg-error'); }
    const c = req.socket.getPeerCertificate();
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({ cn: c && c.subject ? c.subject.CN : null, authorized: req.socket.authorized, http: req.httpVersion }));
  });
});
server.listen(0, '127.0.0.1', () => fs.writeFileSync('port', String(server.address().port)));
