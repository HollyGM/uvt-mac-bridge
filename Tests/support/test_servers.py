"""Servidores locais usados pelos testes do transporte HTTP (HTTP simples e HTTPS com mTLS)."""
import json
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

work = Path(sys.argv[1])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/status302":
            # Como a UVT: 302 sem Location e com o resultado no corpo.
            self._send(302, json.dumps({"result": {"password": "abc", "certificado": "def"}}))
        elif url.path == "/status302-location":
            self._send(302, json.dumps({"redirect": True}), {"Location": "/echo"})
        elif url.path == "/status307":
            self._send(307, "", {"Location": "/echo?via=307"})
        elif url.path == "/status400":
            self._send(400, json.dumps({"erro": "senha"}))
        elif url.path.startswith("/file/"):
            data = (work / url.path[len("/file/"):]).read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif url.path == "/who":
            cert = self.connection.getpeercert()
            subject = dict(item[0] for item in cert["subject"]) if cert else {}
            self._send(200, json.dumps({"cn": subject.get("commonName")}))
        else:
            echo = {"query": query, "set_cerpwd": self.headers.get("SET-CERPWD"), "cookie": self.headers.get("Cookie")}
            self._send(200, json.dumps(echo))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        self._send(200, json.dumps({"content_type": self.headers.get("Content-Type"), "body": body}))


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind chama socket.getfqdn() (DNS reverso), que em runners de CI sem DNS
        # pode levar dezenas de segundos. Os testes só usam 127.0.0.1, então basta o bind.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


http_server = Server(("127.0.0.1", 0), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(work / "server.pem", work / "server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(work / "ca.pem")
https_server = Server(("127.0.0.1", 0), Handler)
https_server.socket = context.wrap_socket(https_server.socket, server_side=True)

(work / "http.port").write_text(str(http_server.server_address[1]))
(work / "https.port").write_text(str(https_server.server_address[1]))

threading.Thread(target=https_server.serve_forever, daemon=True).start()
http_server.serve_forever()
