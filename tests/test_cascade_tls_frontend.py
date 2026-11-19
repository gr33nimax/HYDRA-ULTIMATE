"""Exercise the lab's TLS boundary without needing privileged engine networking."""
import http.client
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hydra.services.managed_nodes.identity import create_certificate_pair
from tests.cascade_tls_frontend import TLSFrontend


def test_anytls_lab_frontend_terminates_tls_before_plaintext_backend(tmp_path):
    certificate, private_key = create_certificate_pair("lab", role="server", address="127.0.0.1")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_bytes(certificate)
    key.write_bytes(private_key)

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    frontend = TLSFrontend("127.0.0.1", 0, target.server_port, cert, key)
    connection = http.client.HTTPSConnection("127.0.0.1", frontend.server.server_address[1], timeout=3,
                                             context=ssl.create_default_context(cafile=str(cert)))
    try:
        connection.request("GET", "/")
        assert connection.getresponse().status == 204
    finally:
        connection.close()
        frontend.close()
        target.shutdown()
        target.server_close()
        thread.join(timeout=2)
