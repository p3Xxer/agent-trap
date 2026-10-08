import http.server
import threading
import urllib.request


def test_local_server_roundtrip():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/"
        assert urllib.request.urlopen(url, timeout=5).read() == b'ok'
    finally:
        server.shutdown()
