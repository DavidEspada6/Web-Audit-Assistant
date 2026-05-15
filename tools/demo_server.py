from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


HOST = "127.0.0.1"
PORT = 8088


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "WebAuditDemo/0.1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
            return

        if parsed.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APP_ENV=demo\nDATABASE_URL=postgres://demo:demo@localhost/demo\n")
            return

        if parsed.path == "/admin":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        if parsed.path == "/phpinfo.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><title>phpinfo()</title><body>PHP Version 8.2.0</body></html>")
            return

        if parsed.path not in {"/", "/index.html"}:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        canary = query.get("audit_canary", [""])[0]
        body = f"""
<!doctype html>
<html>
  <head><title>Web Audit Demo</title></head>
  <body>
    <h1>Web Audit Demo</h1>
    <p>{canary}</p>
    <form method="post" action="/login">
      <input type="text" name="username">
      <input type="password" name="password">
      <button type="submit">Login</button>
    </form>
  </body>
</html>
""".encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=demo123; Path=/")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DemoHandler)
    print(f"Demo server listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
