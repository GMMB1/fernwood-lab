"""Fernwood partner API gateway (published on :8083).

Intentional bug (A3): the /partner/ mount strips the prefix *including its trailing
slash* and concatenates the rest onto an upstream base that has no trailing slash:

    upstream = "http://partner-backend:44302" + "<rest of path>"

so /partner/v1/status becomes http://partner-backend:44302v1/status (broken), and
/partner/@host/ becomes http://partner-backend:44302@host/ - the old authority turns
into userinfo and the attacker chooses the real host.

Built on http.server on purpose: no framework path normalisation gets in the way.
"""
import http.client
import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PARTNER_BASE = "http://partner-backend:44302"   # note: no trailing slash
API_KEYS = {"pk_partner_demo_readonly"}


def split_url(url):
    """Very small URL splitter that behaves like a typical proxy: scheme://[userinfo@]host[:port]/path"""
    rest = url.split("://", 1)[1]
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            cut = min(cut, i)
    authority, path = rest[:cut], rest[cut:] or "/"
    if path.startswith("?"):
        path = "/" + path
    hostport = authority.rsplit("@", 1)[1] if "@" in authority else authority
    host, port = hostport, 80
    if ":" in hostport:
        h, p = hostport.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    return hostport, host, port, path


class Handler(BaseHTTPRequestHandler):
    server_version = "fernwood-gw/1.4"
    sys_version = ""

    def log_message(self, fmt, *args):
        print("gateway:", self.address_string(), fmt % args, flush=True)

    def send(self, status, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def error_page(self, status, title, msg):
        self.send(status, f"<!DOCTYPE HTML><html><head><title>{status} {title}</title></head><body>"
                          f"<h1>{title}</h1><p>{msg}</p><hr><address>fernwood-gw/1.4 Proxy</address></body></html>")

    def do_GET(self):
        raw = self.path
        if raw == "/":
            return self.send(200, json.dumps({"service": "fernwood-partner-gateway", "version": "1.4",
                                              "routes": ["/api/v1/", "/partner/"]}), "application/json")
        if raw.startswith("/api/v1/"):
            return self.api(raw)
        if raw.startswith("/partner/"):
            return self.partner(raw)
        return self.error_page(404, "Not Found", "The requested URL was not found on this server.")

    def api(self, raw):
        # The correctly configured route: a real API that wants a partner key.
        if raw.split("?")[0] == "/api/v1/status":
            return self.send(200, json.dumps({"status": "ok"}), "application/json")
        if self.headers.get("X-Partner-Key") not in API_KEYS:
            return self.send(401, json.dumps({"error": "missing or invalid X-Partner-Key"}), "application/json")
        return self.send(200, json.dumps({"partners": []}), "application/json")

    def partner(self, raw):
        upstream = PARTNER_BASE + raw[len("/partner/"):]      # BUG (A3)
        hostport, host, port, path = split_url(upstream)
        try:
            socket.getaddrinfo(host, port)
        except (socket.gaierror, UnicodeError):
            return self.error_page(502, "Proxy Error",
                                   f"The proxy server received an invalid response from an upstream server.<br>"
                                   f"Reason: DNS lookup failure for: {hostport}")
        try:
            conn = http.client.HTTPConnection(host, port, timeout=4)
            conn.request("GET", path, headers={"Host": hostport, "User-Agent": "fernwood-gw/1.4"})
            resp = conn.getresponse()
            body = resp.read(200_000)
        except ConnectionRefusedError:
            return self.error_page(503, "Service Unavailable",
                                   "The server is temporarily unable to service your request "
                                   "(connection refused by upstream).")
        except (socket.timeout, TimeoutError):
            return self.error_page(504, "Gateway Timeout", "The upstream server did not respond in time.")
        except OSError as exc:
            return self.error_page(502, "Proxy Error", f"Error reading from remote server ({type(exc).__name__}).")
        self.send_response(resp.status)
        for k in ("Content-Type", "Location"):
            if resp.getheader(k):
                self.send_header(k, resp.getheader(k))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 7000), Handler).serve_forever()
