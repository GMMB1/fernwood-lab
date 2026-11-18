"""Fernwood partner link checker (published on :8082).

Intentional bug (A2): the destination guard is thorough for the URL it is given -
scheme, localhost, alternative IP notation, and the *resolved* address - but the
fetch then follows HTTP redirects without re-checking each hop.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

import common as c

app = Flask(__name__)

BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "::/128", "fc00::/7", "fe80::/10")]
ALT_NOTATION = re.compile(r"^(0x[0-9a-f]+|\d+|(0[0-7]*|\d+|0x[0-9a-f]+)(\.(0[0-7]*|\d+|0x[0-9a-f]+)){1,3})$", re.I)


def is_blocked(ip):
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in BLOCKED_NETS)


def guard(url):
    """Return an error string if the URL is not allowed, else None."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return "URL must use http:// or https:// scheme"
    host = (p.hostname or "").lower()
    if not host:
        return "URL must include a hostname"
    if host == "localhost" or host.endswith(".localhost"):
        return "Localhost URLs are not allowed"
    if ALT_NOTATION.match(host):
        parts = host.split(".")
        dotted_decimal = len(parts) == 4 and all(x.isdigit() and (x == "0" or not x.startswith("0")) for x in parts)
        if not dotted_decimal:
            return "Alternative IP notation not allowed"
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        return "Could not resolve host"
    for info in infos:
        if is_blocked(info[4][0]):
            return "Private or reserved IP addresses are not allowed"
    return None


PAGE = """
<div class=card><h1>Partner link checker</h1>
<p>Listing your hotel or tour on Fernwood? Check that your landing page is reachable before you submit it.</p>
<form id=f><label>Landing page URL</label><input name=url placeholder="http://attacker.lab:9000/" required>
<p><button>Check link</button></p></form><pre id=out class=muted>Result appears here.</pre></div>
<div class=card><p class=muted>Runs inside Fernwood Cloud. Internal addresses are blocked for your safety.</p></div>
<script>
document.getElementById('f').addEventListener('submit', function (ev) {
  ev.preventDefault();
  fetch('/api/check', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: ev.target.url.value})})
  .then(function (r) { return r.json(); })
  .then(function (j) { document.getElementById('out').textContent = JSON.stringify(j, null, 2); });
});
</script>"""


@app.get("/")
def index():
    return c.page("Link checker", PAGE, brand="Fernwood Partners")


@app.post("/api/check")
def check():
    url = str((request.get_json(silent=True) or {}).get("url", "")).strip()
    err = guard(url)
    if err:
        return jsonify(ok=False, url=url, error=err), 400
    try:
        # BUG (A2): redirects are followed, and each hop is never passed back through guard().
        r = requests.get(url, timeout=5, allow_redirects=True,
                         headers={"User-Agent": "Fernwood-LinkChecker/2.3"})
    except requests.RequestException as exc:
        return jsonify(ok=False, url=url, error=f"fetch failed: {type(exc).__name__}"), 502
    title = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
    return jsonify(ok=r.ok, url=url, status=r.status_code, content_type=r.headers.get("Content-Type", ""),
                   redirects_followed=len(r.history), length=len(r.content),
                   title=title.group(1).strip()[:120] if title else None, preview=r.text[:500])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
