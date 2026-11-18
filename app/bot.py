"""Victim simulator (internal only, called by the dashboard).

Plays "alice", a logged-in Fernwood member who opens links she is sent. It follows
HTTP redirects but does NOT run JavaScript.

On a real program the victim is always YOUR OWN second account - never a real user.
"""
import os
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, request

import common as c

app = Flask(__name__)
EDGE = os.environ.get("EDGE_HOST", "edge")
PORT_MAP = {8080: f"http://{EDGE}:8080", 8081: f"http://{EDGE}:8081", 9000: f"http://{EDGE}:9000"}
START_PORTS = {8080, 8081}
REDIRECTS = (301, 302, 303, 307, 308)


def to_internal(public_url):
    p = urlparse(public_url)
    if p.scheme not in ("http", "https"):
        return None
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return None
    base = PORT_MAP.get(port)
    if not base:
        return None
    return base + (p.path or "/") + (f"?{p.query}" if p.query else "")


def logged_in_session():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (lab victim simulator; alice)"
    r1 = s.post(f"{PORT_MAP[8080]}/api/login", json={"username": "alice", "password": c.ALICE_PASSWORD}, timeout=5)
    r2 = s.post(f"{PORT_MAP[8081]}/login", data={"username": "alice", "password": c.ALICE_PASSWORD},
                allow_redirects=False, timeout=5)
    if r1.status_code != 200 or r2.status_code not in REDIRECTS:
        raise RuntimeError("victim login failed")
    return s


@app.post("/visit")
def visit():
    url = str((request.get_json(silent=True) or {}).get("url", "")).strip()
    p = urlparse(url)
    try:
        port = p.port
    except ValueError:
        port = None
    if p.scheme not in ("http", "https") or port not in START_PORTS:
        return jsonify(ok=False, message="Alice only opens links that point at the Fernwood website "
                                         "(port 8080) or Fernwood ID (port 8081).")
    try:
        s = logged_in_session()
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, message=f"Victim simulator error: {exc}"), 500
    current, hops, last_status = url, 0, None
    while hops <= 8:
        internal = to_internal(current)
        if internal is None:
            break
        try:
            r = s.get(internal, allow_redirects=False, timeout=6)
        except requests.RequestException:
            break
        last_status = r.status_code
        if r.status_code in REDIRECTS and r.headers.get("Location"):
            current = urljoin(current, r.headers["Location"])
            hops += 1
            continue
        break
    return jsonify(ok=True, message=f"Alice opened your link and followed {hops} redirect(s). "
                                    f"Final status she saw: {last_status}. She does not run JavaScript.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
