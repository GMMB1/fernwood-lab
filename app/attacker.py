"""Attacker box (published on :9000) - the trainee's stand-in for "my own server on the internet".

  any path        is logged (method, path, query, selected headers, body)
  /_log?q=TEXT    shows the log, newest first, filtered by TEXT (use your team tag)
  /r?to=URL       redirects to URL (302, or &code=307)
  /phish          a fake landing page; shows the A1 flag when you arrive via Fernwood's redirect

Inside the lab's server network this box is reachable as http://attacker.lab:9000
"""
import collections
import os
import threading
import time
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, redirect, request

import common as c

app = Flask(__name__)
LOG = collections.deque(maxlen=2000)
LOCK = threading.Lock()
PORTAL_PORT = int(os.environ.get("PORTAL_PUBLIC_PORT", "8080"))
SHOW_HEADERS = ("Host", "User-Agent", "Referer", "Origin", "Cookie", "Authorization", "Content-Type")


# The attacker side always looks different from Fernwood, so trainees know where they are.
ATTACKER_CSS = """
:root{--bg:#140709;--card:#1f0c10;--ink:#f7e8e8;--muted:#d1a7a7;--line:#4d1c23;--brand:#ff5a5a;--warn:#ffb020}
header{background:repeating-linear-gradient(135deg,#2b0b10 0 16px,#3b0f16 16px 32px);border-bottom:2px solid #ff5a5a}
header b{color:#ff5a5a;letter-spacing:.06em}header a{color:#f7e8e8}
.hazard{background:repeating-linear-gradient(135deg,#ffb020 0 18px,#1a1a1a 18px 36px);padding:5px;border-radius:10px;margin-bottom:18px}
.hazard div{background:#1a0a0c;color:#ffb020;font-weight:800;letter-spacing:.04em;text-align:center;padding:12px;border-radius:7px}
.tag{display:inline-block;background:#ff5a5a;color:#140709;font-weight:800;font-size:12px;padding:2px 9px;border-radius:999px;letter-spacing:.05em;margin-bottom:6px}
.fernwood-copy{background:#fff;color:#1d2433;border-radius:10px;padding:18px 20px;margin-bottom:16px;outline:3px dashed #ff5a5a;outline-offset:6px}
.fernwood-copy .fw-brand{color:#1f6f5c;font-weight:700;font-size:17px}
.fernwood-copy input{background:#f6f7f9;color:#1d2433;border:1px solid #dfe3ea}
.fernwood-copy button{background:#1f6f5c}.fernwood-copy label{color:#5b6475}
"""
BRAND = "ATTACKER BOX · port 9000"


def apage(title, body):
    return Response(c.page(title, body, brand=BRAND, extra_css=ATTACKER_CSS), mimetype="text/html")


def record():
    with LOCK:
        LOG.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "client": request.headers.get("X-Forwarded-For", request.remote_addr),
            "method": request.method,
            "url": request.full_path.rstrip("?"),
            "headers": {k: request.headers[k] for k in SHOW_HEADERS if k in request.headers},
            "body": request.get_data(as_text=True)[:2000],
        })


@app.after_request
def no_browser_cache(resp):
    # Always show the newest version of these pages (no stale copies in class).
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    record()
    return apage("Attacker box", """<div class=card><h1>Your attacker box</h1>
      <p>This stands in for a server you control on the internet. Every request to it is logged.</p>
      <table>
      <tr><th>/_log?q=TEAM</th><td>View captured requests (newest first). Put your team tag in paths so you can filter.</td></tr>
      <tr><th>/r?to=URL</th><td>Redirect to URL (302). Add <code>&amp;code=307</code> for a 307.</td></tr>
      <tr><th>/phish</th><td>A fake landing page.</td></tr>
      <tr><th>/anything/else</th><td>Logged and answered with 200.</td></tr></table>
      <p class=muted>From your laptop: <code>http://LAB-IP:9000</code>. From inside Fernwood's servers
      (for example in a URL you make them fetch): <code>http://attacker.lab:9000</code>.</p>
      <p class=muted>Dark red pages = the attacker's side. Fernwood's own pages never look like this.</p></div>""")


@app.get("/_log")
def show_log():
    flt = request.args.get("q", "")
    with LOCK:
        rows = [r for r in LOG if not flt or flt in str(r)][:200]
    if request.args.get("format") == "json":
        return jsonify(rows)
    trs = "".join(
        f"<tr><td>{c.e(r['time'])}</td><td>{c.e(r['method'])}</td><td><code>{c.e(r['url'])}</code></td>"
        f"<td><pre>{c.e(chr(10).join(f'{k}: {v}' for k, v in r['headers'].items()))}"
        f"{(chr(10) + chr(10) + c.e(r['body'])) if r['body'] else ''}</pre></td></tr>" for r in rows)
    body = (f"<div class=card><h1>Captured requests</h1><form><label>Filter</label>"
            f"<input name=q value='{c.e(flt)}' placeholder='team tag'> <button>Filter</button></form>"
            f"<p class=muted>Auto-refreshes every 3 seconds. Showing {len(rows)}.</p>"
            f"<table><tr><th>Time</th><th>Method</th><th>URL</th><th>Headers / body</th></tr>{trs}</table></div>"
            f"<script>setTimeout(function(){{location.reload()}},3000)</script>")
    return apage("Captured requests", body)


@app.get("/r")
def redir():
    record()
    to = request.args.get("to", "/")
    code = 307 if request.args.get("code") == "307" else 302
    return redirect(to, code=code)


@app.get("/steal")
def steal():
    """Where the C1 payload sends what it read from Fernwood as the logged-in victim."""
    record()
    data = request.args.get("d", "")
    ref = request.headers.get("Referer", "")
    try:
        via_portal = urlparse(ref).port == PORTAL_PORT
    except ValueError:
        via_portal = False
    if via_portal and '"member_no"' in data:
        msg = (f"<p>This data was read from Fernwood <b>by JavaScript running inside the victim's own browser "
               f"session</b>, then sent here.</p><p>Lab flag: <span class=flag>{c.FLAGS['C1']}</span></p>")
    else:
        msg = ("<p class=warn>No Fernwood account data received from a Fernwood page. Make Fernwood itself run "
               "your JavaScript, read <code>/api/me</code>, and send the answer here.</p>")
    return apage("Stolen data", f"""
      <div class=hazard><div>&#9888; ATTACKER-CONTROLLED PAGE &middot; port 9000 &middot; data stolen by XSS</div></div>
      <div class=card><span class=tag>RECEIVED FROM THE VICTIM'S BROWSER</span><pre>{c.e(data) or '(nothing)'}</pre></div>
      <div class=card><span class=tag>LAB</span> {msg}</div>""")


@app.get("/phish")
def phish():
    record()
    ref = request.headers.get("Referer", "")
    try:
        via_portal = urlparse(ref).port == PORTAL_PORT
    except ValueError:
        via_portal = False
    if via_portal:
        msg = (f"<p>You arrived here from <code>{c.e(ref)}</code>, which is Fernwood's website. "
               f"A victim would trust this link because it starts with Fernwood's address.</p>"
               f"<p>Lab flag: <span class=flag>{c.FLAGS['A1']}</span></p>")
    else:
        msg = "<p class=warn>No Fernwood referrer seen. Arrive here through Fernwood's own redirect to get the flag.</p>"
    return apage("Sign in", f"""
      <div class=hazard><div>&#9888; ATTACKER-CONTROLLED PAGE &middot; port 9000 &middot; this is NOT Fernwood</div></div>
      <div class=card><span class=tag>WHAT THE VICTIM SEES</span>
      <p class=muted>The box below copies Fernwood's design, like a real phishing page would. There is no red
      frame in real life: the only clue is the address bar - <b>:9000</b> instead of Fernwood's <b>:8080</b>.</p></div>
      <div class=fernwood-copy><div class=fw-brand>Fernwood Travel</div><h1>Session expired</h1>
      <p>Please sign in again to continue.</p><label>Username</label><input autocomplete=off>
      <label>Password</label><input type=password autocomplete=off>
      <p><button type=button>Sign in</button></p></div>
      <div class=card><span class=tag>LAB</span> {msg}</div>""")


@app.route("/<path:anything>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def catch_all(anything):
    if anything == "favicon.ico":
        return "", 404
    record()
    return Response("ok - logged\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
