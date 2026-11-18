"""Fernwood ID - OAuth 2.0 authorization server (published on :8081).

Intentional bugs (B3):
  * the public web client's redirect_uri check only looks at the *path* (/callback...),
    so any host is accepted;
  * the client is public (no secret) - correct for a browser app, but it means
    whoever holds a code can redeem it;
  * PKCE is supported but not required, and the web client never sends it.
"""
import base64
import hashlib
import os
import secrets
import threading
import time
from urllib.parse import urlencode, urlparse

from flask import Flask, jsonify, make_response, redirect, request, session

import common as c

app = Flask(__name__)
app.secret_key = os.environ.get("IDP_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_NAME="fwid_session", SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_HTTPONLY=True)

CLIENTS = {
    "fernwood-web": {
        "type": "public",
        "name": "Fernwood Travel website",
        "first_party": True,
    },
    "fernwood-admin-console": {
        "type": "confidential",
        "name": "Fernwood admin console",
        "secret": os.environ.get("ADMIN_CLIENT_SECRET") or secrets.token_urlsafe(24),
        "redirect_uris": ["https://admin.fernwood.internal/oauth/callback"],
        "first_party": True,
    },
}
CODES, TOKENS = {}, {}
LOCK = threading.Lock()

c.init_db()


def me():
    uid = session.get("uid")
    return c.get_user(uid) if uid else None


def render(title, body, status=200):
    nav = [("Account", "/account"), ("Log out", "/logout")] if me() else [("Log in", "/login")]
    return make_response(c.page(title, body, brand="Fernwood ID", nav=nav), status)


def redirect_uri_allowed(client, uri):
    p = urlparse(uri)
    if client["type"] == "public":
        # BUG (B3): "every Fernwood environment uses /callback", so only the path is checked.
        return p.scheme in ("http", "https") and bool(p.netloc) and p.path.startswith("/callback")
    return uri in client["redirect_uris"]


def oauth_error(error, desc, status=400):
    return jsonify(error=error, error_description=desc), status


@app.after_request
def cors(resp):
    if request.path in ("/oauth/token", "/userinfo"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.get("/")
def index():
    return redirect("/account")


@app.get("/.well-known/openid-configuration")
def discovery():
    base = f"{request.scheme}://{request.host}"
    return jsonify(
        issuer=base,
        authorization_endpoint=f"{base}/oauth/authorize",
        token_endpoint=f"{base}/oauth/token",
        userinfo_endpoint=f"{base}/userinfo",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code"],
        code_challenge_methods_supported=["S256", "plain"],
        token_endpoint_auth_methods_supported=["none", "client_secret_post"],
        scopes_supported=["openid", "profile"])


@app.route("/login", methods=["GET", "POST"])
def login():
    ret = request.values.get("return", "/account")
    if not ret.startswith("/oauth/"):
        ret = "/account"
    err = ""
    if request.method == "POST":
        u = c.get_user_by_name(request.form.get("username", "").strip().lower())
        if u and c.check_pw(request.form.get("password", ""), u["pw"]):
            session.clear()
            session["uid"] = u["id"]
            return redirect(ret)
        err = "Invalid username or password."
    return render("Sign in", f"""<div class=card><h1>Sign in to Fernwood ID</h1>
      <p class=muted>Same username and password as the Fernwood website.</p><p class=warn>{c.e(err)}</p>
      <form method=post><input type=hidden name=return value="{c.e(ret)}">
      <label>Username</label><input name=username required>
      <label>Password</label><input name=password type=password required>
      <p><button>Sign in</button></p></form></div>""")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/account")
def account():
    u = me()
    if not u:
        return redirect("/login")
    return render("Account", f"<div class=card><h1>Fernwood ID</h1><p>Signed in as <b>{c.e(u['username'])}</b>.</p></div>")


@app.get("/oauth/authorize")
def authorize():
    a = request.args
    client = CLIENTS.get(a.get("client_id", ""))
    if not client:
        return render("Error", "<div class=card><h1>400</h1><p>Unknown client_id.</p></div>", 400)
    redirect_uri = a.get("redirect_uri", "")
    if not redirect_uri_allowed(client, redirect_uri):
        return render("Error", "<div class=card><h1>400</h1><p>Invalid parameter: redirect_uri.</p></div>", 400)
    if a.get("response_type") != "code":
        return redirect(f"{redirect_uri}?{urlencode({'error': 'unsupported_response_type', 'state': a.get('state', '')})}")
    u = me()
    if not u:
        return redirect(f"/login?{urlencode({'return': request.full_path})}")
    # First-party clients skip the consent screen.
    code = secrets.token_urlsafe(24)
    with LOCK:
        CODES[code] = {"user_id": u["id"], "client_id": a["client_id"], "redirect_uri": redirect_uri,
                       "challenge": a.get("code_challenge"), "method": a.get("code_challenge_method", "plain"),
                       "exp": time.time() + 600, "used": False}
    sep = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{sep}{urlencode({'code': code, 'state': a.get('state', '')})}")


@app.route("/oauth/token", methods=["POST", "OPTIONS"])
def token():
    if request.method == "OPTIONS":
        return "", 204
    f = request.form
    client_id = f.get("client_id", "")
    client = CLIENTS.get(client_id)
    if not client:
        return oauth_error("invalid_client", "Unknown client.", 401)
    if client["type"] == "confidential" and not secrets.compare_digest(f.get("client_secret", ""), client["secret"]):
        return oauth_error("invalid_client", "Client authentication failed.", 401)
    if f.get("grant_type") != "authorization_code":
        return oauth_error("unsupported_grant_type", "Only authorization_code is supported.")
    with LOCK:
        rec = CODES.get(f.get("code", ""))
        if not rec or rec["used"] or rec["exp"] < time.time() or rec["client_id"] != client_id:
            return oauth_error("invalid_grant", "Invalid, expired or already used authorization code.")
        if f.get("redirect_uri", "") != rec["redirect_uri"]:
            return oauth_error("invalid_grant", "redirect_uri does not match the authorization request.")
        if rec["challenge"]:
            verifier = f.get("code_verifier", "")
            if rec["method"] == "S256":
                calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            else:
                calc = verifier
            if not secrets.compare_digest(calc, rec["challenge"]):
                return oauth_error("invalid_grant", "PKCE verification failed.")
        rec["used"] = True
        access = secrets.token_urlsafe(32)
        TOKENS[access] = {"user_id": rec["user_id"], "client_id": client_id, "exp": time.time() + 3600}
    return jsonify(access_token=access, token_type="Bearer", expires_in=3600,
                   refresh_token=secrets.token_urlsafe(32), scope="openid profile")


@app.route("/userinfo", methods=["GET", "OPTIONS"])
def userinfo():
    if request.method == "OPTIONS":
        return "", 204
    auth = request.headers.get("Authorization", "")
    tok = auth[7:] if auth.lower().startswith("bearer ") else ""
    with LOCK:
        rec = TOKENS.get(tok)
    if not rec or rec["exp"] < time.time():
        return jsonify(error="invalid_token"), 401
    u = c.get_user(rec["user_id"])
    return jsonify(sub=str(u["id"]), preferred_username=u["username"], name=u["full_name"],
                   email=u["email"], member_no=u["member_no"], tier=u["tier"],
                   travel_wallet_voucher=u["wallet_voucher"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
