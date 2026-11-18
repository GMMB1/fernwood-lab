"""Fernwood Travel member portal (published on :8080 behind the caching edge).

Intentional bugs:
  B1  /api/v2/bookings/<ref>/invoice skips the ownership check that /api/v2/bookings/<ref> has.
  B2  /account/profile/<anything> renders the profile, and the edge caches *.css by extension.
  A1  the login page's client-side redirect validator uses startsWith (see static/portal/app.js).
  R0  /api/v2/internal/feature-flags is referenced only by dead code in the bundle.
"""
import os
import re
import secrets

import requests
from flask import Flask, jsonify, make_response, redirect, request, session

import common as c

app = Flask(__name__, static_folder="static/portal", static_url_path="/static")
app.secret_key = os.environ.get("PORTAL_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_NAME="fw_session", SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_HTTPONLY=True)
IDP_INTERNAL = os.environ.get("IDP_INTERNAL", "http://idp:5000")
REF_RE = re.compile(r"^BK-(\d{5})$")
USER_RE = re.compile(r"^[a-z0-9_]{3,20}$")

c.init_db()


def me():
    uid = session.get("uid")
    return c.get_user(uid) if uid else None


def nav():
    lang = ("العربية", "/lang?set=ar&return=" + request.path)
    if me():
        return [("Home", "/"), ("Profile", "/account/profile"), ("Bookings", "/account/bookings"),
                lang, ("Log out", "/logout")]
    return [("Home", "/"), ("Log in", "/login"), ("Register", "/register"), lang]


def render(title, body, status=200, scripts=None, headers=None):
    resp = make_response(c.page(title, body, nav=nav(),
                                scripts=["/static/env.js", "/static/app.js"] + (scripts or [])), status)
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


# ---------------------------------------------------------------- pages
@app.get("/")
def home():
    u = me()
    hello = f"<p>Welcome back, <b>{c.e(u['full_name'])}</b>.</p>" if u else \
        "<p>Log in or register to manage your trips.</p>"
    return render("Home", f"""
      <div class=card><h1>Fly further with Fernwood</h1>{hello}
      <p class=muted>Lab target. Use fake data only. Every account you create is visible to the instructor.</p></div>""")


@app.route("/register", methods=["GET", "POST"])
def register():
    err = ""
    if request.method == "POST":
        f = request.form
        username = f.get("username", "").strip().lower()
        if not USER_RE.match(username):
            err = "Username must be 3-20 characters: a-z, 0-9, underscore."
        elif len(f.get("password", "")) < 6:
            err = "Password must be at least 6 characters."
        elif c.get_user_by_name(username):
            err = "That username is taken."
        else:
            uid = c.create_user(username, f["password"], f.get("full_name", "")[:60] or username,
                                f.get("email", "")[:80], f.get("phone", "")[:30], f.get("address", "")[:120])
            session.clear()
            session["uid"] = uid
            return redirect("/account/profile")
    return render("Register", f"""
      <div class=card><h1>Create an account</h1><p class=warn>{c.e(err)}</p>
      <form method=post>
        <label>Username</label><input name=username required>
        <label>Password</label><input name=password type=password required>
        <label>Full name (fake)</label><input name=full_name placeholder="Test User One">
        <label>Email (fake)</label><input name=email placeholder="one@example.test">
        <label>Phone (fake)</label><input name=phone placeholder="+1 555 0000">
        <label>Address (fake)</label><input name=address placeholder="1 Test Street">
        <p><button>Register</button></p></form></div>""")


@app.get("/login")
def login_page():
    return render("Log in", """
      <div class=card><h1>Log in</h1>
      <form id=login-form>
        <label>Username</label><input name=username autocomplete=username required>
        <label>Password</label><input name=password type=password autocomplete=current-password required>
        <p><button>Log in</button> <span id=login-error class=warn></span></p></form>
      <hr><p><button type=button id=sso-button>Sign in with Fernwood ID</button></p></div>""")


@app.get("/callback")
def callback_page():
    return render("Signing in", """<div class=card><h1>Signing you in...</h1>
      <p id=sso-status class=muted>Exchanging the authorization code.</p></div>""")


# Language switcher. Saves the choice, then app.js sends the user back to "return".
# BUG (C1): app.js only blocks values that start with http, so //host (open redirect)
# and javascript: (XSS) both pass.
@app.get("/lang")
def lang():
    choice = "ar" if request.args.get("set") == "ar" else "en"
    label = "العربية" if choice == "ar" else "English"
    resp = render("Language", f"""<div class=card><h1>{label}</h1>
      <p id=lang-status class=muted>Language saved. Taking you back...</p></div>""")
    resp.set_cookie("fw_lang", choice, samesite="Lax")
    return resp


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


def profile_html(u):
    rows = [("Name", u["full_name"]), ("Member no.", u["member_no"]), ("Tier", u["tier"]),
            ("Miles", u["miles"]), ("Email", u["email"]), ("Phone", u["phone"]),
            ("Address", u["address"]), ("Passport number", u["passport"])]
    body = "".join(f"<tr><th>{c.e(k)}</th><td>{c.e(str(v or '-'))}</td></tr>" for k, v in rows)
    return f"<div class=card><h1>My profile</h1><table>{body}</table></div>"


# The route accepts any trailing segment, like many MVC frameworks do.
@app.get("/account/profile")
@app.get("/account/profile/<path:anything>")
def profile(anything=None):
    u = me()
    if not u:
        return render("Sign in required",
                      "<div class=card><h1>401 - Sign in required</h1><p><a href='/login'>Log in</a></p></div>",
                      status=401, headers={"Cache-Control": "private, no-store"})
    return render("Profile", profile_html(u), headers={"Cache-Control": "private, no-store"})


@app.get("/account/bookings")
def bookings_page():
    if not me():
        return redirect("/login?next=/account/bookings")
    return render("Bookings", """
      <div class=card><h1>My bookings</h1><table id=bookings><tr><td class=muted>Loading...</td></tr></table></div>
      <div class=card><h2>New booking</h2><form id=booking-form>
        <label>Route</label><select name=route>
          <option>LHR -> ATH</option><option>DUB -> JFK</option><option>MAN -> FCO</option><option>BRS -> AMS</option></select>
        <label>Travel date</label><input name=travel_date type=date required>
        <p><button>Book</button></p></form></div>""")


# ------------------------------------------------------------------ api
def require_user():
    u = me()
    if not u:
        return None, (jsonify(error="authentication required"), 401)
    return u, None


def parse_ref(ref):
    m = REF_RE.match(ref or "")
    return int(m.group(1)) if m else None


def booking_json(b, full=False):
    d = {"ref": f"BK-{b['id']}", "route": b["route"], "travel_date": b["travel_date"],
         "passenger": b["passenger"]}
    if full:
        d.update(card_last4=b["card_last4"], amount=b["amount"])
    return d


@app.get("/api/me")
def api_me():
    u, err = require_user()
    if err:
        return err
    return jsonify(username=u["username"], member_no=u["member_no"], tier=u["tier"])


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    u = c.get_user_by_name(str(data.get("username", "")).strip().lower())
    if not u or not c.check_pw(str(data.get("password", "")), u["pw"]):
        return jsonify(error="invalid username or password"), 401
    session.clear()
    session["uid"] = u["id"]
    return jsonify(ok=True)


@app.post("/api/login/sso")
def api_login_sso():
    token = (request.get_json(silent=True) or {}).get("access_token", "")
    try:
        r = requests.get(f"{IDP_INTERNAL}/userinfo", headers={"Authorization": f"Bearer {token}"}, timeout=4)
    except requests.RequestException:
        return jsonify(error="identity provider unavailable"), 502
    if r.status_code != 200:
        return jsonify(error="invalid access token"), 401
    u = c.get_user_by_name(r.json().get("preferred_username", ""))
    if not u:
        return jsonify(error="unknown user"), 401
    session.clear()
    session["uid"] = u["id"]
    return jsonify(ok=True)


@app.get("/api/v2/bookings")
def api_bookings():
    u, err = require_user()
    if err:
        return err
    rows = c.q("SELECT * FROM bookings WHERE owner_id=? ORDER BY id", (u["id"],))
    return jsonify(bookings=[booking_json(b) for b in rows])


@app.post("/api/v2/bookings")
def api_create_booking():
    u, err = require_user()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    route = str(data.get("route", "LHR -> ATH"))[:20]
    date = str(data.get("travel_date", "2027-01-01"))[:10]
    bid = c.x("INSERT INTO bookings(owner_id,route,travel_date,passenger,card_last4,amount,corporate_account,created)"
              " VALUES(?,?,?,?,?,?,?,strftime('%s','now'))",
              (u["id"], route, date, u["full_name"], f"{secrets.randbelow(10000):04d}",
               f"{100 + secrets.randbelow(900)}.00 EUR", "-"))
    return jsonify(ref=f"BK-{bid}"), 201


@app.get("/api/v2/bookings/<ref>")
def api_booking(ref):
    u, err = require_user()
    if err:
        return err
    bid = parse_ref(ref)
    if bid is None:
        return jsonify(error="invalid booking reference format"), 400
    b = c.q("SELECT * FROM bookings WHERE id=?", (bid,), one=True)
    if not b:
        return jsonify(error="booking not found"), 404
    if b["owner_id"] != u["id"]:
        return jsonify(error="you do not have access to this booking"), 403
    return jsonify(booking_json(b, full=True))


@app.get("/api/v2/bookings/<ref>/invoice")
def api_invoice(ref):
    # BUG (B1): the invoice path was added later by another team and only checks
    # that *someone* is logged in, not that they own the booking.
    u, err = require_user()
    if err:
        return err
    bid = parse_ref(ref)
    if bid is None:
        return jsonify(error="invalid booking reference format"), 400
    b = c.q("SELECT * FROM bookings WHERE id=?", (bid,), one=True)
    if not b:
        return jsonify(error="booking not found"), 404
    owner = c.get_user(b["owner_id"])
    return jsonify(invoice_no=f"INV-{b['id']}", booking=f"BK-{b['id']}", billed_to=owner["full_name"],
                   billing_address=owner["address"], email=owner["email"], route=b["route"],
                   travel_date=b["travel_date"], amount=b["amount"], card_last4=b["card_last4"],
                   corporate_account=b["corporate_account"])


@app.get("/api/v2/internal/feature-flags")
def api_feature_flags():
    u, err = require_user()
    if err:
        return err
    return jsonify(
        lab_flag=c.FLAGS["R0"],
        note="Recon reward. Finding a hidden route is a test plan, not a vulnerability.",
        flags={"new_checkout": False, "sso_button": True, "invoice_v2": True},
        partner_gateway={"public_prefix": "/partner/", "port": 8083,
                         "upstreams_pending_migration": ["crm.fernwood.internal",
                                                         "provisioning.fernwood.internal",
                                                         "sso-legacy.fernwood.internal"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
