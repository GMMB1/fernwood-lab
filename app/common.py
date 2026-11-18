"""Shared helpers for the Fernwood Travel training lab.

Everything in this lab is intentionally vulnerable. It is a teaching target for a
classroom, not a reference implementation. Never expose it to the internet.
"""
import hashlib
import html
import os
import secrets
import sqlite3
import time

DB_PATH = os.environ.get("FW_DB", "/data/fernwood.db")
ALICE_PASSWORD = os.environ.get("ALICE_PASSWORD", "alice-lab-password-change-me")

# One flag per station. A flag is only reachable once the *impact* is achieved,
# never for merely observing the bug.
FLAGS = {
    "R0": "FW{the_bundle_is_the_spec}",
    "A1": "FW{startswith_is_not_a_url_parser}",
    "A2": "FW{redirects_skip_the_ssrf_guard}",
    "A3": "FW{read_the_error_as_structure}",
    "B1": "FW{one_object_two_paths_one_check}",
    "B2": "FW{the_cdn_trusted_the_extension}",
    "B3": "FW{path_only_redirect_uri_no_pkce}",
    "C1": "FW{a_redirect_to_javascript_is_xss}",
}

STATIONS = {
    "R0": "Recon: the bundle is the spec",
    "A1": "Open redirect: a validator that is not a URL parser",
    "A2": "SSRF: the guard only checks the first URL",
    "A3": "Proxy path concatenation (stretch)",
    "B1": "IDOR: one object, two paths",
    "B2": "Web cache deception",
    "B3": "OAuth: path-only redirect_uri, public client, no PKCE",
    "C1": "Chain: open redirect to XSS (language switcher)",
}


# --------------------------------------------------------------------------- db
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def q(sql, args=(), one=False):
    conn = connect()
    try:
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    if one:
        return rows[0] if rows else None
    return rows


def x(sql, args=()):
    conn = connect()
    try:
        cur = conn.execute(sql, args)
        return cur.lastrowid
    finally:
        conn.close()


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 60000).hex()
    return f"{salt}${digest}"


def check_pw(pw, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return secrets.compare_digest(hash_pw(pw, salt), stored)


def member_no():
    return "FW" + "".join(secrets.choice("0123456789") for _ in range(8))


def init_db():
    """Create tables and seed demo data exactly once, even if several services start together."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw TEXT NOT NULL,
            full_name TEXT, email TEXT, phone TEXT, address TEXT,
            member_no TEXT, tier TEXT, miles INTEGER,
            passport TEXT, wallet_voucher TEXT, created REAL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS bookings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL, route TEXT, travel_date TEXT,
            passenger TEXT, card_last4 TEXT, amount TEXT,
            corporate_account TEXT, created REAL)""")
        seeded = conn.execute("SELECT 1 FROM users WHERE username='alice'").fetchone()
        if not seeded:
            people = [
                ("bob", "Bob Marsh", "bob@example.test", "+1 555 0101", "12 Harbor Rd, Portsmouth", "Silver", 18200),
                ("carol", "Carol Nyberg", "carol@example.test", "+1 555 0102", "4 Elm Close, Leeds", "Blue", 2300),
                ("alice", "Alice Harrow", "alice@example.test", "+1 555 0199", "77 Quay Street, Galway", "Gold", 96410),
                ("dave", "Dave Okafor", "dave@example.test", "+1 555 0103", "9 Mill Lane, Bath", "Blue", 640),
            ]
            ids = {}
            for u, name, email, phone, addr, tier, miles in people:
                pw = ALICE_PASSWORD if u == "alice" else secrets.token_urlsafe(16)
                passport = FLAGS["B2"] if u == "alice" else "P" + "".join(secrets.choice("0123456789") for _ in range(8))
                voucher = FLAGS["B3"] if u == "alice" else "FWV-" + secrets.token_hex(4).upper()
                cur = conn.execute(
                    "INSERT INTO users(username,pw,full_name,email,phone,address,member_no,tier,miles,passport,wallet_voucher,created)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (u, hash_pw(pw), name, email, phone, addr, member_no(), tier, miles, passport, voucher, time.time()))
                ids[u] = cur.lastrowid
            bookings = [
                (10001, "bob", "LHR -> ATH", "2026-12-02", "Bob Marsh", "4417", "312.40 EUR", "CORP-" + secrets.token_hex(3).upper()),
                (10002, "carol", "MAN -> FCO", "2026-12-09", "Carol Nyberg", "0921", "188.00 EUR", "-"),
                (10003, "bob", "ATH -> LHR", "2026-12-16", "Bob Marsh", "4417", "301.10 EUR", "CORP-" + secrets.token_hex(3).upper()),
                (10004, "alice", "DUB -> JFK", "2027-01-11", "Alice Harrow", "7781", "1240.00 EUR", FLAGS["B1"]),
                (10005, "carol", "FCO -> MAN", "2026-12-20", "Carol Nyberg", "0921", "176.50 EUR", "-"),
                (10006, "dave", "BRS -> AMS", "2027-02-03", "Dave Okafor", "3304", "98.00 EUR", "-"),
            ]
            for bid, owner, route, date, pax, last4, amount, corp in bookings:
                conn.execute(
                    "INSERT INTO bookings(id,owner_id,route,travel_date,passenger,card_last4,amount,corporate_account,created)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (bid, ids[owner], route, date, pax, last4, amount, corp, time.time()))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_user(uid):
    return q("SELECT * FROM users WHERE id=?", (uid,), one=True)


def get_user_by_name(username):
    return q("SELECT * FROM users WHERE username=?", (username,), one=True)


def create_user(username, password, full_name, email, phone, address):
    return x(
        "INSERT INTO users(username,pw,full_name,email,phone,address,member_no,tier,miles,passport,wallet_voucher,created)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (username, hash_pw(password), full_name, email, phone, address, member_no(), "Blue", 0,
         "not on file", "FWV-" + secrets.token_hex(4).upper(), time.time()))


# ----------------------------------------------------------------------- html
e = html.escape

BASE_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2433;--muted:#5b6475;--line:#dfe3ea;--brand:#1f6f5c;--warn:#a5361b}
@media (prefers-color-scheme:dark){:root{--bg:#12161d;--card:#1a2029;--ink:#e6e9ef;--muted:#9aa3b2;--line:#2c3440;--brand:#4fb393;--warn:#ef8a6b}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{background:var(--card);border-bottom:1px solid var(--line);padding:12px 20px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
header b{color:var(--brand);font-size:17px}header a{color:var(--ink);text-decoration:none}header a:hover{text-decoration:underline}
main{max-width:880px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
input,select,textarea{font:inherit;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);width:100%;max-width:460px}
button{font:inherit;padding:7px 14px;border:0;border-radius:6px;background:var(--brand);color:#fff;cursor:pointer}
label{display:block;margin:10px 0 4px;color:var(--muted);font-size:13px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}pre{background:var(--bg);border:1px solid var(--line);padding:10px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.muted{color:var(--muted)}.warn{color:var(--warn)}.flag{font-family:ui-monospace,monospace;font-weight:700;color:var(--brand)}
details{margin:6px 0}summary{cursor:pointer;color:var(--brand)}
"""


def page(title, body, brand="Fernwood Travel", nav=None, scripts=None, extra_css=""):
    nav = nav or []
    links = "".join(f'<a href="{e(h)}">{e(t)}</a>' for t, h in nav)
    js = "".join(f'<script src="{e(s)}"></script>' for s in (scripts or []))
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)} - {e(brand)}</title><style>{BASE_CSS}{extra_css}</style></head>"
            f"<body><header><b>{e(brand)}</b>{links}</header><main>{body}</main>{js}</body></html>")
