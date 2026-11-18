"""Fernwood internal network services (no published ports).

One process answers for several internal hostnames, dispatched on the Host header:
  metadata.fernwood.internal      - fake cloud instance-metadata service (A2 target)
  provisioning.fernwood.internal  - internal provisioning portal (A3 target)
"""
import json

from flask import Flask, Response, request

import common as c

app = Flask(__name__)


def host():
    return request.host.split(":")[0].lower()


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def dispatch(path):
    h = host()
    if h.startswith("metadata"):
        return metadata("/" + path)
    if h.startswith("provisioning"):
        return provisioning("/" + path)
    return Response("unknown virtual host\n", 404, mimetype="text/plain")


def metadata(path):
    tree = {
        "/latest/meta-data/": "ami-id\nhostname\ninstance-id\niam/\n",
        "/latest/meta-data/hostname": "linkcheck-7f9c.fernwood.internal\n",
        "/latest/meta-data/instance-id": "i-0lab0fernwood0001\n",
        "/latest/meta-data/ami-id": "ami-0lab00000000001\n",
        "/latest/meta-data/iam/": "security-credentials/\n",
        "/latest/meta-data/iam/security-credentials/": "linkchecker-role\n",
    }
    if path in tree:
        return Response(tree[path], mimetype="text/plain")
    if path.rstrip("/") == "/latest/meta-data/iam/security-credentials/linkchecker-role":
        creds = {"Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": "ASIALABNOTAREALKEY00",
                 "SecretAccessKey": "lab-only-not-a-real-secret", "Token": c.FLAGS["A2"],
                 "Expiration": "2099-01-01T00:00:00Z",
                 "LabNote": "On a real program: stop here. Never use credentials you obtained."}
        return Response(json.dumps(creds, indent=2), mimetype="application/json")
    if path in ("/", "/latest", "/latest/"):
        return Response("meta-data/\n", mimetype="text/plain")
    return Response("Not Found\n", 404, mimetype="text/plain")


def provisioning(path):
    if path == "/":
        body = (f"<div class=card><h1>Provisioning portal (internal)</h1>"
                f"<p>Partner onboarding and SIM/device provisioning. Staff network only.</p>"
                f"<p>Lab flag: <span class=flag>{c.FLAGS['A3']}</span></p>"
                f"<p class=muted>On a real program: stop at the first internal page that answers. "
                f"GET / only - no logins, no admin paths.</p></div>")
        return Response(c.page("Provisioning", body, brand="Fernwood Internal"), mimetype="text/html")
    return Response("Not Found\n", 404, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
