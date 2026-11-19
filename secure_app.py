# Remediated version of vulnerable_app.py
import os, sqlite3, subprocess, json, ipaddress
from pathlib import Path
from flask import Flask, request, abort
from markupsafe import escape
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET_KEY"]                   # F1 secret from env
DB = "users.db"
UPLOADS = Path("uploads").resolve()

@app.after_request
def headers(r):                                                 # F9 security headers
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    return r

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("user", ""), request.form.get("pass", "")
    row = sqlite3.connect(DB).execute(
        "SELECT pw FROM users WHERE name = ?", (u,)).fetchone()  # F3 parameterised query
    ok = row and check_password_hash(row[0], p)                  # F2 salted scrypt hash
    return ("ok", 200) if ok else ("denied", 401)

@app.route("/search")
def search():
    return f"<h1>Results for {escape(request.args.get('q', ''))}</h1>"   # F4 output encoding

@app.route("/ping")
def ping():
    try:
        host = str(ipaddress.ip_address(request.args.get("host", "")))  # F5 strict validation
    except ValueError:
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True,
                         text=True, timeout=5, shell=False)             # no shell
    return out.stdout

@app.route("/file")
def file():
    target = (UPLOADS / request.args.get("name", "")).resolve()
    if UPLOADS not in target.parents or not target.is_file():           # F6 canonicalisation
        abort(404)
    return target.read_text()

@app.route("/load", methods=["POST"])
def load():
    try:
        return str(json.loads(request.data))                            # F7 safe data format
    except ValueError:
        abort(400)

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)                              # F8
