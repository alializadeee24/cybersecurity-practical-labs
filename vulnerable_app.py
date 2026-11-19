# INTENTIONALLY VULNERABLE demo app (for the code review) - never deploy
import sqlite3, hashlib, pickle, subprocess
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "supersecret123"                       # V1 hardcoded secret
DB = "users.db"

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["user"], request.form["pass"]
    pw = hashlib.md5(p.encode()).hexdigest()            # V2 weak hash
    q = f"SELECT * FROM users WHERE name='{u}' AND pw='{pw}'"   # V3 SQL injection
    row = sqlite3.connect(DB).execute(q).fetchone()
    return "ok" if row else "denied"

@app.route("/search")
def search():
    return f"<h1>Results for {request.args.get('q','')}</h1>"   # V4 reflected XSS

@app.route("/ping")
def ping():
    host = request.args["host"]
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # V5 command injection

@app.route("/file")
def file():
    return open("uploads/" + request.args["name"]).read()      # V6 path traversal

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                      # V7 insecure deserialization

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                         # V8 debug + all interfaces
