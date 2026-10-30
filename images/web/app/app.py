import json
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, Response, g, render_template, request, abort
from markupsafe import Markup

APP_MODE = os.environ.get("APP_MODE", "vulnerable")
DB_PATH = "/tmp/app.db"
FILES_DIR = Path("/app/files").resolve()
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "10.10.10.6")

app = Flask(__name__)


def seed():
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT);
        INSERT INTO users (username, password, role) VALUES
            ('admin', 'S3cr3t-Admin-2026', 'admin'),
            ('alice', 'alice123', 'user'),
            ('bob', 'hunter2', 'user');
        INSERT INTO products (name, description) VALUES
            ('Router R100', 'Edge router for small offices'),
            ('Switch S24', '24 port managed switch'),
            ('Firewall FW1', 'Stateful packet filter appliance'),
            ('Access Point A5', 'Dual band wireless access point');
        """
    )
    con.commit()
    con.close()
    print("database seeded", flush=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if request.remote_addr == TRUSTED_PROXY and xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "-"


@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.after_request
def log_request(resp):
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "src_ip": client_ip(),
        "method": request.method,
        "path": request.full_path.rstrip("?"),
        "status": resp.status_code,
        "mode": APP_MODE,
    }
    event = g.pop("event", None)
    if event:
        entry["event"] = event
    print(json.dumps(entry), flush=True)
    return resp


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    con = get_db()
    if APP_MODE == "secure":
        row = con.execute(
            "SELECT username, role FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
    else:
        query = (
            "SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = con.execute(query).fetchone()
    if row:
        g.event = f"login_success:{row['username']}"
        return render_template("result.html", title="Welcome", message=f"Logged in as {row['username']} ({row['role']})")
    g.event = f"login_failed:{username}"
    return render_template("result.html", title="Login failed", message="Invalid credentials"), 401


@app.get("/search")
def search():
    term = request.args.get("q", "")
    con = get_db()
    if APP_MODE == "secure":
        rows = con.execute(
            "SELECT name, description FROM products WHERE name LIKE ?",
            (f"%{term}%",),
        ).fetchall()
        shown = term
    else:
        query = f"SELECT name, description FROM products WHERE name LIKE '%{term}%'"
        rows = con.execute(query).fetchall()
        shown = Markup(term)
    return render_template("search.html", term=shown, rows=rows)


@app.get("/download")
def download():
    name = request.args.get("file", "")
    if APP_MODE == "secure":
        target = (FILES_DIR / name).resolve()
        if os.path.commonpath([target, FILES_DIR]) != str(FILES_DIR) or not target.is_file():
            g.event = f"download_denied:{name}"
            abort(404)
    else:
        target = Path(FILES_DIR / name)
        if not target.exists() or not target.is_file():
            g.event = f"download_missing:{name}"
            abort(404)
    g.event = f"download:{name}"
    with open(target, "rb") as fh:
        data = fh.read()
    return Response(data, mimetype="text/plain")


seed()
