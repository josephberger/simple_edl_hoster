import os
import re
import secrets
import sqlite3
import fcntl
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    session,
    Response,
    flash,
    abort,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
DB_FILE = os.path.join(BASE_DIR, "edl_users.db")

# Every *.txt file in FEED_DIR is a feed, served at /edl/<name>.txt
FEED_DIR = os.path.abspath(os.path.join(BASE_DIR, os.environ.get("EDL_FEED_DIR", "feeds")))
FEED_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
DEFAULT_FEED = "urls"

# Set FLASK_SECRET_KEY in production. Without it, a random key is generated per
# process (sessions are invalidated on restart and differ between workers).
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set EDL_COOKIE_SECURE=1 once the UI is served over HTTPS
    SESSION_COOKIE_SECURE=os.environ.get("EDL_COOKIE_SECURE") == "1",
)

# Behind nginx: trust X-Forwarded-For/Proto/Host from exactly one proxy hop
if os.environ.get("EDL_BEHIND_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

@contextmanager
def feed_lock():
    """Cross-process lock (gunicorn runs several workers), so appends don't interleave."""
    with open(os.path.join(BASE_DIR, ".feed.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

# Regex tailored for PAN-OS URL objects:
# - Supports leftmost wildcard (*.domain.com or domain.com)
# - Validates standard domain labels & TLD
# - Allows paths, ports, or trailing slashes (*.badsite.com:8080/phish)
PAN_URL_PATTERN = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?(/\S*)?"
)

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token")

def init_db():
    with closing(get_db()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            """
        )
        conn.commit()

        # Seed an initial admin user with a random password if the table is empty
        cur = conn.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            password = os.environ.get("EDL_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("admin", generate_password_hash(password, method="pbkdf2:sha256")),
            )
            conn.commit()
            print(f"[INFO] Seeded user 'admin' with password: {password}")

    os.makedirs(FEED_DIR, exist_ok=True)
    if not list_feeds():
        with open(feed_path(DEFAULT_FEED), "w", encoding="utf-8") as f:
            f.write("# Palo Alto Networks Custom EDL URL Feed\n")

def list_feeds():
    return sorted(
        name[:-4] for name in os.listdir(FEED_DIR)
        if name.endswith(".txt") and FEED_NAME_PATTERN.fullmatch(name[:-4])
    )

def feed_path(name):
    """Path of an existing feed, or None if the name is invalid/unknown (blocks traversal)."""
    if not FEED_NAME_PATTERN.fullmatch(name):
        return None
    return os.path.join(FEED_DIR, name + ".txt")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- Inline Templates ---

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Simple EDL Hoster - Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 2rem; border-radius: 8px; width: 340px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); border: 1px solid #334155; }
        h2 { margin-top: 0; margin-bottom: 1.5rem; text-align: center; font-size: 1.25rem; font-weight: 600; }
        label { font-size: 0.875rem; color: #94a3b8; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.65rem; margin: 0.4rem 0 1rem 0; border: 1px solid #334155; border-radius: 4px; background: #0f172a; color: #fff; box-sizing: border-box; }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #0284c7; }
        button { width: 100%; padding: 0.65rem; background: #0284c7; border: none; border-radius: 4px; color: #fff; font-weight: 600; cursor: pointer; transition: background 0.15s; }
        button:hover { background: #0369a1; }
        .error { color: #f87171; font-size: 0.875rem; margin-bottom: 1rem; text-align: center; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Simple EDL Hoster</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}<div class="error">{{ messages[0] }}</div>{% endif %}
        {% endwith %}
        <form method="POST">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <label>Username</label>
            <input type="text" name="username" required autofocus>
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

SUBMIT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Simple EDL Hoster</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; max-width: 850px; margin: 0 auto; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; border: 1px solid #334155; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: 0.75rem; border-bottom: 1px solid #334155; }
        input[type="text"] { width: 100%; padding: 0.75rem; border: 1px solid #334155; border-radius: 4px; background: #0f172a; color: #fff; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.95rem; }
        input[type="text"]:focus { outline: none; border-color: #0284c7; }
        button { padding: 0.65rem 1.25rem; background: #0284c7; border: none; border-radius: 4px; color: #fff; font-weight: 600; cursor: pointer; margin-top: 1rem; transition: background 0.15s; }
        button:hover { background: #0369a1; }
        .msg { padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }
        .msg.success { background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }
        .msg.error { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
        pre { background: #0f172a; padding: 1rem; border-radius: 4px; border: 1px solid #334155; overflow-x: auto; font-size: 0.85rem; line-height: 1.5; color: #cbd5e1; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        select { padding: 0.4rem; border-radius: 4px; background: #0f172a; color: #fff; border: 1px solid #334155; }
        .hint { font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem; margin-bottom: 1rem; }
        code { background: #0f172a; padding: 0.15rem 0.35rem; border-radius: 3px; border: 1px solid #334155; color: #38bdf8; }
    </style>
</head>
<body>
    <header>
        <div>Authenticated: <strong>{{ username }}</strong></div>
        <div>
            <a href="{{ url_for('get_edl_feed', name=feed) }}" target="_blank">Raw Feed (Firewall Target)</a> | 
            <a href="{{ url_for('logout') }}">Sign Out</a>
        </div>
    </header>

    <div class="card">
        <h3 style="margin-top:0;">Append Entry to URL EDL</h3>
        <form method="GET" style="margin-bottom:1rem;">
            <label class="hint">Feed:</label>
            <select name="feed" onchange="this.form.submit()">
                {% for f in feeds %}<option value="{{ f }}" {{ "selected" if f == feed }}>{{ f }}.txt</option>{% endfor %}
            </select>
        </form>
        <p class="hint">
            Input accepts FQDNs, URLs with path, and leftmost wildcards.<br>
            Examples: <code>*.threatdomain.com</code>, <code>badactor.org/phish/</code>, <code>sub.domain.co.uk:8443</code>
        </p>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="msg {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <input type="hidden" name="feed" value="{{ feed }}">
            <input type="text" name="url_entry" placeholder="*.malicious-domain.com" required autocomplete="off">
            <button type="submit">Append Entry</button>
        </form>
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Current Feed Preview: {{ feed }}.txt (Last 15 Lines)</h3>
        <pre>{{ recent_entries if recent_entries else "No entries currently recorded." }}</pre>
    </div>
</body>
</html>
"""

# --- Route Handlers ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with closing(get_db()) as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()  # drop pre-login state (fixation) and rotate CSRF token
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("submit"))

        flash("Invalid username or password.")
    return render_template_string(LOGIN_HTML)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def submit():
    feeds = list_feeds()
    feed = request.form.get("feed") or request.args.get("feed") or (DEFAULT_FEED if DEFAULT_FEED in feeds else feeds[0])
    if feed not in feeds:
        abort(404)
    path = feed_path(feed)

    if request.method == "POST":
        raw_url = request.form.get("url_entry", "").strip()

        # Sanitize common input issues: strip leading schemes (http://, https://) and trailing whitespace
        clean_url = re.sub(r"^https?://", "", raw_url, flags=re.IGNORECASE).strip()

        if not PAN_URL_PATTERN.fullmatch(clean_url):
            flash("Invalid URL format. Please provide a valid domain/path (e.g. *.domain.com or test.com/path).", "error")
        else:
            # ISO 8601 UTC timestamp
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            # PAN-OS EDL format requirement:
            # Space followed by # tells PAN-OS everything after is a comment and will be ignored by the engine.
            edl_line = f"{clean_url} # added by {session['username']} on {now_utc}\n"

            with feed_lock():
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                existing = {line.split(" #", 1)[0].strip().lower() for line in content.splitlines()}
                needs_newline = bool(content) and not content.endswith("\n")
                if clean_url.lower() in existing:
                    flash(f"Entry already present in {feed}.txt: {clean_url}", "error")
                    return redirect(url_for("submit", feed=feed))
                with open(path, "a", encoding="utf-8") as f:
                    f.write(("\n" if needs_newline else "") + edl_line)

            flash(f"Added to {feed}.txt: {clean_url}", "success")
            return redirect(url_for("submit", feed=feed))

    with open(path, "r", encoding="utf-8") as f:
        recent = "".join(f.readlines()[-15:])

    return render_template_string(
        SUBMIT_HTML,
        username=session.get("username"),
        recent_entries=recent,
        feeds=feeds,
        feed=feed,
    )

@app.route("/edl/<name>.txt", methods=["GET"])
def get_edl_feed(name):
    """
    Public, unauthenticated raw endpoint queried by Palo Alto Networks firewalls.
    One endpoint per feed file: /edl/<name>.txt serves FEED_DIR/<name>.txt.
    """
    path = feed_path(name)
    if not path or not os.path.isfile(path):
        abort(404)

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    return Response(
        content,
        mimetype="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

# Initialise at import time so WSGI servers (gunicorn) get the DB and feed file too.
init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("EDL_HOST", "0.0.0.0"),
        port=int(os.environ.get("EDL_PORT", "5500")),
        debug=False,
    )
