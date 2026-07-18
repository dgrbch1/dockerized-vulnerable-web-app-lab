import html
import os
import sqlite3
import time
from typing import Optional

from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest


app = FastAPI(title=os.getenv("APP_NAME", "Vulnerable Web App Lab"))
STARTED_AT = time.time()

HTTP_REQUESTS = Counter(
    "vulnlab_http_requests_total",
    "Total HTTP requests received by the vulnerable lab app.",
    ["method", "path", "status"],
)
LAB_EVENTS = Counter(
    "vulnlab_events_total",
    "Security lab events triggered in the vulnerable app.",
    ["lab", "event"],
)
REQUEST_LATENCY = Histogram(
    "vulnlab_request_latency_seconds",
    "Request latency for the vulnerable lab app.",
    ["path"],
)
APP_UPTIME = Gauge(
    "vulnlab_uptime_seconds",
    "Uptime of the vulnerable lab app in seconds.",
)

EVENTS = {
    "sql_injection_attempts": 0,
    "xss_attempts": 0,
    "idor_attempts": 0,
}


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            account_balance TEXT NOT NULL,
            private_note TEXT NOT NULL
        );

        INSERT INTO users VALUES
          (1, 'alice', 'wonderland123', 'user', '$4,200', 'Alice is testing suspicious invoices.'),
          (2, 'bob', 'builder123', 'user', '$900', 'Bob reused a password in the training lab.'),
          (3, 'admin', 'admin123', 'admin', '$99,999', 'Admin account: high privilege demo user.');

        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL
        );

        INSERT INTO products VALUES
          (1, 'Firewall Policy Review', 'Check overly broad inbound rules.'),
          (2, 'Container Image Scan', 'Find vulnerable packages in container images.'),
          (3, 'Phishing Drill', 'Train users to report suspicious emails.');
        """
    )
    return conn


def layout(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>{html.escape(title)} · VulnLab</title>
          <style>
            :root {{
              color-scheme: dark;
              --bg: #07111f;
              --panel: #101d33;
              --panel2: #0b1628;
              --border: #29496c;
              --text: #eaf2ff;
              --muted: #b8c7dd;
              --blue: #2f80ed;
              --red: #ff5a70;
              --green: #57d68d;
              --yellow: #ffd166;
            }}
            * {{ box-sizing: border-box; }}
            body {{
              background:
                radial-gradient(circle at top left, rgba(47,128,237,.28), transparent 35%),
                var(--bg);
              color: var(--text);
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 28px;
            }}
            main {{ max-width: 1080px; margin: 0 auto; }}
            nav {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
            a, a:visited {{ color: #9cc7ff; }}
            .navlink, button {{
              background: var(--blue);
              border: 0;
              border-radius: 12px;
              color: white !important;
              cursor: pointer;
              display: inline-block;
              font-weight: 700;
              padding: 11px 14px;
              text-decoration: none;
            }}
            .navlink.secondary {{ background: #31445f; }}
            .card {{
              background: rgba(16, 29, 51, .94);
              border: 1px solid var(--border);
              border-radius: 18px;
              margin: 16px 0;
              padding: 22px;
              box-shadow: 0 14px 38px rgba(0,0,0,.28);
            }}
            .grid {{
              display: grid;
              gap: 14px;
              grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            }}
            input {{
              background: var(--panel2);
              border: 1px solid var(--border);
              border-radius: 12px;
              color: var(--text);
              display: block;
              margin: 8px 0 14px;
              padding: 12px;
              width: 100%;
            }}
            code, pre {{
              background: #050c16;
              border: 1px solid #223e5f;
              border-radius: 10px;
              color: #d9e8ff;
            }}
            code {{ padding: 2px 6px; }}
            pre {{ overflow: auto; padding: 14px; }}
            .danger {{ border-color: rgba(255,90,112,.65); }}
            .danger h2, .bad {{ color: var(--red); }}
            .safe {{ border-color: rgba(87,214,141,.65); }}
            .safe h2, .good {{ color: var(--green); }}
            .hint {{ color: var(--yellow); }}
            .muted {{ color: var(--muted); }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border-bottom: 1px solid #284568; padding: 10px; text-align: left; }}
          </style>
        </head>
        <body>
          <main>
            <nav>
              <a class="navlink" href="/">Home</a>
              <a class="navlink secondary" href="/lab/sql-injection">SQL Injection</a>
              <a class="navlink secondary" href="/lab/xss">XSS</a>
              <a class="navlink secondary" href="/lab/idor">IDOR</a>
              <a class="navlink secondary" href="/scoreboard">Scoreboard</a>
              <a class="navlink secondary" href="/metrics" target="_blank">Metrics</a>
            </nav>
            {body}
          </main>
        </body>
        </html>
        """
    )


@app.middleware("http")
async def observe_requests(request: Request, call_next):
    start = time.time()
    path = request.url.path
    response = await call_next(request)
    REQUEST_LATENCY.labels(path=path).observe(time.time() - start)
    HTTP_REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    return response


@app.get("/")
def home():
    return layout(
        "Home",
        """
        <section class="card">
          <h1>Vulnerable Web App Lab</h1>
          <p class="muted">
            This is a local-only Docker cybersecurity lab. It intentionally contains beginner web vulnerabilities
            so you can test, explain, and fix them in a safe environment.
          </p>
          <p><strong>Run target:</strong> <code>http://localhost:8080</code></p>
        </section>

        <section class="grid">
          <article class="card danger">
            <h2>1. SQL Injection</h2>
            <p>Test a weak login query that trusts raw user input.</p>
            <a class="navlink" href="/lab/sql-injection">Start SQLi lab</a>
          </article>
          <article class="card danger">
            <h2>2. Reflected XSS</h2>
            <p>See how unsanitized search text can become executable page content.</p>
            <a class="navlink" href="/lab/xss">Start XSS lab</a>
          </article>
          <article class="card danger">
            <h2>3. IDOR</h2>
            <p>Change an object ID in the URL and view data without authorization checks.</p>
            <a class="navlink" href="/lab/idor">Start IDOR lab</a>
          </article>
        </section>

        """,
    )


@app.get("/lab/sql-injection")
def sql_injection_form():
    return layout(
        "SQL Injection Lab",
        """
        <section class="card danger">
          <h1>Lab 1: SQL Injection</h1>
          <p>
            The vulnerable login builds a SQL query by directly joining strings. That means user input can change the
            query logic.
          </p>
          <p class="hint">Safe local test payload for the username field:</p>
          <pre>' OR '1'='1' --</pre>
          <p class="muted">Put anything in the password field. The <code>--</code> comments out the password check.</p>
          <form method="post" action="/lab/sql-injection/login">
            <label>Username</label>
            <input name="username" value="alice" />
            <label>Password</label>
            <input name="password" value="wrongpassword" />
            <button type="submit">Try vulnerable login</button>
          </form>
        </section>

        <section class="card safe">
          <h2>How to fix</h2>
          <p>Use parameterized queries instead of string-built SQL.</p>
          <pre>SELECT * FROM users WHERE username = ? AND password = ?</pre>
        </section>
        """,
    )


@app.post("/lab/sql-injection/login")
def sql_injection_login(username: str = Form(...), password: str = Form(...)):
    conn = db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    rows = conn.execute(query).fetchall()
    suspicious = "'" in username or "--" in username or " OR " in username.upper()
    if suspicious:
        EVENTS["sql_injection_attempts"] += 1
        LAB_EVENTS.labels("sql_injection", "attempt").inc()

    if rows:
        user = rows[0]
        result = f"""
        <section class="card danger">
          <h1 class="bad">Login bypassed</h1>
          <p>The vulnerable query returned a user:</p>
          <pre>id={user['id']} username={html.escape(user['username'])} role={html.escape(user['role'])}</pre>
          <p>This shows why raw SQL string building is dangerous.</p>
        </section>
        """
    else:
        result = """
        <section class="card">
          <h1>Login failed</h1>
          <p>Normal bad credentials did not return a user. Try the guided payload with the comment marker: <code>' OR '1'='1' --</code></p>
        </section>
        """

    return layout(
        "SQL Injection Result",
        result
        + f"""
        <section class="card">
          <h2>Query the app executed</h2>
          <pre>{html.escape(query)}</pre>
          <a class="navlink" href="/lab/sql-injection">Back to SQLi lab</a>
        </section>
        """,
    )


@app.get("/lab/xss")
def xss_lab(q: str = ""):
    suspicious = "<" in q and ">" in q
    if suspicious:
        EVENTS["xss_attempts"] += 1
        LAB_EVENTS.labels("xss", "attempt").inc()

    products = [
        {"name": "Firewall Policy Review", "description": "Check overly broad inbound rules."},
        {"name": "Container Image Scan", "description": "Find vulnerable packages in container images."},
        {"name": "Phishing Drill", "description": "Train users to report suspicious emails."},
    ]
    filtered = [
        product
        for product in products
        if not q or q.lower() in product["name"].lower() or q.lower() in product["description"].lower()
    ]
    rows = "".join(
        f"<tr><td>{html.escape(p['name'])}</td><td>{html.escape(p['description'])}</td></tr>" for p in filtered
    )

    return layout(
        "XSS Lab",
        f"""
        <section class="card danger">
          <h1>Lab 2: Reflected XSS</h1>
          <p>
            This page intentionally reflects your search term without escaping it in one place.
            That is the vulnerability.
          </p>
          <p class="hint">Safe local test payload:</p>
          <pre>&lt;mark&gt;XSS test&lt;/mark&gt;</pre>
          <form method="get" action="/lab/xss">
            <label>Search</label>
            <input name="q" value="{html.escape(q, quote=True)}" />
            <button type="submit">Search</button>
          </form>
        </section>

        <section class="card danger">
          <h2>Vulnerable reflected output</h2>
          <p>You searched for: <strong>{q}</strong></p>
        </section>

        <section class="card safe">
          <h2>Safe escaped output</h2>
          <p>You searched for: <strong>{html.escape(q)}</strong></p>
        </section>

        <section class="card">
          <h2>Search results</h2>
          <table>
            <tr><th>Name</th><th>Description</th></tr>
            {rows or '<tr><td colspan="2">No results</td></tr>'}
          </table>
        </section>

        <section class="card safe">
          <h2>How to fix</h2>
          <p>Escape untrusted output before rendering it into HTML. Framework template auto-escaping helps a lot.</p>
        </section>
        """,
    )


@app.get("/lab/idor")
def idor_lab():
    return layout(
        "IDOR Lab",
        """
        <section class="card danger">
          <h1>Lab 3: IDOR</h1>
          <p>
            IDOR means Insecure Direct Object Reference. The app exposes records by ID, but does not check whether
            the current user is allowed to see that record.
          </p>
          <p>Try these local URLs:</p>
          <ul>
            <li><a href="/profile/1">/profile/1</a> — Alice</li>
            <li><a href="/profile/2">/profile/2</a> — Bob</li>
            <li><a href="/profile/3">/profile/3</a> — Admin</li>
          </ul>
          <p class="hint">The bug: changing the number changes whose private data you see.</p>
        </section>

        <section class="card safe">
          <h2>How to fix</h2>
          <p>
            Do not trust object IDs alone. Check the logged-in user owns the record or has permission before returning it.
          </p>
        </section>
        """,
    )


@app.get("/profile/{user_id}")
def vulnerable_profile(user_id: int):
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    EVENTS["idor_attempts"] += 1
    LAB_EVENTS.labels("idor", "view_profile").inc()

    if not user:
        return layout("Profile Not Found", "<section class='card'><h1>No profile found</h1></section>")

    return layout(
        "Vulnerable Profile",
        f"""
        <section class="card danger">
          <h1>Vulnerable profile view</h1>
          <p class="bad">This endpoint does not check who you are. It only trusts the number in the URL.</p>
          <table>
            <tr><th>ID</th><td>{user['id']}</td></tr>
            <tr><th>Username</th><td>{html.escape(user['username'])}</td></tr>
            <tr><th>Role</th><td>{html.escape(user['role'])}</td></tr>
            <tr><th>Balance</th><td>{html.escape(user['account_balance'])}</td></tr>
            <tr><th>Private note</th><td>{html.escape(user['private_note'])}</td></tr>
          </table>
        </section>
        <section class="card safe">
          <h2>Secure direction</h2>
          <p>A real app should check: “Is the current logged-in user allowed to view user ID {user['id']}?”</p>
        </section>
        """,
    )


@app.get("/scoreboard")
def scoreboard():
    return layout(
        "Scoreboard",
        f"""
        <section class="card">
          <h1>Lab Scoreboard</h1>
          <p class="muted">These counters prove you tested the lab locally.</p>
          <table>
            <tr><th>Lab</th><th>Attempts</th></tr>
            <tr><td>SQL injection</td><td>{EVENTS['sql_injection_attempts']}</td></tr>
            <tr><td>Reflected XSS</td><td>{EVENTS['xss_attempts']}</td></tr>
            <tr><td>IDOR profile views</td><td>{EVENTS['idor_attempts']}</td></tr>
          </table>
        </section>
        """,
    )


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status_page():
    return {
        **EVENTS,
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
        "metrics_url": "/metrics",
    }


@app.get("/metrics")
def metrics():
    APP_UPTIME.set(time.time() - STARTED_AT)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
