# Vulnerable Web App Lab

This is a safe Docker cybersecurity lab that runs only on your computer.

It intentionally contains beginner web vulnerabilities so you can test them, explain them in an interview, and learn how to fix them.

## What this project tests

This project tests common web application security weaknesses:

1. SQL injection
2. Reflected cross-site scripting, also called XSS
3. IDOR, which means Insecure Direct Object Reference

It does **not** attack real websites. Everything runs locally at:

```text
http://localhost:8080
```

## Step 1: Start the lab

From PowerShell:

```powershell
cd C:\Users\wqweq\Documents\Codex\2026-07-01\cyb
docker compose up -d --build
```

Then open:

```text
http://localhost:8080
```

## Step 2: Test SQL injection

Open:

```text
http://localhost:8080/lab/sql-injection
```

Try this username:

```text
' OR '1'='1' --
```

Use any password.

What happens:

- The vulnerable app builds a SQL query using raw string input.
- Your input changes the query logic.
- The `--` comments out the password check.
- The login can return a user even without a valid password.

Interview explanation:

> “I demonstrated SQL injection by showing how raw user input can alter a database query. The fix is parameterized queries.”

## Step 3: Test reflected XSS

Open:

```text
http://localhost:8080/lab/xss
```

Search for:

```html
<mark>XSS test</mark>
```

What happens:

- The vulnerable output renders your input as HTML.
- The safe output escapes your input so it stays text.

Interview explanation:

> “I demonstrated reflected XSS by showing how unescaped user input becomes page content. The fix is output encoding and template auto-escaping.”

## Step 4: Test IDOR

Open:

```text
http://localhost:8080/lab/idor
```

Try:

```text
http://localhost:8080/profile/1
http://localhost:8080/profile/2
http://localhost:8080/profile/3
```

What happens:

- The app returns data based only on the ID in the URL.
- It does not check whether the current user has permission.

Interview explanation:

> “I demonstrated IDOR by changing an object ID in the URL and accessing another user’s record. The fix is authorization checks on every object access.”

## Step 5: Check your scoreboard

Open:

```text
http://localhost:8080/scoreboard
```

This shows which labs you tested.

Or run the automated local test:

```powershell
.\scripts\generate-traffic.ps1
```

## Optional: Prometheus metrics

The app exposes metrics here:

```text
http://localhost:8080/metrics
```

You can start the optional monitoring stack:

```powershell
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d --build
```

Then open:

- Prometheus: <http://localhost:9090>
- Grafana: <http://localhost:3000>
- Alertmanager: <http://localhost:9093>

Grafana login:

- Username: `admin`
- Password: `cyberlab`

## How to describe this project in an interview

> “I built a Dockerized vulnerable web application lab that demonstrates SQL injection, reflected XSS, and IDOR in a safe local environment. Each lab includes the vulnerable behavior, a guided test, and the secure coding fix. I also exposed Prometheus-style metrics so the project can be extended into detection and monitoring.”

## Stop the lab

```powershell
docker compose down
```
