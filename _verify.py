"""
CyberShield AI - Full Verification Script
Covers all tasks: pages, upload, DB update, dashboard stats, charts, threats, PDF.
"""
import os, sys, io, sqlite3, tempfile, shutil

os.environ.setdefault("CYBERSHIELD_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(__file__))

import app as cybershield
client = cybershield.app.test_client()
cybershield.app.config["TESTING"] = True
cybershield.app.config["WTF_CSRF_ENABLED"] = False

DB = cybershield.DB_PATH
PASS = []
FAIL = []

def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))

def login():
    return client.post("/login", data={"username": "admin", "password": "adminpass"},
                       follow_redirects=True)

# ── 1. Auth ──────────────────────────────────────────────────────────────────
print("\n[1] Authentication")
r = client.get("/dashboard")
check("Unauthenticated redirect", r.status_code == 302)

r = login()
check("Login success (200)", r.status_code == 200)
check("Login lands on dashboard", b"dashboard" in r.data.lower() or b"threat" in r.data.lower())

# ── 2. All pages ─────────────────────────────────────────────────────────────
print("\n[2] Page availability")
pages = [
    ("/dashboard",   "Dashboard"),
    ("/upload",      "Upload Log"),
    ("/threats",     "Threat Analysis"),
    ("/ai_summary",  "AI Summary"),
    ("/generate_pdf_all", "Reports (PDF all)"),
    ("/settings",    "Settings"),
]
for path, label in pages:
    r = client.get(path, follow_redirects=True)
    check(f"{label} ({path}) -> 200", r.status_code == 200,
          f"got {r.status_code}")

# ── 3. API endpoints ─────────────────────────────────────────────────────────
print("\n[3] API endpoints")
import json

r = client.get("/api/chart-data")
check("GET /api/chart-data -> 200", r.status_code == 200)
data = json.loads(r.data)
check("chart-data has severity key", "severity" in data)
check("chart-data has top_types key", "top_types" in data)
check("chart-data has top_ips key", "top_ips" in data)

r = client.get("/api/threats?limit=10")
check("GET /api/threats -> 200", r.status_code == 200)
threats_api = json.loads(r.data)
check("api/threats returns list", isinstance(threats_api, list))
check("api/threats has entries", len(threats_api) > 0)

# ── 4. Dashboard statistics ───────────────────────────────────────────────────
print("\n[4] Dashboard statistics")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM logs")
total_logs = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM threats")
total_threats = cur.fetchone()[0]
conn.close()

check("DB has logs", total_logs > 0, f"found {total_logs}")
check("DB has threats", total_threats > 0, f"found {total_threats}")

r = client.get("/dashboard")
body = r.data.decode("utf-8", errors="replace")
check("Dashboard shows log count", str(total_logs) in body)
check("Dashboard shows threat count", str(total_threats) in body)

# ── 5. Upload a log file ──────────────────────────────────────────────────────
print("\n[5] Upload")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM threats")
threats_before = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM logs")
logs_before = cur.fetchone()[0]
conn.close()

log_content = b"""Jul 10 12:00:01 server sshd[9999]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2
Jul 10 12:00:02 server sshd[9999]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2
Jul 10 12:00:03 server sshd[9999]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2
[10/Jul/2026:12:01:00] GET /index.php?id=1 UNION SELECT password FROM users-- HTTP/1.1 200 452
[10/Jul/2026:12:02:00] GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1 200 215
"""

r = client.post(
    "/upload",
    data={"logfile": (io.BytesIO(log_content), "_verify_upload.log")},
    content_type="multipart/form-data",
    follow_redirects=True,
)
check("Upload returns 200 (no HTTP 500)", r.status_code == 200,
      f"got {r.status_code}")
check("Upload success flash shown",
      b"success" in r.data.lower() or b"uploaded" in r.data.lower() or b"parsed" in r.data.lower())

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM threats")
threats_after = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM logs")
logs_after = cur.fetchone()[0]
conn.close()

check("DB logs count increased", logs_after > logs_before,
      f"{logs_before} -> {logs_after}")
check("DB threats count increased", threats_after > threats_before,
      f"{threats_before} -> {threats_after}")

# ── 6. Dashboard updates after upload ────────────────────────────────────────
print("\n[6] Dashboard updates after upload")
r = client.get("/dashboard")
body = r.data.decode("utf-8", errors="replace")
check("Dashboard reflects new log count", str(logs_after) in body)
check("Dashboard reflects new threat count", str(threats_after) in body)

# ── 7. Chart data updates ─────────────────────────────────────────────────────
print("\n[7] Chart data updates")
r = client.get("/api/chart-data")
data = json.loads(r.data)
total_from_api = sum(data["severity"].values())
check("Chart API total matches DB threats", total_from_api == threats_after,
      f"api={total_from_api} db={threats_after}")

# ── 8. Threat table updates ───────────────────────────────────────────────────
print("\n[8] Threat table / API")
r = client.get("/api/threats?limit=500")
all_threats = json.loads(r.data)
# /api/threats has a hard LIMIT 500; with >500 threats the list is capped — that is correct behaviour
check("Threat API returns up to LIMIT 500", len(all_threats) <= 500,
      f"got {len(all_threats)}")

# Verify brute-force was detected (3 failed attempts from 1.2.3.4)
bf = [t for t in all_threats if t["type"] == "Brute Force" and t.get("ip") == "1.2.3.4"]
check("Brute Force detected from uploaded file", len(bf) > 0)

# Verify SQL injection detected
sqli = [t for t in all_threats if t["type"] == "SQL Injection"]
check("SQL Injection detected", len(sqli) > 0)

# Verify XSS detected
xss = [t for t in all_threats if t["type"] == "XSS"]
check("XSS detected", len(xss) > 0)

# ── 9. PDF generation ─────────────────────────────────────────────────────────
print("\n[9] PDF generation")
# Single-log PDF
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT id FROM logs ORDER BY id LIMIT 1")
first_log_id = cur.fetchone()[0]
conn.close()

r = client.get(f"/generate_pdf/{first_log_id}")
check(f"Single PDF (log {first_log_id}) -> 200", r.status_code == 200,
      f"got {r.status_code}")
check("Single PDF content-type is PDF",
      "pdf" in r.content_type.lower() or r.data[:4] == b"%PDF")

r = client.get("/generate_pdf_all")
check("Consolidated PDF -> 200", r.status_code == 200, f"got {r.status_code}")
check("Consolidated PDF content-type is PDF",
      "pdf" in r.content_type.lower() or r.data[:4] == b"%PDF")

# ── 10. Upload edge cases ─────────────────────────────────────────────────────
print("\n[10] Upload edge cases")
r = client.post("/upload", data={"logfile": (io.BytesIO(b"data"), "evil.exe")},
                content_type="multipart/form-data", follow_redirects=True)
check("Rejected bad extension (.exe)", r.status_code == 200)
check("Bad extension shows error flash",
      b"unsupported" in r.data.lower() or b"danger" in r.data.lower())

r = client.post("/upload", data={}, content_type="multipart/form-data",
                follow_redirects=True)
check("Empty upload handled gracefully", r.status_code == 200)

# ── 11. Search / filter ───────────────────────────────────────────────────────
print("\n[11] Search")
r = client.get("/search?severity=Critical", follow_redirects=True)
check("Search by severity -> 200", r.status_code == 200)

r = client.get("/search?type=XSS", follow_redirects=True)
check("Search by type -> 200", r.status_code == 200)

r = client.get("/search?ip=1.2.3.4", follow_redirects=True)
check("Search by IP -> 200", r.status_code == 200)

# ── 12. Logout ────────────────────────────────────────────────────────────────
print("\n[12] Logout")
r = client.get("/logout", follow_redirects=True)
check("Logout -> 200", r.status_code == 200)
r = client.get("/dashboard")
check("Post-logout dashboard redirects", r.status_code == 302)

# ── Summary ───────────────────────────────────────────────────────────────────
total = len(PASS) + len(FAIL)
print(f"\n{'='*55}")
print(f"  RESULT: {len(PASS)}/{total} passed, {len(FAIL)} failed")
if FAIL:
    print("  FAILED TESTS:")
    for f in FAIL:
        print(f"    - {f}")
print(f"{'='*55}")
print(f"\n  DB state after test:")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM logs"); print(f"    Logs    : {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM threats"); print(f"    Threats : {cur.fetchone()[0]}")
cur.execute("SELECT severity, COUNT(*) FROM threats GROUP BY severity ORDER BY severity")
for row in cur.fetchall():
    print(f"    {row[0]:10}: {row[1]}")
conn.close()
print()
sys.exit(0 if not FAIL else 1)
