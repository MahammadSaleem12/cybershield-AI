import os
import re
import sqlite3
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
    jsonify,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
ALLOWED_EXTENSIONS = {"log", "txt", "csv"}

app = Flask(__name__)
app.secret_key = os.environ.get("CYBERSHIELD_SECRET", "change-me-in-prod-123")



def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def generate_bulk_security_events(count=500):
    import random
    from datetime import datetime, timedelta

    attack_templates = [
        ('ssh', 'Failed password for invalid user {user} from {ip} port {port} ssh2'),
        ('ssh', 'Accepted password for {user} from {ip} port {port} ssh2'),
        ('ssh', 'Invalid user {user} from {ip} port {port}'),
        ('web', 'GET /index.php?id=1 UNION SELECT password FROM users-- HTTP/1.1'),
        ('web', 'GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1'),
        ('web', 'Nikto v2.1.6 scan started against /var/www/html'),
        ('web', 'Metasploit handler started for exploit/multi/handler'),
        ('web', 'Hydra: login attempt on {ip} for user {user}'),
        ('sys', 'sudo: pam_unix(sudo:session): session opened for user root by (uid=1000)'),
        ('sys', 'Possible portscan from {ip}'),
        ('sys', 'kernel: suspicious connection from {ip} to port {port}'),
        ('web', 'GET /admin?user=admin\' OR \'1\'=\'1\" HTTP/1.1'),
        ('web', 'GET /login.php?username=admin&password=1234 HTTP/1.1'),
        ('web', 'GET /search?q=%3Cscript%3Efetch(%22http://evil.example.com%22)%3C%2Fscript%3E'),
        ('sys', 'Malware detected in /tmp/{file} by signature {sig}'),
    ]
    users = ['admin', 'bob', 'alice', 'john', 'maria', 'guest', 'svcuser']
    ips = [
        '203.0.113.45', '198.51.100.23', '192.0.2.50', '192.0.2.14',
        '198.51.100.8', '203.0.113.99', '172.16.0.12', '10.0.0.17',
        '104.244.42.1', '54.174.10.2'
    ]
    files = ['payload.exe', 'trojan.bin', 'shell.php', 'report.csv', 'config.php']
    sigs = ['EICAR', 'Trojan.Generic', 'Worm.Agent', 'Ransomware.X']
    now = datetime.utcnow()
    lines = []
    for i in range(count):
        ts = now - timedelta(minutes=random.randint(1, 7200))
        template = random.choice(attack_templates)
        msg = template[1].format(
            user=random.choice(users),
            ip=random.choice(ips),
            port=random.randint(1024, 65535),
            file=random.choice(files),
            sig=random.choice(sigs),
        )
        if template[0] == 'ssh':
            line = f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{1000 + i}]: {msg}"
        elif template[0] == 'web':
            line = f"[{ts.strftime('%d/%b/%Y:%H:%M:%S')}] {msg}"
        else:
            line = f"{ts.strftime('%b %d %H:%M:%S')} server {msg}"
        lines.append(line)
    return '\n'.join(lines) + '\n'


def init_dirs_and_samples():
    os.makedirs(LOGS_DIR, exist_ok=True)
    # sample logs
    sample1 = os.path.join(LOGS_DIR, "sample_auth.log")
    sample2 = os.path.join(LOGS_DIR, "sample_web.log")
    sample_bulk = os.path.join(LOGS_DIR, "sample_bulk.log")
    if not os.path.exists(sample1):
        with open(sample1, "w", encoding="utf-8") as f:
            f.write("""
Jul 10 12:00:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2
Jul 10 12:00:05 server sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2
Jul 10 12:01:00 server sshd[1235]: Accepted password for john from 198.51.100.23 port 42311 ssh2
Jul 10 12:05:17 server sudo: pam_unix(sudo:session): session opened for user root by (uid=1000)
Jul 10 12:10:22 server kernel: Possible portscan from 198.51.100.23
""")
    if not os.path.exists(sample2):
        with open(sample2, "w", encoding="utf-8") as f:
            f.write("""
[10/Jul/2026:12:00:00] "GET /index.php?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 452
[10/Jul/2026:12:00:03] "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 215
[10/Jul/2026:12:05:00] "Nikto v2.1.6 scan started against /var/www/html"
[10/Jul/2026:12:06:00] "Metasploit handler started for exploit/multi/handler"
""")
    if not os.path.exists(sample_bulk):
        with open(sample_bulk, "w", encoding="utf-8") as f:
            f.write(generate_bulk_security_events(500))


def init_db():
    init_dirs_and_samples()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL UNIQUE,
            uploaded_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            type TEXT,
            severity TEXT,
            message TEXT,
            ip TEXT,
            timestamp TEXT,
            FOREIGN KEY(log_id) REFERENCES logs(id)
        )
        """
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        pw = generate_password_hash("adminpass")
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", ("admin", pw))
        conn.commit()

    # Import sample log files not yet in the DB
    cur.execute("SELECT filepath FROM logs")
    existing = {r[0] for r in cur.fetchall()}
    new_logs = []
    for fname in os.listdir(LOGS_DIR):
        path = os.path.join(LOGS_DIR, fname)
        if os.path.isfile(path) and path not in existing:
            cur.execute(
                "INSERT OR IGNORE INTO logs (filename, filepath, uploaded_at) VALUES (?,?,?)",
                (fname, path, datetime.utcnow().isoformat()),
            )
            if cur.lastrowid:
                new_logs.append((cur.lastrowid, path))
    conn.commit()

    # Collect all logs that have no threats yet
    cur.execute(
        "SELECT id, filepath FROM logs WHERE id NOT IN (SELECT DISTINCT log_id FROM threats)"
    )
    unparsed = cur.fetchall()
    conn.close()  # close BEFORE calling parse_log_and_store to avoid lock

    for row in unparsed:
        parse_log_and_store(row[0], row[1])


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def severity_for(threat_type):
    mapping = {
        "Metasploit": "Critical",
        "Malware": "Critical",
        "SQL Injection": "Critical",
        "Brute Force": "Critical",
        "Privilege Escalation": "High",
        "Port Scan": "High",
        "Hydra": "High",
        "Nikto": "High",
        "Suspicious IP": "High",
        "Failed password": "Medium",
        "Invalid user": "Medium",
        "XSS": "Medium",
        "Accepted password": "Low",
        "Unknown": "Low",
    }
    return mapping.get(threat_type, "Low")


def parse_log_and_store(log_id, filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        lines = []

    detections = []
    failed_counts = {}

    patterns = [
        (r"Failed password|authentication failure|failed login", "Failed password"),
        (r"Invalid user", "Invalid user"),
        (r"Accepted password|login succeeded|session opened", "Accepted password"),
        (r"UNION SELECT|SELECT .*FROM|OR 1=1|DROP TABLE", "SQL Injection"),
        (r"<script>|%3Cscript%3E|</script>", "XSS"),
        (r"portscan|SYN scan|nmap", "Port Scan"),
        (r"Malware|trojan|virus|worm|malicious", "Malware"),
        (r"hydra", "Hydra"),
        (r"Nikto", "Nikto"),
        (r"Metasploit|msf", "Metasploit"),
        (r"sudo:|session opened for user root|setuid", "Privilege Escalation"),
    ]

    ip_regex = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for ln in lines:
        line = ln.strip()
        found = False
        ip = None
        m = ip_regex.search(line)
        if m:
            ip = m.group(1)

        # try to extract a timestamp-like prefix
        ts = None
        tmatch = re.match(r"^(\[?\d{1,2}[/A-Za-z:\-\s]+\]?)[\s-]+", line)
        if tmatch:
            ts = tmatch.group(1)

        for patt, tname in patterns:
            if re.search(patt, line, re.IGNORECASE):
                detections.append({"type": tname, "message": line, "ip": ip, "time": ts or datetime.utcnow().isoformat()})
                found = True
                if tname == "Failed password" and ip:
                    failed_counts[ip] = failed_counts.get(ip, 0) + 1
                break

        # suspicious IP heuristic
        if not found and ip and re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line):
            if "scan" in line.lower() or "suspicious" in line.lower():
                detections.append({"type": "Suspicious IP", "message": line, "ip": ip, "time": ts or datetime.utcnow().isoformat()})

    # brute force detection
    for ip, cnt in failed_counts.items():
        if cnt >= 3:
            detections.append({"type": "Brute Force", "message": f"{cnt} failed attempts from {ip}", "ip": ip, "time": None})

    # store detections in DB
    conn = get_db_connection()
    cur = conn.cursor()
    for d in detections:
        sev = severity_for(d["type"])
        cur.execute(
            "INSERT INTO threats (log_id,type,severity,message,ip,timestamp) VALUES (?,?,?,?,?,?)",
            (log_id, d["type"], sev, d["message"], d["ip"], d.get("time") or datetime.utcnow().isoformat()),
        )
    conn.commit()
    conn.close()


def require_login(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session["user"] = username
            flash("Logged in successfully", "success")
            next_page = request.args.get("next") or url_for("dashboard")
            return redirect(next_page)
        flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@require_login
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM logs")
    total_logs = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) as cnt FROM threats")
    total_threats = cur.fetchone()[0]
    cur.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity")
    sev_rows = cur.fetchall()
    sev_counts = {r[0]: r[1] for r in sev_rows}
    cur.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type ORDER BY cnt DESC LIMIT 10")
    top_types = cur.fetchall()
    cur.execute("SELECT ip, COUNT(*) as cnt FROM threats WHERE ip IS NOT NULL GROUP BY ip ORDER BY cnt DESC LIMIT 10")
    top_ips = cur.fetchall()
    cur.execute("SELECT COUNT(DISTINCT log_id) as cnt FROM threats")
    logs_with_threats = cur.fetchone()[0]
    safe_logs = max(0, total_logs - logs_with_threats)
    risk_score = min(100, sev_counts.get('Critical', 0) * 20 + sev_counts.get('High', 0) * 10 + sev_counts.get('Medium', 0) * 5 + sev_counts.get('Low', 0) * 2)
    cur.execute("SELECT id, filename, uploaded_at FROM logs ORDER BY uploaded_at DESC LIMIT 5")
    recent_logs = cur.fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        total_threats=total_threats,
        safe_logs=safe_logs,
        risk_score=risk_score,
        sev_counts=sev_counts,
        top_types=top_types,
        top_ips=top_ips,
        recent_logs=recent_logs,
    )


@app.route("/upload", methods=["GET", "POST"])
@require_login
def upload():
    if request.method == "POST":
        if "logfile" not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files["logfile"]
        if not file or file.filename == "":
            flash("No selected file", "warning")
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash("Unsupported file type. Upload .log, .txt, or .csv files only.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        dest = os.path.join(LOGS_DIR, filename)
        file.save(dest)

        conn = get_db_connection()
        cur = conn.cursor()
        # Use INSERT OR IGNORE so re-uploading the same filename never creates a duplicate
        cur.execute(
            "INSERT OR IGNORE INTO logs (filename, filepath, uploaded_at) VALUES (?,?,?)",
            (filename, dest, datetime.utcnow().isoformat()),
        )
        conn.commit()
        log_id = cur.lastrowid
        # lastrowid is 0 when INSERT OR IGNORE skips — fetch the existing id
        if not log_id:
            cur.execute("SELECT id FROM logs WHERE filepath=?", (dest,))
            log_id = cur.fetchone()[0]
        conn.close()  # close BEFORE parse to avoid database-is-locked

        # Only parse if this log has no threats yet
        conn2 = get_db_connection()
        cur2 = conn2.cursor()
        cur2.execute("SELECT COUNT(*) FROM threats WHERE log_id=?", (log_id,))
        already_parsed = cur2.fetchone()[0] > 0
        conn2.close()

        if not already_parsed:
            parse_log_and_store(log_id, dest)

        flash("File uploaded and parsed successfully.", "success")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY uploaded_at DESC")
    logs = cur.fetchall()
    conn.close()
    return render_template("upload.html", logs=logs)


@app.route("/logs")
@require_login
def logs_index():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY uploaded_at DESC")
    logs = cur.fetchall()
    conn.close()
    return render_template("upload.html", logs=logs)


@app.route("/log/<int:log_id>")
@require_login
def view_log(log_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE id=?", (log_id,))
    log = cur.fetchone()
    if not log:
        conn.close()
        flash("Log not found", "warning")
        return redirect(url_for("dashboard"))
    # read file
    content = ""
    try:
        with open(log["filepath"], "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        content = "Could not read file"
    cur.execute("SELECT * FROM threats WHERE log_id=? ORDER BY timestamp DESC", (log_id,))
    threats = cur.fetchall()
    conn.close()
    return render_template("report.html", log=log, content=content, threats=threats)


@app.route("/generate_pdf/<int:log_id>")
@require_login
def generate_pdf(log_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE id=?", (log_id,))
    log = cur.fetchone()
    if not log:
        conn.close()
        flash("Log not found", "warning")
        return redirect(url_for("dashboard"))
    cur.execute("SELECT * FROM threats WHERE log_id=? ORDER BY timestamp DESC", (log_id,))
    threats = cur.fetchall()
    conn.close()

    severity_counts = {}
    for t in threats:
        severity_counts[t['severity']] = severity_counts.get(t['severity'], 0) + 1

    pdf_path = os.path.join(BASE_DIR, f"report_{log_id}.pdf")
    try:
        c = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica-Bold", 18)
        c.drawString(40, height - 40, "CyberShield AI Executive Threat Report")
        c.setFont("Helvetica", 11)
        c.drawString(40, height - 64, f"File: {log['filename']}")
        c.drawString(40, height - 80, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        y = height - 110
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, "Executive Summary")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Total threats detected: {len(threats)}")
        y -= 14
        c.drawString(40, y, f"Critical: {severity_counts.get('Critical', 0)}, High: {severity_counts.get('High', 0)}, Medium: {severity_counts.get('Medium', 0)}, Low: {severity_counts.get('Low', 0)}")
        y -= 24
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, "Threat Details")
        y -= 20
        c.setFont("Helvetica", 10)
        for t in threats:
            line = f"[{t['timestamp']}] {t['severity']} {t['type']} {t['ip']}"
            c.drawString(40, y, line[:100])
            y -= 12
            if y < 60:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 40
        c.save()
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        flash(f"Failed to generate PDF: {e}", "danger")
        return redirect(url_for("view_log", log_id=log_id))


@app.route("/search")
@require_login
def search():
    qtype = request.args.get("type")
    severity = request.args.get("severity")
    ip = request.args.get("ip")
    conn = get_db_connection()
    cur = conn.cursor()
    sql = "SELECT threats.*, logs.filename FROM threats LEFT JOIN logs ON threats.log_id=logs.id WHERE 1=1"
    params = []
    if qtype:
        sql += " AND type LIKE ?"
        params.append(f"%{qtype}%")
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if ip:
        sql += " AND ip LIKE ?"
        params.append(f"%{ip}%")
    sql += " ORDER BY timestamp DESC LIMIT 100"
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return render_template("settings.html", recent=[], threats=rows, search_params={"type": qtype, "severity": severity, "ip": ip})


@app.route("/api/chart-data")
@require_login
def api_chart_data():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity")
    sev_rows = cur.fetchall()
    sev_counts = {r[0]: r[1] for r in sev_rows}
    cur.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type ORDER BY cnt DESC LIMIT 10")
    top_types = cur.fetchall()
    cur.execute("SELECT ip, COUNT(*) as cnt FROM threats WHERE ip IS NOT NULL GROUP BY ip ORDER BY cnt DESC LIMIT 10")
    top_ips = cur.fetchall()
    conn.close()
    return jsonify({
        "severity": sev_counts,
        "top_types": [{"type": r[0], "count": r[1]} for r in top_types],
        "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
    })


@app.route("/api/threats")
@require_login
def api_threats():
    # return recent threats (limit and filters)
    limit = int(request.args.get("limit", 200))
    severity = request.args.get("severity")
    qtype = request.args.get("type")
    ip = request.args.get("ip")
    conn = get_db_connection()
    cur = conn.cursor()
    sql = "SELECT threats.*, logs.filename FROM threats LEFT JOIN logs ON threats.log_id=logs.id WHERE 1=1"
    params = []
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if qtype:
        sql += " AND type LIKE ?"
        params.append(f"%{qtype}%")
    if ip:
        sql += " AND ip LIKE ?"
        params.append(f"%{ip}%")
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        uname = None
        m = re.search(r"for\s+(\w+)|user\s+(\w+)|username[=:]\s*(\w+)", (r["message"] or ""), re.IGNORECASE)
        if m:
            for g in m.groups():
                if g:
                    uname = g
                    break
        status = "Open" if r["severity"] in ("Critical", "High") else "Reviewed"
        out.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "severity": r["severity"],
            "type": r["type"],
            "ip": r["ip"],
            "message": r["message"],
            "log": r["filename"],
            "log_id": r["log_id"],
            "username": uname,
            "status": status,
        })
    return jsonify(out)


def generate_ai_summary_text():
    # simple heuristic summary and recommendations
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity")
    sev = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type ORDER BY cnt DESC LIMIT 5")
    top = cur.fetchall()
    cur.execute("SELECT ip, COUNT(*) as cnt FROM threats WHERE ip IS NOT NULL GROUP BY ip ORDER BY cnt DESC LIMIT 1")
    top_ip = cur.fetchone()
    conn.close()
    risk_score = min(100, sev.get('Critical', 0) * 20 + sev.get('High', 0) * 10 + sev.get('Medium', 0) * 5 + sev.get('Low', 0) * 2)
    recs = []
    if sev.get('Critical', 0) > 0:
        recs.append('Investigate critical alerts immediately and isolate affected assets.')
    if sev.get('High', 0) > 3:
        recs.append('Block malicious IPs and tighten access controls immediately.')
    if sev.get('Medium', 0) > 10:
        recs.append('Review authentication policies and consider rate limiting on entry points.')
    if not recs:
        recs.append('No immediate high-risk patterns detected; continue monitoring.')
    summary = {
        'counts': sev,
        'top_types': [{ 'type': r[0], 'count': r[1] } for r in top],
        'recommendations': recs,
        'risk_score': risk_score,
        'most_dangerous_ip': top_ip[0] if top_ip else 'N/A',
        'most_frequent_attack': top[0][0] if top else 'N/A',
    }
    return summary


@app.route("/ai_summary")
@require_login
def ai_summary():
    summary = generate_ai_summary_text()
    return render_template('ai_summary.html', summary=summary)


@app.route('/threats')
@require_login
def threats_page():
    return render_template('threats.html')


@app.route('/generate_pdf_all')
@require_login
def generate_pdf_all():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT threats.*, logs.filename FROM threats LEFT JOIN logs ON threats.log_id=logs.id ORDER BY timestamp DESC LIMIT 500")
    rows = cur.fetchall()
    conn.close()
    pdf_path = os.path.join(BASE_DIR, 'report_all.pdf')
    try:
        c = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter
        c.setFont('Helvetica-Bold', 16)
        c.drawString(40, height-40, 'CyberShield AI - Consolidated Threat Report')
        c.setFont('Helvetica', 10)
        y = height-70
        for r in rows:
            line = f"[{r['timestamp']}] {r['severity']} {r['type']} {r['ip']} ({r['filename']})"
            c.drawString(40, y, line[:1000])
            y -= 12
            if y < 60:
                c.showPage()
                y = height-40
        c.save()
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        flash(f'Failed to generate consolidated PDF: {e}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/rescan_logs')
@require_login
def rescan_logs():
    # scan LOGS_DIR and import new logs then parse them
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT filepath FROM logs")
    existing = {r[0] for r in cur.fetchall()}
    added = 0
    for fname in os.listdir(LOGS_DIR):
        path = os.path.join(LOGS_DIR, fname)
        if os.path.isfile(path) and path not in existing:
            cur.execute("INSERT INTO logs (filename, filepath, uploaded_at) VALUES (?,?,?)", (fname, path, datetime.utcnow().isoformat()))
            conn.commit()
            log_id = cur.lastrowid
            parse_log_and_store(log_id, path)
            added += 1
    conn.close()
    flash(f'Rescanned logs, added {added} new files', 'info')
    return redirect(url_for('dashboard'))


@app.route("/settings", methods=["GET", "POST"])
@require_login
def settings():
    message = None
    if request.method == "POST":
        # change password
        old = request.form.get("old_password")
        new = request.form.get("new_password")
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (session.get("user"),))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], old):
            cur.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user["id"]))
            conn.commit()
            message = ("Password updated", "success")
        else:
            message = ("Old password incorrect", "danger")
        conn.close()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT threats.*, logs.filename FROM threats LEFT JOIN logs ON threats.log_id=logs.id ORDER BY threats.timestamp DESC LIMIT 50")
    recent = cur.fetchall()
    conn.close()
    return render_template("settings.html", recent=recent, message=message)


# Run init_db regardless of how the app is started (direct or WSGI)
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
