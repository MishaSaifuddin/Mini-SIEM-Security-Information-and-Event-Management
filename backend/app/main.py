from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from app.config import Config
from app.database import Base, engine, SessionLocal
from app.api import auth, events, rules, alerts, sources, dashboard

app = FastAPI(
    title="Mini SIEM - Security Information and Event Management",
    description="A lightweight SIEM platform for log collection, detection, and alerting.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=Config.API_PREFIX)
app.include_router(events.router, prefix=Config.API_PREFIX)
app.include_router(rules.router, prefix=Config.API_PREFIX)
app.include_router(alerts.router, prefix=Config.API_PREFIX)
app.include_router(sources.router, prefix=Config.API_PREFIX)
app.include_router(dashboard.router, prefix=Config.API_PREFIX)


# Serve the built React frontend (SPA). Falls back to index.html for client routes.
FRONTEND_BUILD = Path(__file__).resolve().parent.parent.parent / "frontend" / "build"

def _serve_frontend():
    index = FRONTEND_BUILD / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"detail": "Frontend not built. Run 'npm run build' in /frontend"}

if FRONTEND_BUILD.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_BUILD / "static"), name="static")
    for f in ["favicon.ico", "manifest.json", "logo192.png", "logo512.png", "robots.txt"]:
        p = FRONTEND_BUILD / f
        if p.is_file():
            def _make_route(path: Path):
                def handler():
                    return FileResponse(path)
                return handler
            app.get(f"/{f}", include_in_schema=False)(_make_route(p))


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    seed_data()


def seed_data():
    """Seed initial data: default admin user and detection rules."""
    from app.models import User, DetectionRule
    from app.core.security import get_password_hash

    db = SessionLocal()

    try:
        # Seed admin user
        if not db.query(User).filter(User.username == "admin").first():
            admin = User(
                username="admin",
                email="admin@siem.local",
                hashed_password=get_password_hash("admin123"),
                role="admin",
            )
            db.add(admin)

        # Seed detection rules
        seed_rules = [
            {
                "name": "Brute Force Attack - Multiple Failed Logins",
                "rule_id": "BRUTE-FORCE-001",
                "description": "Multiple failed login attempts from the same source IP within a short time window indicates a brute force attack.",
                "severity": "high",
                "category": "Credential Access",
                "source_types": ["auth", "windows"],
                "event_types": ["failed_login"],
                "conditions": {"event_type": "failed_login"},
                "threshold": 5,
                "time_window_seconds": 300,
                "group_by": "source_ip",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
            },
            {
                "name": "Possible Impossible Travel - Login From Multiple Locations",
                "rule_id": "IMPOSSIBLE-TRAVEL-001",
                "description": "Detects a user logging in from two different IP addresses in a very short time window, suggesting credential reuse or account compromise.",
                "severity": "high",
                "category": "Credential Access",
                "source_types": ["auth", "windows"],
                "event_types": ["successful_login"],
                "conditions": {
                    "$or": [
                        {"event_type": "successful_login", "description": {"contains": "password"}},
                        {"event_type": "successful_logon"},
                    ]
                },
                "threshold": 2,
                "time_window_seconds": 60,
                "group_by": "user",
                "mitre_technique": "T1078",
                "mitre_tactic": "Initial Access",
            },
            {
                "name": "Port Scan Detection",
                "rule_id": "PORT-SCAN-001",
                "description": "Multiple connections from the same source to many different destination ports within a short window suggests port scanning.",
                "severity": "medium",
                "category": "Discovery",
                "source_types": ["firewall"],
                "event_types": ["firewall_rule_hit"],
                "conditions": {"event_type": "firewall_rule_hit"},
                "threshold": 20,
                "time_window_seconds": 60,
                "group_by": "source_ip",
                "mitre_technique": "T1046",
                "mitre_tactic": "Discovery",
            },
            {
                "name": "Privilege Escalation - New Admin Account",
                "rule_id": "PRIV-ESC-001",
                "description": "A new user account was created, which could indicate privilege escalation or persistence.",
                "severity": "high",
                "category": "Privilege Escalation",
                "source_types": ["windows"],
                "event_types": ["user_account_created", "user_account_enabled", "member_added_to_security_group"],
                "conditions": {
                    "$or": [
                        {"event_type": "user_account_created"},
                        {"event_type": "member_added_to_security_group"},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1078",
                "mitre_tactic": "Privilege Escalation",
            },
            {
                "name": "Suspicious IP Address Communication",
                "rule_id": "SUSPICIOUS-IP-001",
                "description": "Event originated from or communicated with a known suspicious/threat IP address.",
                "severity": "high",
                "category": "Command and Control",
                "source_types": ["firewall", "web_server", "windows"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"source_ip": {"in": ["185.220.101.42", "45.155.205.5", "103.99.131.2", "91.240.118.66"]}},
                        {"destination_ip": {"in": ["185.220.101.42", "45.155.205.5", "103.99.131.2", "91.240.118.66"]}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1071",
                "mitre_tactic": "Command and Control",
            },
            {
                "name": "Malware Indicator - Suspicious Process or Behavior",
                "rule_id": "MALWARE-INDICATOR-001",
                "description": "Detects signs of malware based on known malicious process names, file hashes, or behaviors.",
                "severity": "critical",
                "category": "Execution",
                "source_types": ["windows", "syslog"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"process_name": {"contains": "mimikatz"}},
                        {"process_name": {"contains": "powersploit"}},
                        {"process_name": {"contains": "meterpreter"}},
                        {"command_line": {"contains": "minikatz"}},
                        {"command_line": {"contains": "sekurlsa"}},
                        {"command_line": {"contains": "Invoke-Mimikatz"}},
                        {"file_path": {"contains": "\\temp\\"}},
                        {"description": {"contains": "WannaCry"}},
                        {"description": {"contains": "EternalBlue"}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1059",
                "mitre_tactic": "Execution",
            },
            {
                "name": "Audit Log Cleared - Tampering Attempt",
                "rule_id": "LOG-TAMPER-001",
                "description": "Security audit log was cleared, which is a sign of log tampering to cover tracks.",
                "severity": "critical",
                "category": "Defense Evasion",
                "source_types": ["windows"],
                "event_types": ["audit_log_cleared"],
                "conditions": {"event_type": "audit_log_cleared"},
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1070",
                "mitre_tactic": "Defense Evasion",
            },
            {
                "name": "Successful Brute Force - Login After Failures",
                "rule_id": "BRUTE-FORCE-SUCCESS-001",
                "description": "A successful login from an IP that previously had multiple failed login attempts could indicate a successful brute force attack.",
                "severity": "critical",
                "category": "Credential Access",
                "source_types": ["auth", "windows"],
                "event_types": ["successful_login", "successful_logon"],
                "conditions": {
                    "$or": [
                        {"event_type": "successful_login"},
                        {"event_type": "successful_logon"},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 300,
                "group_by": "source_ip",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
            },
            {
                "name": "Service Installation - Potential Backdoor",
                "rule_id": "BACKDOOR-001",
                "description": "A new service was installed on the system, which could indicate a backdoor or persistence mechanism.",
                "severity": "medium",
                "category": "Persistence",
                "source_types": ["windows"],
                "event_types": ["service_installed"],
                "conditions": {"event_type": "service_installed"},
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1543",
                "mitre_tactic": "Persistence",
            },
            {
                "name": "Web Attack - Suspicious HTTP Status",
                "rule_id": "WEB-ATTACK-001",
                "description": "Web server logs showing high number of error responses (401/403/500) from single IP may indicate scanning or attack attempts.",
                "severity": "medium",
                "category": "Initial Access",
                "source_types": ["web_server"],
                "event_types": ["web_access"],
                "conditions": {
                    "source_type": "web_server",
                    "response_code": {"in": ["401", "403", "500"]},
                },
                "threshold": 10,
                "time_window_seconds": 300,
                "group_by": "source_ip",
                "mitre_technique": "T1190",
                "mitre_tactic": "Initial Access",
            },
            {
                "name": "Account Lockout - Targeted Attack",
                "rule_id": "ACCOUNT-LOCKOUT-001",
                "description": "An account was locked out, often the result of a brute force or password spraying attack.",
                "severity": "medium",
                "category": "Credential Access",
                "source_types": ["windows"],
                "event_types": ["account_locked_out"],
                "conditions": {"event_type": "account_locked_out"},
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
            },
            {
                "name": "SQL Injection Attack",
                "rule_id": "WEB-SQLI-001",
                "description": "Detects SQL injection patterns in web requests, indicating an attacker probing the database layer.",
                "severity": "high",
                "category": "Initial Access",
                "source_types": ["web_server"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"description": {"contains": "OR 1=1"}},
                        {"description": {"contains": "or 1=1"}},
                        {"description": {"contains": "UNION SELECT"}},
                        {"description": {"contains": "union select"}},
                        {"description": {"contains": "SELECT * FROM"}},
                        {"description": {"contains": "information_schema"}},
                        {"description": {"contains": "0x27"}},
                        {"description": {"regex": "sleep\\(\\s*\\d+"}},
                        {"description": {"contains": "'--"}},
                        {"description": {"contains": "load_file"}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "source_ip",
                "mitre_technique": "T1190",
                "mitre_tactic": "Initial Access",
            },
            {
                "name": "Cross-Site Scripting (XSS) Attack",
                "rule_id": "WEB-XSS-001",
                "description": "Detects XSS payloads in web requests - attempts to inject malicious JavaScript into the application.",
                "severity": "high",
                "category": "Initial Access",
                "source_types": ["web_server"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"description": {"contains": "<script>"}},
                        {"description": {"contains": "%3Cscript%3E"}},
                        {"description": {"contains": "<script src"}},
                        {"description": {"contains": "onerror="}},
                        {"description": {"contains": "onload="}},
                        {"description": {"contains": "alert("}},
                        {"description": {"contains": "javascript:"}},
                        {"description": {"contains": "<img src"}},
                        {"description": {"contains": "prompt("}},
                        {"description": {"contains": "<svg"}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "source_ip",
                "mitre_technique": "T1189",
                "mitre_tactic": "Initial Access",
            },
            {
                "name": "Path Traversal Attempt",
                "rule_id": "WEB-PATHTRAV-001",
                "description": "Detects path traversal attempts used to access files outside the web root (e.g. reading /etc/passwd).",
                "severity": "medium",
                "category": "Initial Access",
                "source_types": ["web_server"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"description": {"contains": "../"}},
                        {"description": {"contains": "..%2f"}},
                        {"description": {"contains": "..%5c"}},
                        {"description": {"contains": "..\\\\"}},
                        {"description": {"contains": "%2e%2e%2f"}},
                        {"description": {"contains": "etc/passwd"}},
                        {"description": {"contains": "windows\\win.ini"}},
                        {"description": {"contains": "../../../"}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "source_ip",
                "mitre_technique": "T1083",
                "mitre_tactic": "Discovery",
            },
            {
                "name": "Credential Brute Force on Web Login",
                "rule_id": "WEB-BRUTEFORCE-001",
                "description": "Multiple failed web login attempts (401) from the same source IP within a short window - credential stuffing or brute force.",
                "severity": "high",
                "category": "Credential Access",
                "source_types": ["web_server"],
                "event_types": ["web_access"],
                "conditions": {
                    "source_type": "web_server",
                    "response_code": "401",
                },
                "threshold": 10,
                "time_window_seconds": 300,
                "group_by": "source_ip",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
            },
            {
                "name": "Reconnaissance Followed by Attack - Cross-Source Correlation",
                "rule_id": "CORRELATION-SCAN-BRUTEFORCE-001",
                "description": "Correlates a source IP that performed network scanning (firewall) and then attempted credential brute force (auth/web) - indicates a coordinated attack chain.",
                "severity": "high",
                "category": "Correlation",
                "source_types": [],
                "event_types": [],
                "correlation": {
                    "stages": [
                        {"source_type": "firewall", "event_type": "firewall_rule_hit", "label": "scanning"},
                        {"source_type": "auth", "event_type": "failed_login", "label": "bruteforce"},
                    ],
                    "group_by": "source_ip",
                    "window_seconds": 3600,
                },
                "conditions": {},
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "source_ip",
                "mitre_technique": "T1071",
                "mitre_tactic": "Discovery",
            },
            {
                "name": "Malicious File Upload Attempt",
                "rule_id": "WEB-UPLOAD-001",
                "description": "Detects attempts to upload potentially malicious files (PHP shells, executable scripts) to the web application.",
                "severity": "high",
                "category": "Execution",
                "source_types": ["web_server"],
                "event_types": [],
                "conditions": {
                    "$or": [
                        {"description": {"contains": "shell.php"}},
                        {"description": {"contains": "cmd.php"}},
                        {"description": {"contains": "_.php"}},
                        {"description": {"contains": "upload.php"}},
                        {"description": {"contains": "phtml"}},
                        {"description": {"contains": ".exe"}},
                        {"description": {"contains": ".jsp"}},
                        {"description": {"contains": "webshell"}},
                        {"description": {"contains": "POST /upload"}},
                    ]
                },
                "threshold": 1,
                "time_window_seconds": 3600,
                "group_by": "source_ip",
                "mitre_technique": "T1190",
                "mitre_tactic": "Execution",
            },
        ]

        for rule_data in seed_rules:
            if not db.query(DetectionRule).filter(DetectionRule.rule_id == rule_data["rule_id"]).first():
                rule = DetectionRule(**rule_data)
                db.add(rule)

        db.commit()
    finally:
        db.close()


@app.get("/")
def root():
    return _serve_frontend()


@app.get("/api/health")
def health():
    return {"status": "healthy", "timestamp": str(__import__('datetime').datetime.utcnow())}


# SPA fallback: any non-API, non-asset path returns the frontend index.html
@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith("api/") or full_path == "api":
        return {"detail": "Not Found"}
    if FRONTEND_BUILD.exists():
        return _serve_frontend()
    return {"detail": "Not Found"}
