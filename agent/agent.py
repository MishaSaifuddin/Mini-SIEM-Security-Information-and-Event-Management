"""
Mini SIEM Log Collection Agent
===============================
A lightweight Python agent that collects logs from local/remote sources and
forwards them to the Mini SIEM server via its REST API.

Supported sources:
  - Windows Event Logs (via win32evtlog or XML export)
  - Syslog (reads from syslog socket or file)
  - Web server logs (Apache/Nginx access logs)
  - Auth logs (/var/log/auth.log)
  - Custom JSON/structured logs
"""
import json
import os
import sys
import time
import socket
import signal
import argparse
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("siem-agent")


class SIEMAgentConfig:
    def __init__(self, config_file: Optional[str] = None):
        self.siem_url = os.environ.get("SIEM_URL", "http://localhost:8000")
        self.api_key = os.environ.get("SIEM_API_KEY", "")
        self.username = os.environ.get("SIEM_USERNAME", "admin")
        self.password = os.environ.get("SIEM_PASSWORD", "admin123")
        self.agent_name = os.environ.get("AGENT_NAME", socket.gethostname())
        self.poll_interval = int(os.environ.get("POLL_INTERVAL", "5"))
        
        if config_file and Path(config_file).exists():
            self.load_config(config_file)
    
    def load_config(self, path: str):
        with open(path, "r") as f:
            data = json.load(f)
            for key, value in data.items():
                if hasattr(self, key) and value is not None:
                    setattr(self, key, value)


class BaseCollector:
    """Base class for log collectors."""
    
    name = "base"
    
    def __init__(self, agent: "SIEMAgent"):
        self.agent = agent
    
    def collect(self) -> List[Dict]:
        raise NotImplementedError
    
    def run(self):
        batch = self.collect()
        if batch:
            self.agent.send_batch(batch)


class WindowsEventCollector(BaseCollector):
    """Collect Windows Event Log entries."""
    
    name = "windows"
    
    def __init__(self, agent: "SIEMAgent"):
        super().__init__(agent)
        # Map of interesting event IDs
        self.security_events = {
            4624: "successful_logon",
            4625: "failed_logon",
            4634: "logoff",
            4648: "logon_with_explicit_credentials",
            4672: "special_privileges_assigned",
            4720: "user_account_created",
            4722: "user_account_enabled",
            4725: "user_account_disabled",
            4726: "user_account_deleted",
            4728: "member_added_to_security_group",
            4732: "member_added_to_local_group",
            4740: "account_locked_out",
            4768: "kerberos_ticket_granted",
            1102: "audit_log_cleared",
        }
    
    def _read_windows_events(self) -> List[Dict]:
        """Read Windows Event Log via PowerShell as fallback."""
        events = []
        try:
            import subprocess
            # Use PowerShell to get recent security events
            ps_script = """
            Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddMinutes(-1)} -MaxEvents 50 |
            ForEach-Object {
                Write-Output "ID=$($_.Id)|TIME=$($_.TimeCreated)|USER=$($_.Properties[0].Value)|MSG=$($_.Message)"
            }
            """
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                event = {"source_type": "windows", "hostname": socket.gethostname()}
                for part in parts:
                    if part.startswith("ID="):
                        event["event_id"] = part.split("=", 1)[1]
                        eid = event["event_id"]
                        event["event_type"] = self.security_events.get(int(eid), "windows_event")
                    elif part.startswith("TIME="):
                        try:
                            dt = datetime.strptime(part.split("=", 1)[1], "%Y-%m-%d %H:%M:%S")
                            event["timestamp"] = dt.isoformat()
                        except ValueError:
                            pass
                    elif part.startswith("USER="):
                        event["user"] = part.split("=", 1)[1]
                    elif part.startswith("MSG="):
                        event["description"] = part.split("=", 1)[1][:500]
                if "event_id" in event:
                    events.append(event)
        except Exception as e:
            logger.error(f"Error reading Windows events: {e}")
        return events
    
    def collect(self):
        events = self._read_windows_events()
        if events:
            logger.info(f"Collected {len(events)} Windows events")
        for e in events:
            e["source_name"] = f"{socket.gethostname()}-logs"
        return events


class SyslogCollector(BaseCollector):
    """Collect syslog messages via UDP or file tailing."""
    
    name = "syslog"
    
    def __init__(self, agent: "SIEMAgent", port: int = 514, host: str = "0.0.0.0"):
        super().__init__(agent)
        self.port = port
        self.host = host
        self._running = False
        self._batch = []
    
    def collect(self):
        return []
    
    def start_udp_server(self):
        """Start a UDP syslog server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._running = True
        logger.info(f"Syslog UDP server listening on {self.host}:{self.port}")
        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
                message = data.decode("utf-8", errors="replace").strip()
                event = {
                    "source_type": "syslog",
                    "source_name": f"syslog-{addr[0]}",
                    "hostname": self._extract_hostname(message),
                    "ip_address": addr[0],
                    "event_type": "syslog",
                    "description": message[:1000],
                    "raw_data": message,
                    "severity": "info",
                }
                self._batch.append(event)
                if len(self._batch) >= 20:
                    self.agent.send_batch(self._batch)
                    self._batch = []
            except socket.timeout:
                if self._batch and time.time() - self._last_send > 5:
                    self.agent.send_batch(self._batch)
                    self._batch = []
    
    @staticmethod
    def _extract_hostname(message: str) -> str:
        parts = message.split(" ")
        for part in parts[:3]:
            if part and not part.startswith("<") and ":" not in part and "." in part:
                return part
        return socket.gethostname()


class FileTailCollector(BaseCollector):
    """Tail log files (web server, auth logs, etc.)."""
    
    name = "file_tail"
    
    def __init__(self, agent: "SIEMAgent", paths: List[str], source_type: str = "custom"):
        super().__init__(agent)
        self.paths = paths
        self.source_type = source_type
        self._last_positions = {}
    
    def collect(self):
        events = []
        for path in self.paths:
            if not Path(path).exists():
                continue
            last_pos = self._last_positions.get(path, 0)
            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    self._last_positions[path] = f.tell()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    event = {"source_type": self.source_type, "source_name": path}
                    if self.source_type == "web_server":
                        event = self._parse_web_line(line)
                    else:
                        event["description"] = line[:1000]
                        event["raw_data"] = line
                        event["severity"] = "info"
                    event["hostname"] = socket.gethostname()
                    events.append(event)
            except Exception as e:
                logger.warning(f"Error reading {path}: {e}")
        if events:
            self._last_positions[path] = 0  # fresh start
        return events
    
    @staticmethod
    def _parse_web_line(line: str) -> Dict:
        import re
        result = {"source_type": "web_server", "event_type": "web_access", "raw_data": line}
        pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3})'
        match = re.search(pattern, line)
        if match:
            ip, ident, user, time_str, request, status = match.groups()
            result["source_ip"] = ip
            result["user"] = user if user != "-" else ""
            result["description"] = request
            result["response_code"] = status
        return result


class JSONLogCollector(BaseCollector):
    """Collect structured JSON logs from applications."""
    
    name = "json_log"
    
    def __init__(self, agent: "SIEMAgent", paths: List[str]):
        super().__init__(agent)
        self.paths = paths
    
    def collect(self):
        events = []
        for path in self.paths:
            if not Path(path).exists():
                continue
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            event = {"source_type": "custom_json", "source_name": path}
                            # Map common JSON fields
                            if "timestamp" in data:
                                event["timestamp"] = data["timestamp"]
                            if "level" in data:
                                event["severity"] = data["level"]
                            elif "severity" in data:
                                event["severity"] = data["severity"]
                            if "event_type" in data:
                                event["event_type"] = data["event_type"]
                            if "message" in data:
                                event["description"] = str(data["message"]).get("data", str(data["message"]))
                            elif "msg" in data:
                                event["description"] = str(data["msg"])
                            if "user" in data:
                                event["user"] = data["user"]
                            if "host" in data:
                                event["hostname"] = data["host"]
                            # Keep remaining as extra data
                            extra = {k: v for k, v in data.items() if k not in event}
                            event["extra_data"] = extra
                            events.append(event)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.warning(f"Error reading JSON log {path}: {e}")
        return events


class SIEMAgent:
    """Main agent that manages collectors and sends data to the SIEM server."""
    
    def __init__(self, config: SIEMAgentConfig):
        self.config = config
        self.token = None
        self.collectors: List[BaseCollector] = []
        self._stop = False
        self._batch_lock = threading.Lock()
        self._pending_batch = []
    
    def add_collector(self, collector: BaseCollector):
        self.collectors.append(collector)
    
    def authenticate(self) -> bool:
        """Authenticate with the SIEM server."""
        try:
            resp = requests.post(
                f"{self.config.siem_url}/api/auth/login",
                json={"username": self.config.username, "password": self.config.password},
                timeout=10,
            )
            if resp.status_code == 200:
                self.token = resp.json()["access_token"]
                logger.info("Successfully authenticated with SIEM server")
                return True
            logger.error(f"Authentication failed: {resp.text}")
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to SIEM server at {self.config.siem_url}")
        return False
    
    def send_batch(self, events: List[Dict]):
        """Send a batch of events to the SIEM server."""
        if not self.token:
            if not self.authenticate():
                time.sleep(10)
                return
        
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{self.config.siem_url}/api/events/ingest/batch",
                json={"events": events},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.debug(f"Sent {len(events)} events")
            else:
                logger.error(f"Failed to send batch: {resp.status_code} {resp.text}")
                # Token might be expired
                if resp.status_code == 401:
                    self.token = None
        except requests.exceptions.ConnectionError:
            logger.error("Connection lost to SIEM server")
            self.token = None
    
    def run(self):
        """Main agent loop."""
        if not self.authenticate():
            logger.error("Cannot start agent - authentication failed. Will retry.")
        
        logger.info(f"Starting SIEM agent '{self.config.agent_name}' with {len(self.collectors)} collectors")
        
        # Start any background collectors (like UDP server)
        for collector in self.collectors:
            if hasattr(collector, "start_udp_server"):
                t = threading.Thread(target=collector.start_udp_server, daemon=True)
                t.start()
        
        while not self._stop:
            for collector in self.collectors:
                try:
                    batch = collector.collect()
                    if batch:
                        self.send_batch(batch)
                except Exception as e:
                    logger.error(f"Collector {collector.name} error: {e}")
            
            time.sleep(self.config.poll_interval)
        
        logger.info("Agent stopped")
    
    def stop(self):
        self._stop = True
        for collector in self.collectors:
            if hasattr(collector, "_running"):
                collector._running = False


def build_default_config() -> SIEMAgentConfig:
    """Build agent config with sensible defaults based on the platform."""
    cfg = SIEMAgentConfig()
    
    # Windows Event Log collector
    if sys.platform == "win32":
        win = WindowsEventCollector(None)
        # Need agent ref - set later
    
    return cfg


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM Log Collection Agent")
    parser.add_argument("--config", help="Path to configuration file (JSON)")
    parser.add_argument("--siem-url", default=os.environ.get("SIEM_URL", "http://localhost:8000"))
    parser.add_argument("--username", default=os.environ.get("SIEM_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("SIEM_PASSWORD", "admin123"))
    parser.add_argument("--agent-name", default=socket.gethostname())
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--collect-windows", action="store_true", help="Collect Windows Event Logs")
    parser.add_argument("--syslog-port", type=int, default=0, help="Start UDP syslog server on port (0 to disable)")
    parser.add_argument("--tail", action="append", default=[], help="Tail log file (can be repeated)")
    parser.add_argument("--source-type", default="custom", help="Source type for tailed files")
    parser.add_argument("--json-logs", action="append", default=[], help="Watch JSON log files (can be repeated)")
    
    args = parser.parse_args()
    
    cfg = SIEMAgentConfig(args.config if args.config else None)
    cfg.siem_url = args.siem_url
    cfg.username = args.username
    cfg.password = args.password
    cfg.agent_name = args.agent_name
    cfg.poll_interval = args.poll_interval
    
    agent = SIEMAgent(cfg)
    
    # Add collectors based on args
    if args.collect_windows or sys.platform == "win32":
        collector = WindowsEventCollector(agent)
        agent.add_collector(collector)
        logger.info("Windows Event Log collector enabled")
    
    if args.syslog_port:
        collector = SyslogCollector(agent, port=args.syslog_port)
        agent.add_collector(collector)
        logger.info(f"Syslog collector enabled on UDP {args.syslog_port}")
    
    for path in args.tail:
        collector = FileTailCollector(agent, [path], source_type=args.source_type)
        agent.add_collector(collector)
        logger.info(f"File tailing collector enabled for {path}")
    
    for path in args.json_logs:
        collector = JSONLogCollector(agent, [path])
        agent.add_collector(collector)
        logger.info(f"JSON log collector enabled for {path}")
    
    # If no collectors explicitly set, enable a default file poller
    if not agent.collectors:
        logger.warning("No collectors specified. Specify --collect-windows, --tail, --json-logs, or --syslog-port")
        logger.info("Example: python agent.py --tail /var/log/auth.log --source-type auth")
        return
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    agent.run()


if __name__ == "__main__":
    main()
