"""
Log normalization service.
Converts raw logs from various sources into a standardized Event format.
"""
import re
from datetime import datetime
from typing import Dict, Any, Optional
from app.schemas import EventIngest


class LogNormalizer:
    """Normalizes various log formats into a standardized Event structure."""

    @staticmethod
    def normalize_windows_event(event_id: str, source: str, raw: str) -> Dict[str, Any]:
        """Normalize Windows Event Log data."""
        mapping = {
            # Security - Logon events (4624, 4625)
            "4624": "successful_logon",
            "4625": "failed_logon",
            "4634": "logoff",
            "4648": "logon_with_explicit_credentials",
            "4672": "special_privileges_assigned",
            "4720": "user_account_created",
            "4722": "user_account_enabled",
            "4725": "user_account_disabled",
            "4726": "user_account_deleted",
            "4728": "member_added_to_security_group",
            "4732": "member_added_to_local_group",
            "4740": "account_locked_out",
            "4768": "kerberos_ticket_granted",
            "4769": "kerberos_service_ticket_requested",
            "4771": "kerberos_pre_auth_failed",
            "1102": "audit_log_cleared",
            # System
            "7045": "service_installed",
            "7036": "service_started",
            "6005": "event_log_service_started",
        }
        return {
            "event_type": mapping.get(str(event_id), "windows_event"),
            "event_id": str(event_id),
            "source_type": "windows",
        }

    @staticmethod
    def normalize_syslog(raw: str) -> Dict[str, Any]:
        """Normalize syslog message."""
        return {
            "source_type": "syslog",
            "event_type": "syslog",
            "raw_data": raw,
        }

    @staticmethod
    def normalize_web_server(raw: str) -> Dict[str, Any]:
        """Normalize Apache/Nginx access log."""
        # Common combined log format
        pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
        match = re.search(pattern, raw)
        result = {"source_type": "web_server", "event_type": "web_access", "raw_data": raw}
        if match:
            ip, ident, user, time_str, request, status, size, referrer, user_agent = match.groups()
            result["source_ip"] = ip
            result["user"] = user if user != "-" else ""
            result["description"] = request
            result["response_code"] = status
            # Split request into method, URL (path + query), protocol
            parts = request.split()
            if parts:
                result["method"] = parts[0]
                if len(parts) > 1:
                    url = parts[1]
                    result["url"] = url
                    # Split query string from path for web attack rule access
                    if "?" in url:
                        path, query = url.split("?", 1)
                        result["url_path"] = path
                        result["url_query"] = query
                    else:
                        result["url_path"] = url
                        result["url_query"] = ""
            result["extra_data"] = {}
            for k in ("method", "url", "url_path", "url_query"):
                if k in result:
                    result["extra_data"][k] = result[k]
        return result

    @staticmethod
    def normalize_firewall(raw: str) -> Dict[str, Any]:
        """Normalize firewall log."""
        result = {"source_type": "firewall", "event_type": "firewall_rule_hit", "raw_data": raw}
        return result

    @staticmethod
    def normalize_auth(raw: str) -> Dict[str, Any]:
        """Normalize authentication log (SSH, etc.)."""
        result = {"source_type": "auth", "event_type": "auth_event", "raw_data": raw}
        result = LogNormalizer._match_auth_pattern(raw, result)
        return result

    @staticmethod
    def _match_auth_pattern(content: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Match common auth string patterns using either raw_data or description."""
        raw = content
        # SSH failed password attempt
        if "Failed password" in raw:
            m = re.search(r'from (\S+) port (\d+)', raw)
            result["event_type"] = "failed_login"
            if m:
                result["source_ip"] = m.group(1)
                result["destination_port"] = int(m.group(2))
            m2 = re.search(r'for (?:invalid user )?(\S+)', raw)
            if m2:
                result["user"] = m2.group(1)
        elif "Accepted password" in raw:
            result["event_type"] = "successful_login"
            m = re.search(r'for (\S+) from (\S+)', raw)
            if m:
                result["user"] = m.group(1)
                result["source_ip"] = m.group(2)
        return result

    @staticmethod
    def infer_severity(event_type: str, raw: str) -> str:
        """Infer severity from event type and content."""
        high_risk = ["failed_login", "account_locked_out", "audit_log_cleared",
                     "critical", "malware", "privilege_escalation"]
        for h in high_risk:
            if h in event_type.lower():
                return "high"
        if "warn" in raw.lower() or "error" in raw.lower():
            return "warning"
        return "info"

    @staticmethod
    def _content(event: EventIngest) -> str:
        """Get the best content to parse for pattern matching."""
        return event.raw_data or event.description or ""

    @staticmethod
    def normalize(event: EventIngest) -> EventIngest:
        """Normalize an incoming event based on its source type."""
        content = LogNormalizer._content(event)
        if event.source_type == "windows":
            normalized = LogNormalizer.normalize_windows_event(event.event_id, event.source_name, event.raw_data)
            event.event_type = normalized["event_type"]
            event.source_type = normalized["source_type"]
            if normalized.get("event_id"):
                event.event_id = normalized["event_id"]
        elif event.source_type == "syslog":
            normalized = LogNormalizer.normalize_syslog(event.raw_data)
            event.source_type = normalized["source_type"]
        elif event.source_type in ("web_server", "apache", "nginx"):
            normalized = LogNormalizer.normalize_web_server(event.raw_data)
            event.source_type = normalized["source_type"]
            event.event_type = normalized.get("event_type", event.event_type)
            if normalized.get("description"):
                event.description = normalized["description"]
            if normalized.get("source_ip"):
                event.source_ip = normalized["source_ip"]
            if normalized.get("response_code"):
                event.response_code = normalized["response_code"]
            extra = normalized.get("extra_data") or {}
            if extra:
                event.extra_data = {**(event.extra_data or {}), **extra}
        elif event.source_type in ("firewall", "pfSense", "iptables"):
            normalized = LogNormalizer.normalize_firewall(event.raw_data)
            event.source_type = normalized["source_type"]
        elif event.source_type == "auth":
            normalized = LogNormalizer.normalize_auth(content)
            event.source_type = normalized["source_type"]
            event.event_type = normalized.get("event_type", event.event_type)
            if normalized.get("source_ip"):
                event.source_ip = normalized["source_ip"]
            if normalized.get("user"):
                event.user = normalized["user"]
            if normalized.get("destination_port"):
                event.destination_port = normalized["destination_port"]

        # Infer severity if not set
        if not event.severity or event.severity == "info":
            event.severity = LogNormalizer.infer_severity(event.event_type, content)

        return event
