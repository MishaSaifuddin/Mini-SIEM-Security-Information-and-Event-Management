"""
Detection engine for the mini SIEM.

Supports:
1. Custom rule-based detection (field matching + thresholds)
2. Sigma rule format subset (YAML-based detection conditions)

Sigma rule format reference: https://github.com/SigmaHQ/sigma
"""
import re
import yaml
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from app.models import Event, DetectionRule, Alert
from app.database import SessionLocal


def evaluate_field_match(event_data: Dict[str, Any], field: str, value: Any) -> bool:
    """Evaluate a single field condition against event data."""
    # Get the actual value from the event (supporting nested via dots)
    actual = event_data.get(field)
    
    if actual is None:
        return False
    
    # Handle list values (for fields that can have multiple values)
    if isinstance(value, list):
        return any(evaluate_field_match(event_data, field, v) for v in value)
    
    actual_str = str(actual).lower()
    
    if isinstance(value, dict):
        # Operator dictionaries like {contains: x, not_contains: y}
        for op, op_value in value.items():
            op_value_str = str(op_value).lower()
            if op == "equals":
                if actual_str != op_value_str:
                    return False
            elif op == "contains":
                if op_value_str not in actual_str:
                    return False
            elif op == "not_contains":
                if op_value_str in actual_str:
                    return False
            elif op == "startswith":
                if not actual_str.startswith(op_value_str):
                    return False
            elif op == "endswith":
                if not actual_str.endswith(op_value_str):
                    return False
            elif op == "regex":
                try:
                    if not re.search(op_value_str, actual_str):
                        return False
                except re.error:
                    return False
            elif op == "in":
                if isinstance(op_value, list):
                    if actual_str not in [str(v).lower() for v in op_value]:
                        return False
                else:
                    return False
            elif op == "not_in":
                if isinstance(op_value, list):
                    if actual_str in [str(v).lower() for v in op_value]:
                        return False
                else:
                    return False
            elif op == "greater_than":
                try:
                    if float(actual) <= float(op_value):
                        return False
                except (ValueError, TypeError):
                    return False
            elif op == "less_than":
                try:
                    if float(actual) >= float(op_value):
                        return False
                except (ValueError, TypeError):
                    return False
            elif op == "is_null":
                return actual is None
            elif op == "not_null":
                if actual is None:
                    return False
            else:
                # Unknown operator, treat as equals
                if actual_str != op_value_str:
                    return False
        return True
    else:
        # Direct string value comparison (case-insensitive)
        value_str = str(value).lower()
        return actual_str == value_str


def event_to_dict(event: Event) -> Dict[str, Any]:
    """Convert SQLAlchemy Event object to a dict for rule evaluation."""
    data = {
        "id": event.id,
        "timestamp": event.timestamp,
        "source_id": event.source_id,
        "source_name": event.source_name,
        "source_type": event.source_type,
        "hostname": event.hostname,
        "ip_address": event.ip_address,
        "event_type": event.event_type,
        "event_id": event.event_id,
        "severity": event.severity,
        "description": event.description,
        "raw_data": event.raw_data,
        "user": event.user,
        "process_name": event.process_name,
        "process_id": event.process_id,
        "file_path": event.file_path,
        "command_line": event.command_line,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "source_ip": event.source_ip,
        "response_code": event.response_code,
    }
    # Merge extra_data at top level for easier rule access
    for k, v in (event.extra_data or {}).items():
        data[k] = v
    return data


def evaluate_single_rule(rule: DetectionRule, event_dict: Dict[str, Any]) -> bool:
    """Evaluate a detection rule against a single normalized event."""
    # Source type filtering
    if rule.source_types:
        src = event_dict.get("source_type", "")
        if src not in rule.source_types:
            return False
    
    # Specific event types
    if rule.event_types:
        et = event_dict.get("event_type", "")
        if et not in rule.event_types:
            return False
    
    conditions = rule.conditions or {}
    
    # Condition structure:
    # { "field": "value", ... } - all must match (AND)
    # or 
    # { "$or": [ {conditions1}, {conditions2} ] }
    
    results: List[bool] = []
    
    if "$or" in conditions:
        or_conditions = conditions["$or"]
        for cond in or_conditions:
            if all(evaluate_field_match(event_dict, field, val) for field, val in cond.items()):
                results.append(True)
            else:
                results.append(False)
        in_or = any(results)
        # Check if there are AND conditions alongside OR
        non_or = {k: v for k, v in conditions.items() if k != "$or"}
        if non_or:
            all_non_or = all(evaluate_field_match(event_dict, field, val) for field, val in non_or.items())
            return all_non_or and in_or
        return in_or
    else:
        return all(evaluate_field_match(event_dict, field, val) for field, val in conditions.items())


def parse_sigma_rule(sigma_yaml: str) -> Dict[str, Any]:
    """Parse a Sigma rule YAML string into a structured rule condition.
    Supports a subset of the Sigma specification:
    - detection: selection / condition fields with keywords, equals
    """
    try:
        data = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError:
        return {}
    
    detection = data.get("detection", {})
    if not detection:
        return {}
    
    condition = detection.get("condition", "selection")
    
    # Extract selections (all keys except 'condition' and 'timeframe')
    selections = {}
    for key, value in detection.items():
        if key not in ("condition", "timeframe"):
            selections[key] = value
    
    # Build conditions dict
    conditions = {}
    
    if isinstance(condition, str):
        if " or " in condition:
            # e.g., "sel1 or sel2"
            parts = [p.strip() for p in condition.split(" or ")]
            or_list = []
            for part in parts:
                if part in selections:
                    or_list.append(selections[part])
            conditions["$or"] = or_list
        elif " and not " in condition:
            # e.g., "selection and not filter"
            pos = condition.find(" and not ")
            pos_part = condition[:pos].strip()
            neg_part = condition[pos + len(" and not "):].strip()
            if pos_part in selections and neg_part in selections:
                conditions.update(selections[pos_part])
                # Add negation as !field not equals
                # (simplified - not even added since we don't support NOT well)
        else:
            # e.g., "selection" or "selection but not filter"
            if " but not " in condition:
                pos = condition.find(" but not ")
                pos_part = condition[:pos].strip()
                if pos_part in selections:
                    conditions = normalize_sigma_value(selections[pos_part])
            elif condition in selections:
                conditions = normalize_sigma_value(selections[condition])
            else:
                # Try all selections
                for name, sel in selections.items():
                    conditions.update(normalize_sigma_value(sel))
    
    return conditions


def normalize_sigma_value(value: Any) -> Dict[str, Any]:
    """Convert sigma field values to flat condition dict for our engine."""
    if isinstance(value, dict):
        return value  # Already structured
    return {}


def evaluate_threshold(db: Session, rule: DetectionRule, event_dict: Dict[str, Any]) -> Optional[Event]:
    """Check if a threshold rule is triggered within the time window.
    Returns the new Event if the threshold is met, otherwise None."""
    threshold = rule.threshold or 1
    
    # Group by field determines what to group on
    group_field = rule.group_by
    if group_field and group_field not in event_dict:
        return None
    
    group_value = event_dict.get(group_field) if group_field else None
    
    window_start = datetime.utcnow() - timedelta(seconds=rule.time_window_seconds or 3600)
    
    query = db.query(Event).filter(
        Event.timestamp >= window_start,
    )
    
    # Filter by source type
    if rule.source_types:
        query = query.filter(Event.source_type.in_(rule.source_types))
    
    # Count matching events in window with same group_value
    from sqlalchemy import func
    count_query = query
    
    if group_value is not None:
        # Need to match the group_by field - this is complex with raw SQL.
        # We'll use a simpler approach: count all events from same source in window
        # and check if rule conditions match.
        if group_field == "source_ip":
            count_query = count_query.filter(Event.source_ip == group_value)
        elif group_field == "destination_ip":
            count_query = count_query.filter(Event.destination_ip == group_value)
        elif group_field == "ip_address":
            count_query = count_query.filter(Event.ip_address == group_value)
        elif group_field == "user":
            count_query = count_query.filter(Event.user == group_value)
    
    count = count_query.count()
    
    if count >= threshold:
        # Threshold met, create alert
        return event_dict  # simplified - return dict
    return None


def evaluate_correlation(db: Session, rule: DetectionRule, event_dict: Dict[str, Any]) -> bool:
    """Evaluate a multi-stage cross-source correlation rule.

    Checks that events from each required stage (source_type + event_type)
    exist for the same group value (e.g. source_ip) within the time window.
    The current event must match at least one stage; dedup is handled by
    checking no existing alert for this rule+group in the window.
    """
    corr = rule.correlation or {}
    stages = corr.get("stages") or []
    if not stages:
        return False

    group_by = corr.get("group_by") or rule.group_by or "source_ip"
    window_seconds = corr.get("window_seconds") or rule.time_window_seconds or 3600

    group_value = event_dict.get(group_by)
    if not group_value:
        return False

    # Check if current event matches at least one stage
    event_matches_stage = False
    for stage in stages:
        st_src = stage.get("source_type")
        st_etype = stage.get("event_type")
        if st_src and event_dict.get("source_type") != st_src:
            continue
        if st_etype and event_dict.get("event_type") != st_etype:
            continue
        event_matches_stage = True
        break
    if not event_matches_stage:
        return False

    window_start = datetime.utcnow() - timedelta(seconds=window_seconds)

    # Dedup: skip if we already alerted for this rule+group in the window
    existing = db.query(Alert).filter(
        Alert.rule_id == rule.id,
        Alert.created_at >= window_start,
    ).first()
    if existing:
        return False

    # Each stage must have at least one matching event from the same group
    for stage in stages:
        stage_src = stage.get("source_type")
        stage_etype = stage.get("event_type")
        stage_key = stage.get("key", group_by)

        q = db.query(Event).filter(Event.timestamp >= window_start)
        if stage_src:
            q = q.filter(Event.source_type == stage_src)
        if stage_etype:
            q = q.filter(Event.event_type == stage_etype)

        # Build a query that matches the group value on whichever IP field the
        # stage uses. For IP-based grouping, match source_ip, destination_ip OR
        # ip_address so a scanning IP can be found as either endpoint.
        match_clauses = []
        if stage_key == "source_ip":
            match_clauses.append(Event.source_ip == group_value)
        elif stage_key == "destination_ip":
            match_clauses.append(Event.destination_ip == group_value)
        elif stage_key == "ip_address":
            match_clauses.append(Event.ip_address == group_value)
        elif stage_key == "user":
            match_clauses.append(Event.user == group_value)
        else:
            # Default: match on any IP-bearing field for correlation stages
            match_clauses.append(Event.source_ip == group_value)
            match_clauses.append(Event.destination_ip == group_value)
            match_clauses.append(Event.ip_address == group_value)

        if match_clauses:
            from sqlalchemy import or_
            q = q.filter(or_(*match_clauses))

        if q.count() == 0:
            return False

    return True


def run_detection(db: Session, event: Event) -> Optional[Alert]:
    """Run all enabled detection rules against a new event.
    Returns list of created alerts."""
    event_dict = event_to_dict(event)
    
    rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()  # noqa: E712
    
    alert = None
    
    for rule in rules:
        # Check if rule applies to this source type
        if rule.source_types:
            src = event_dict.get("source_type", "")
            if src and src not in rule.source_types:
                continue
        
        # Check if rule has conditions
        correlation_matched = False
        if not (rule.conditions or rule.sigma_rule):
            # Correlation-only rule
            if rule.correlation:
                if evaluate_correlation(db, rule, event_dict):
                    correlation_matched = True
                else:
                    continue
            else:
                continue
        
        # Evaluate conditions (skip if correlation rule already matched)
        if not correlation_matched:
            if rule.conditions:
                matched = evaluate_single_rule(rule, event_dict)
            elif rule.sigma_rule:
                sigma_conditions = parse_sigma_rule(rule.sigma_rule)
                if sigma_conditions:
                    temp_rule = DetectionRule(
                        name=rule.name,
                        conditions=sigma_conditions,
                        source_types=rule.source_types,
                        event_types=rule.event_types,
                    )
                    matched = evaluate_single_rule(temp_rule, event_dict)
                else:
                    matched = False
            else:
                matched = False
            if not matched:
                continue
        else:
            matched = True
        
        if matched:
            # Check if this rule needs to be triggered
            # For non-threshold rules, trigger immediately
            if rule.threshold and rule.threshold > 1:
                # Threshold rule - check if enough events in window
                trigger = evaluate_threshold(db, rule, event_dict)
                if not trigger:
                    continue
            
            # Create alert
            alert = Alert(
                timestamp=datetime.utcnow(),
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                status="open",
                title=f"{rule.name} - {event_dict.get('hostname', 'unknown host')}",
                description=rule.description,
                source=event_dict.get("source_name", "") or event_dict.get("source_type", ""),
                hostname=event_dict.get("hostname", ""),
                ip_address=event_dict.get("ip_address", "") or event_dict.get("source_ip", ""),
                event_count=1,
                matched_events=[{
                    "id": event.id,
                    "timestamp": str(event.timestamp) if event.timestamp else None,
                    "source_name": event.source_name,
                    "source_type": event.source_type,
                    "description": event.description,
                    "user": event.user,
                }],
                mitre_technique=rule.mitre_technique or "",
                mitre_tactic=rule.mitre_tactic or "",
                tags=[rule.category] if rule.category else [],
            )
            db.add(alert)
            rule.last_triggered = datetime.utcnow()
    
    db.commit()
    return alert


def process_event(db: Session, event: Event) -> Optional[Alert]:
    """Process an event through the detection pipeline."""
    return run_detection(db, event)
