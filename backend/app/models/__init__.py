from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON, ForeignKey, Index, LargeBinary
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    source_type = Column(String(50), nullable=False)
    hostname = Column(String(100), default="")
    ip_address = Column(String(45), default="")
    description = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_source_id", "source_id"),
        Index("idx_events_severity", "severity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_id = Column(Integer, ForeignKey("log_sources.id"), nullable=True)
    source_name = Column(String(100), default="")
    source_type = Column(String(50), default="")
    hostname = Column(String(100), default="")
    ip_address = Column(String(45), default="")
    event_type = Column(String(100), default="")
    event_id = Column(String(100), default="")
    severity = Column(String(20), default="info")
    description = Column(Text, default="")
    raw_data = Column(Text, default="")
    user = Column(String(100), default="")
    process_name = Column(String(255), default="")
    process_id = Column(String(50), default="")
    file_path = Column(String(1024), default="")
    command_line = Column(Text, default="")
    destination_ip = Column(String(45), default="")
    destination_port = Column(Integer, nullable=True)
    source_ip = Column(String(45), default="")
    response_code = Column(String(20), default="")
    extra_data = Column(JSON, default=dict)
    normalized = Column(Boolean, default=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    rule_id = Column(String(100), unique=True, index=True)
    description = Column(Text, default="")
    severity = Column(String(20), default="medium")
    category = Column(String(100), default="")
    enabled = Column(Boolean, default=True)
    source_types = Column(JSON, default=list)
    conditions = Column(JSON, default=dict)
    event_types = Column(JSON, default=list)
    threshold = Column(Integer, default=1)
    time_window_seconds = Column(Integer, default=3600)
    group_by = Column(String(100), default="")
    mitre_technique = Column(String(100), default="")
    mitre_tactic = Column(String(100), default="")
    correlation = Column(JSON, default=dict)
    sigma_rule = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_triggered = Column(DateTime, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("idx_alerts_timestamp", "timestamp"),
        Index("idx_alerts_severity", "severity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)
    rule_name = Column(String(200), default="")
    severity = Column(String(20), default="medium")
    status = Column(String(20), default="open")
    title = Column(String(300), default="")
    description = Column(Text, default="")
    source = Column(String(100), default="")
    hostname = Column(String(100), default="")
    ip_address = Column(String(45), default="")
    event_count = Column(Integer, default=1)
    matched_events = Column(JSON, default=list)
    mitre_technique = Column(String(100), default="")
    mitre_tactic = Column(String(100), default="")
    tags = Column(JSON, default=list)
    assignee = Column(String(100), default="")
    resolution_notes = Column(Text, default="")
    resolved_by = Column(String(100), default="")
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
