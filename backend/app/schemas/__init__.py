from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class LogSourceCreate(BaseModel):
    name: str
    source_type: str
    hostname: str = ""
    ip_address: str = ""
    description: str = ""


class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


class LogSourceOut(BaseModel):
    id: int
    name: str
    source_type: str
    hostname: str
    ip_address: str
    description: str
    enabled: bool
    created_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True


class EventIngest(BaseModel):
    timestamp: Optional[datetime] = None
    source_id: Optional[int] = None
    source_name: str = ""
    source_type: str = ""
    hostname: str = ""
    ip_address: str = ""
    event_type: str = ""
    event_id: str = ""
    severity: str = "info"
    description: str = ""
    raw_data: str = ""
    user: str = ""
    process_name: str = ""
    process_id: str = ""
    file_path: str = ""
    command_line: str = ""
    destination_ip: str = ""
    destination_port: Optional[int] = None
    source_ip: str = ""
    response_code: str = ""
    extra_data: Dict[str, Any] = Field(default_factory=dict)


class EventBatchIngest(BaseModel):
    events: List[EventIngest]


class EventOut(BaseModel):
    id: int
    timestamp: Optional[datetime] = None
    source_id: Optional[int] = None
    source_name: str = ""
    source_type: str = ""
    hostname: str = ""
    ip_address: str = ""
    event_type: str = ""
    event_id: str = ""
    severity: str = "info"
    description: str = ""
    raw_data: str = ""
    user: str = ""
    process_name: str = ""
    process_id: str = ""
    file_path: str = ""
    command_line: str = ""
    destination_ip: str = ""
    destination_port: Optional[int] = None
    source_ip: str = ""
    response_code: str = ""
    extra_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class RuleCreate(BaseModel):
    name: str
    rule_id: str
    description: str = ""
    severity: str = "medium"
    category: str = ""
    enabled: bool = True
    source_types: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    event_types: List[str] = Field(default_factory=list)
    threshold: int = 1
    time_window_seconds: int = 3600
    group_by: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    enabled: Optional[bool] = None
    source_types: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    event_types: Optional[List[str]] = None
    threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None
    group_by: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


class RuleOut(BaseModel):
    id: int
    name: str
    rule_id: str
    description: str = ""
    severity: str = "medium"
    category: str = ""
    enabled: bool = True
    source_types: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    event_types: List[str] = Field(default_factory=list)
    threshold: int = 1
    time_window_seconds: int = 3600
    group_by: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_triggered: Optional[datetime] = None

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    resolution_notes: Optional[str] = None


class AlertOut(BaseModel):
    id: int
    timestamp: Optional[datetime] = None
    rule_id: Optional[int] = None
    rule_name: str = ""
    severity: str = "medium"
    status: str = "open"
    title: str = ""
    description: str = ""
    source: str = ""
    hostname: str = ""
    ip_address: str = ""
    event_count: int = 1
    matched_events: List[Any] = Field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    tags: List[str] = Field(default_factory=list)
    assignee: str = ""
    resolution_notes: str = ""
    resolved_by: str = ""
    resolved_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RuleTestResult(BaseModel):
    rule_id: str
    rule_name: str
    matched: bool
    matched_events: List[Any] = Field(default_factory=list)
    details: str = ""
