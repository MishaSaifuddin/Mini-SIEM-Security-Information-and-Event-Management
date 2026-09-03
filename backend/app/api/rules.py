from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.models import DetectionRule, Event
from app.schemas import RuleCreate, RuleUpdate, RuleOut, RuleTestResult
from app.services.detection_engine import evaluate_single_rule, event_to_dict, parse_sigma_rule
from app.core.security import get_current_user

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    return db.query(DetectionRule).order_by(DetectionRule.severity).all()


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(rule_id: int, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("/", response_model=RuleOut, status_code=201)
def create_rule(rule_data: RuleCreate, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    existing = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_data.rule_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule ID already exists")
    
    rule = DetectionRule(
        name=rule_data.name,
        rule_id=rule_data.rule_id,
        description=rule_data.description,
        severity=rule_data.severity,
        category=rule_data.category,
        enabled=rule_data.enabled,
        source_types=rule_data.source_types,
        conditions=rule_data.conditions,
        event_types=rule_data.event_types,
        threshold=rule_data.threshold,
        time_window_seconds=rule_data.time_window_seconds,
        group_by=rule_data.group_by,
        mitre_technique=rule_data.mitre_technique,
        mitre_tactic=rule_data.mitre_tactic,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: int, rule_data: RuleUpdate, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    update_data = rule_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}


@router.post("/test", response_model=RuleTestResult)
def test_rule(rule_data: RuleCreate, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    """Test a rule against recent events."""
    from sqlalchemy import desc
    recent_events = db.query(Event).order_by(desc(Event.timestamp)).limit(100).all()
    
    temp_rule = DetectionRule(
        name=rule_data.name,
        rule_id=rule_data.rule_id,
        severity=rule_data.severity,
        source_types=rule_data.source_types,
        conditions=rule_data.conditions,
        event_types=rule_data.event_types,
        threshold=rule_data.threshold,
        time_window_seconds=rule_data.time_window_seconds,
        group_by=rule_data.group_by,
    )
    
    matched_events = []
    for event in recent_events:
        event_dict = event_to_dict(event)
        if evaluate_single_rule(temp_rule, event_dict):
            matched_events.append({
                "id": event.id,
                "timestamp": str(event.timestamp) if event.timestamp else None,
                "source_name": event.source_name,
                "source_type": event.source_type,
                "description": event.description,
                "user": event.user,
            })
    
    return RuleTestResult(
        rule_id=rule_data.rule_id,
        rule_name=rule_data.name,
        matched=len(matched_events) > 0,
        matched_events=matched_events[:10],
        details=f"Tested against {len(recent_events)} recent events. {len(matched_events)} matched.",
    )


@router.post("/sigma")
def import_sigma_rule(
    rule_data: dict,
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
):
    """Import a Sigma YAML rule."""
    import yaml
    sigma_yaml = rule_data.get("sigma_rule", "")
    
    try:
        parsed = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)}")
    
    if not parsed or "detection" not in parsed:
        raise HTTPException(status_code=400, detail="Invalid Sigma rule - missing 'detection' section")
    
    title = parsed.get("title", rule_data.get("name", "Imported Sigma Rule"))
    rule_id = parsed.get("id", rule_data.get("rule_id", f"sigma-{datetime.utcnow().timestamp()}"))
    severity = parsed.get("level", rule_data.get("severity", "medium"))
    description = parsed.get("description", "")
    
    # Map lambda levels to severity
    severity_map = {
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    severity = severity_map.get(str(severity).lower(), severity)
    
    # MITRE mapping
    mitre = parsed.get("tags", [])
    mitre_tactic = ""
    mitre_technique = ""
    for tag in mitre:
        if tag.startswith("attack.t") and not mitre_technique:
            mitre_technique = tag
        if tag.startswith("attack.") and not mitre_tactic:
            mitre_tactic = tag
    
    existing = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
    source_types = rule_data.get("source_types", [])
    
    conditions = parse_sigma_rule(sigma_yaml)
    
    if existing:
        existing.name = title
        existing.description = description
        existing.severity = severity
        existing.sigma_rule = sigma_yaml
        existing.conditions = conditions
        existing.source_types = source_types
        if mitre_technique:
            existing.mitre_technique = mitre_technique
        if mitre_tactic:
            existing.mitre_tactic = mitre_tactic
        db.commit()
        db.refresh(existing)
        return existing
    
    rule = DetectionRule(
        name=title,
        rule_id=str(rule_id),
        description=description,
        severity=severity,
        category="sigma",
        enabled=True,
        source_types=source_types,
        conditions=conditions,
        sigma_rule=sigma_yaml,
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule
