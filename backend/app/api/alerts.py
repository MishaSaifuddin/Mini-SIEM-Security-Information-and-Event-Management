from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from datetime import datetime, timedelta
from typing import Optional, List

from app.database import get_db
from app.models import Alert, Event
from app.schemas import AlertUpdate, AlertOut
from app.core.security import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
def list_alerts(
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    search: Optional[str] = None,
):
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if search:
        query = query.filter(Alert.title.ilike(f"%{search}%"))
    
    total = query.count()
    alerts = query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()
    return {"total": total, "alerts": [AlertOut.model_validate(a) for a in alerts]}


@router.get("/stats")
def alert_stats(
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
    hours: int = Query(24, ge=1, le=24 * 90),
):
    """Get alert statistics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total = db.query(func.count(Alert.id)).filter(Alert.timestamp >= since).scalar() or 0
    open_count = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= since, Alert.status == "open"
    ).scalar() or 0
    
    severity_counts = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.severity)
        .all()
    )
    
    status_counts = dict(
        db.query(Alert.status, func.count(Alert.id))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.status)
        .all()
    )
    
    rule_counts = dict(
        db.query(Alert.rule_name, func.count(Alert.id))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    
    timeline = (
        db.query(
            func.strftime('%Y-%m-%d %H:00', Alert.timestamp).label('hour'),
            func.count(Alert.id)
        )
        .filter(Alert.timestamp >= since)
        .group_by('hour')
        .order_by('hour')
        .all()
    )
    
    return {
        "total": total,
        "open": open_count,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "rule_counts": rule_counts,
        "timeline": [{"timestamp": h, "count": c} for h, c in timeline],
    }


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: object = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    update_data = alert_data.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(alert, field, value)
    
    if "status" in update_data and update_data["status"] in ("resolved", "false_positive", "closed"):
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = current_user.username
    
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/related-events")
def get_related_events(
    alert_id: int,
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
):
    """Get events related to an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    matched = alert.matched_events or []
    event_ids = [m.get("id") for m in matched if m.get("id")]
    
    if not event_ids:
        # Look for events matching alert criteria
        query = db.query(Event)
        if alert.hostname:
            query = query.filter(Event.hostname == alert.hostname)
        if alert.ip_address:
            query = query.filter(
                (Event.ip_address == alert.ip_address) |
                (Event.source_ip == alert.ip_address) |
                (Event.destination_ip == alert.ip_address)
            )
        events = query.order_by(desc(Event.timestamp)).limit(50).all()
    else:
        events = db.query(Event).filter(Event.id.in_(event_ids)).all()
    
    from app.schemas import EventOut
    return [EventOut.model_validate(e) for e in events]
