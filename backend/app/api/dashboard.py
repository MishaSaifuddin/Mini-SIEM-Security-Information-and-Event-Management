from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta

from app.database import get_db
from app.models import Event, Alert, LogSource, DetectionRule
from app.core.security import get_current_user
from app.db_utils import hour_trunc

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
    hours: int = Query(24, ge=1, le=24 * 90),
):
    """Get comprehensive dashboard summary."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Total events
    total_events = db.query(func.count(Event.id)).filter(Event.timestamp >= since).scalar() or 0
    
    # Events per second/minute
    events_per_min = round(total_events / max(hours * 60, 1), 2)
    
    # Alerts
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.timestamp >= since).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= since, Alert.status == "open"
    ).scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= since, Alert.severity == "critical"
    ).scalar() or 0
    high_alerts = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= since, Alert.severity == "high"
    ).scalar() or 0
    
    # Log sources
    total_sources = db.query(func.count(LogSource.id)).scalar() or 0
    active_sources = db.query(func.count(LogSource.id)).filter(
        LogSource.last_seen >= since
    ).scalar() or 0
    
    # Active rules
    active_rules = db.query(func.count(DetectionRule.id)).filter(
        DetectionRule.enabled == True  # noqa: E712
    ).scalar() or 0
    
    # Event timeline (last 24h hourly)
    event_timeline = (
        db.query(
            hour_trunc(Event.timestamp).label('hour'),
            func.count(Event.id),
        )
        .filter(Event.timestamp >= since)
        .group_by('hour')
        .order_by('hour')
        .all()
    )
    
    # Alert timeline
    alert_timeline = (
        db.query(
            hour_trunc(Alert.timestamp).label('hour'),
            func.count(Alert.id),
        )
        .filter(Alert.timestamp >= since)
        .group_by('hour')
        .order_by('hour')
        .all()
    )
    
    # Top sources
    top_sources = (
        db.query(
            Event.source_name,
            Event.source_type,
            func.count(Event.id).label('count'),
        )
        .filter(Event.timestamp >= since)
        .group_by(Event.source_name, Event.source_type)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    
    # Top event types
    top_event_types = (
        db.query(
            Event.event_type,
            func.count(Event.id).label('count'),
        )
        .filter(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    
    # Recent alerts
    recent_alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(10).all()
    
    # Severity distribution of events
    event_severity = dict(
        db.query(Event.severity, func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by(Event.severity)
        .all()
    )
    
    # Alert severity distribution
    alert_severity = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.severity)
        .all()
    )
    
    # Top alert rules
    top_rules = (
        db.query(Alert.rule_name, func.count(Alert.id).label('count'))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    
    return {
        "kpis": {
            "total_events": total_events,
            "events_per_min": events_per_min,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_sources": total_sources,
            "active_sources": active_sources,
            "active_rules": active_rules,
        },
        "event_timeline": [{"timestamp": h, "count": c} for h, c in event_timeline],
        "alert_timeline": [{"timestamp": h, "count": c} for h, c in alert_timeline],
        "top_sources": [
            {"name": s.source_name, "type": s.source_type, "count": s.count}
            for s in top_sources
        ],
        "top_event_types": [{"type": t.event_type, "count": t.count} for t in top_event_types],
        "event_severity": event_severity,
        "alert_severity": alert_severity,
        "top_rules": [{"rule": r.rule_name, "count": r.count} for r in top_rules],
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "timestamp": str(a.timestamp) if a.timestamp else None,
            }
            for a in recent_alerts
        ],
    }
