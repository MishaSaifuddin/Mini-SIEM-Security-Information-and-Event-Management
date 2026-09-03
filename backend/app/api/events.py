from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_
from datetime import datetime, timedelta
from typing import Optional, List

from app.database import get_db
from app.models import Event, LogSource, Alert, DetectionRule
from app.schemas import EventIngest, EventBatchIngest, EventOut
from app.services.normalizer import LogNormalizer
from app.services.detection_engine import process_event
from app.core.security import get_current_user

router = APIRouter(prefix="/events", tags=["events"])


def ingest_single_event(db: Session, event_data: EventIngest) -> Event:
    """Normalize and store a single event, then run detection."""
    # Normalize
    event_data = LogNormalizer.normalize(event_data)
    
    # Find source if source_id not provided
    source_id = event_data.source_id
    if not source_id:
        # Try to match by name/source_type
        source = None
        if event_data.source_name:
            source = db.query(LogSource).filter(
                LogSource.name == event_data.source_name
            ).first()
        if not source and event_data.ip_address:
            source = db.query(LogSource).filter(
                LogSource.ip_address == event_data.ip_address
            ).first()
        if not source and event_data.source_name:
            # Create source on-the-fly
            source = LogSource(
                name=event_data.source_name,
                source_type=event_data.source_type or "custom",
                ip_address=event_data.ip_address,
            )
            db.add(source)
            db.flush()
        
        if source:
            source_id = source.id
            # Update last seen
            source.last_seen = datetime.utcnow()
    
    event = Event(
        timestamp=event_data.timestamp or datetime.utcnow(),
        source_id=source_id,
        source_name=event_data.source_name,
        source_type=event_data.source_type,
        hostname=event_data.hostname,
        ip_address=event_data.ip_address,
        event_type=event_data.event_type,
        event_id=event_data.event_id,
        severity=event_data.severity,
        description=event_data.description,
        raw_data=event_data.raw_data,
        user=event_data.user,
        process_name=event_data.process_name,
        process_id=event_data.process_id,
        file_path=event_data.file_path,
        command_line=event_data.command_line,
        destination_ip=event_data.destination_ip,
        destination_port=event_data.destination_port,
        source_ip=event_data.source_ip,
        response_code=event_data.response_code,
        extra_data=event_data.extra_data,
    )
    db.add(event)
    db.flush()
    
    # Run detection
    alert = process_event(db, event)
    
    return event


@router.post("/ingest", response_model=EventOut, status_code=201)
def ingest_event(event_data: EventIngest, db: Session = Depends(get_db)):
    """Ingest a single log event."""
    event = ingest_single_event(db, event_data)
    db.commit()
    db.refresh(event)
    return event


@router.post("/ingest/batch")
def ingest_batch(batch: EventBatchIngest, db: Session = Depends(get_db)):
    """Ingest a batch of log events."""
    ingested = 0
    for event_data in batch.events:
        ingest_single_event(db, event_data)
        ingested += 1
    db.commit()
    return {"ingested": ingested, "message": f"Successfully ingested {ingested} events"}


@router.get("/", response_model=List[EventOut])
def list_events(
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    source_type: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    user: Optional[str] = None,
    search: Optional[str] = None,
    from_time: Optional[datetime] = None,
    to_time: Optional[datetime] = None,
):
    query = db.query(Event)
    
    if source_type:
        query = query.filter(Event.source_type == source_type)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if severity:
        query = query.filter(Event.severity == severity)
    if hostname:
        query = query.filter(Event.hostname.ilike(f"%{hostname}%"))
    if ip:
        query = query.filter(or_(
            Event.ip_address == ip,
            Event.source_ip == ip,
            Event.destination_ip == ip,
        ))
    if user:
        query = query.filter(Event.user.ilike(f"%{user}%"))
    if search:
        query = query.filter(or_(
            Event.description.ilike(f"%{search}%"),
            Event.raw_data.ilike(f"%{search}%"),
            Event.process_name.ilike(f"%{search}%"),
            Event.command_line.ilike(f"%{search}%"),
        ))
    if from_time:
        query = query.filter(Event.timestamp >= from_time)
    if to_time:
        query = query.filter(Event.timestamp <= to_time)
    
    total = query.count()
    events = query.order_by(desc(Event.timestamp)).offset(offset).limit(limit).all()
    
    # Attach total via response header style
    events_out = [EventOut.model_validate(e) for e in events]
    return events_out


@router.get("/stats")
def event_stats(
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
    hours: int = Query(24, ge=1, le=24 * 30),
):
    """Get event statistics over time period."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total = db.query(func.count(Event.id)).filter(Event.timestamp >= since).scalar() or 0
    
    # Count by severity
    severity_counts = dict(
        db.query(Event.severity, func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by(Event.severity)
        .all()
    )
    
    # Count by source type
    source_counts = dict(
        db.query(Event.source_type, func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by(Event.source_type)
        .all()
    )
    
    # Count by event type
    event_type_counts = dict(
        db.query(Event.event_type, func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    
    # Timeline data (hourly buckets)
    from sqlalchemy import extract
    timeline = (
        db.query(
            func.strftime('%Y-%m-%d %H:00', Event.timestamp).label('hour'),
            func.count(Event.id)
        )
        .filter(Event.timestamp >= since)
        .group_by('hour')
        .order_by('hour')
        .all()
    )
    
    return {
        "total": total,
        "severity_counts": severity_counts,
        "source_type_counts": source_counts,
        "event_type_counts": event_type_counts,
        "timeline": [{"timestamp": h, "count": c} for h, c in timeline],
    }


@router.get("/sources")
def list_event_sources(db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    """List distinct event sources."""
    sources = (
        db.query(
            Event.source_type,
            Event.source_name,
            func.count(Event.id).label('event_count'),
            func.max(Event.timestamp).label('last_event'),
        )
        .group_by(Event.source_type, Event.source_name)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    return [
        {
            "source_type": s.source_type,
            "source_name": s.source_name,
            "event_count": s.event_count,
            "last_event": s.last_event,
        }
        for s in sources
    ]


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
