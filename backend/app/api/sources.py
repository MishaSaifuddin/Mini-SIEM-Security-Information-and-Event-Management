from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from datetime import datetime, timedelta

from app.database import get_db
from app.models import LogSource
from app.schemas import LogSourceCreate, LogSourceUpdate, LogSourceOut
from app.core.security import get_current_user

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("/", response_model=list[LogSourceOut])
def list_sources(db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    return db.query(LogSource).order_by(LogSource.name).all()


@router.post("/", response_model=LogSourceOut, status_code=201)
def create_source(
    source_data: LogSourceCreate,
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
):
    source = LogSource(
        name=source_data.name,
        source_type=source_data.source_type,
        hostname=source_data.hostname,
        ip_address=source_data.ip_address,
        description=source_data.description,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.put("/{source_id}", response_model=LogSourceOut)
def update_source(
    source_id: int,
    source_data: LogSourceUpdate,
    db: Session = Depends(get_db),
    _: object = Depends(get_current_user),
):
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    
    update_data = source_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(source, field, value)
    db.commit()
    db.refresh(source)
    return source


@router.delete("/{source_id}")
def delete_source(source_id: int, db: Session = Depends(get_db), _: object = Depends(get_current_user)):
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    db.delete(source)
    db.commit()
    return {"message": "Source deleted"}
