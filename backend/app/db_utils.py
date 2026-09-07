"""Database-dialect-agnostic SQL helpers for the SIEM app."""
from sqlalchemy import func
from app.database import engine
from app.config import Config

_db_url = Config.get_database_url()
IS_SQLITE = _db_url.startswith("sqlite")


def hour_trunc(column):
    """Return a SQL expression truncating a timestamp column to the hour,
    compatible with both SQLite and PostgreSQL."""
    if IS_SQLITE:
        return func.strftime("%Y-%m-%d %H:00", column)
    return func.date_trunc("hour", column)