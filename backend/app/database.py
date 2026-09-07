import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import Config


def _get_engine_kwargs(url: str):
    """Return create_engine kwargs appropriate for the DB back-end."""
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    # Postgres/MySQL over the network: require SSL and add pool settings
    return {
        "connect_args": {"sslmode": "require"} if url.startswith(("postgres", "postgresql")) else {},
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }


engine = create_engine(
    Config.get_database_url(),
    **_get_engine_kwargs(Config.get_database_url()),
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
