import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from src.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger("database")

Base = declarative_base()

def get_engine():
    cfg = get_config()
    db_url = cfg.database_url
    if db_url.startswith("sqlite:///"):
        # Ensure parent folder exists
        sqlite_path = db_url.replace("sqlite:///", "")
        db_dir = os.path.dirname(sqlite_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    eng = create_engine(
        db_url,
        connect_args={"check_same_thread": False, "timeout": 30} if db_url.startswith("sqlite") else {},
        pool_pre_ping=True
    )
    if db_url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
            cursor.close()
    return eng

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initializes database schema and ensures required tables exist."""
    # Ensure all models are imported before creating tables
    import src.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables verified/created successfully.")

@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session scope."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Database session rollback due to error: {exc}", exc_info=True)
        raise
    finally:
        session.close()
