"""Database engine, session management, and snapshot/reset utilities.

The snapshot/reset helpers give the evaluation harness an AgentDojo-style
pre_environment / post_environment contract: snapshot before a trial, run the
agents, score against the diff, then restore before the next trial.
"""
from __future__ import annotations

import shutil
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app import config

# check_same_thread=False so the dev server and harness can share the file.
engine = create_engine(
    config.DB_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_session() -> Session:
    """FastAPI dependency: yields a session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Session:
    """Standalone transactional scope for scripts and the harness."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def snapshot() -> None:
    """Copy the live DB file to the snapshot path (pre_environment)."""
    engine.dispose()  # flush WAL / release the file handle
    shutil.copy2(config.DB_PATH, config.SNAPSHOT_PATH)


def reset() -> None:
    """Restore the live DB file from the snapshot (post-trial cleanup)."""
    if not config.SNAPSHOT_PATH.exists():
        raise FileNotFoundError("No snapshot exists; call snapshot() first.")
    engine.dispose()
    shutil.copy2(config.SNAPSHOT_PATH, config.DB_PATH)
