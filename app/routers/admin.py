"""Admin and evaluation-support endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app import db as dbmod
from app.db import get_session
from app.models import ActionLog, AgentHandoff, Customer, Ticket

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/health")
def health(db: Session = Depends(get_session)):
    return {
        "status": "ok",
        "customers": db.scalar(select(func.count()).select_from(Customer)),
        "tickets": db.scalar(select(func.count()).select_from(Ticket)),
    }


@router.post("/snapshot")
def make_snapshot():
    dbmod.snapshot()
    return {"status": "snapshot_taken"}


@router.post("/reset")
def do_reset():
    dbmod.reset()
    return {"status": "reset_from_snapshot"}


@router.get("/action-log")
def action_log(run_id: str | None = None, db: Session = Depends(get_session)):
    stmt = select(ActionLog).order_by(ActionLog.id)
    if run_id:
        stmt = stmt.where(ActionLog.run_id == run_id)
    rows = db.scalars(stmt).all()
    return [
        {"id": r.id, "run_id": r.run_id, "principal": r.actor_principal,
         "action": r.action, "resource": r.resource, "target_id": r.target_id,
         "destination": r.destination, "authorized": r.authorized}
        for r in rows
    ]


@router.get("/handoffs")
def handoffs(run_id: str | None = None, db: Session = Depends(get_session)):
    stmt = select(AgentHandoff).order_by(AgentHandoff.hop_index)
    if run_id:
        stmt = stmt.where(AgentHandoff.run_id == run_id)
    rows = db.scalars(stmt).all()
    return [
        {"hop": r.hop_index, "from": r.source_principal, "to": r.target_principal,
         "trusted": r.trusted, "payload": r.payload}
        for r in rows
    ]
