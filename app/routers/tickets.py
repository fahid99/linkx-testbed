"""Ticket operations — includes the primary injection ingress (ticket body)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.eval.logging import log_action
from app.models import Ticket, TicketMessage
from app.routers.deps import get_principal, get_run_id
from app.schemas import TicketOut, TicketCreate, MessageOut, TriageIn

router = APIRouter(prefix="/tickets", tags=["tickets"])


@router.get("", response_model=list[TicketOut])
def list_tickets(include_injected: bool = False, db: Session = Depends(get_session)):
    stmt = select(Ticket)
    if not include_injected:
        stmt = stmt.where(Ticket.is_injected.is_(False))
    return db.scalars(stmt).all()


@router.get("/{ticket_id}", response_model=TicketOut)
def get_ticket(ticket_id: int, db: Session = Depends(get_session)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "ticket not found")
    # Untrusted body is returned verbatim — the IPI ingress surface.
    return t


@router.get("/{ticket_id}/messages", response_model=list[MessageOut])
def get_messages(ticket_id: int, db: Session = Depends(get_session)):
    return db.scalars(
        select(TicketMessage).where(TicketMessage.ticket_id == ticket_id)
    ).all()


@router.post("", response_model=TicketOut, status_code=201)
def create_ticket(payload: TicketCreate, db: Session = Depends(get_session),
                  principal: str = Depends(get_principal)):
    """Open a ticket. This is the attacker-controllable ingress: the body is
    stored and later surfaced to agents verbatim."""
    t = Ticket(
        customer_id=payload.customer_id,
        channel=payload.channel,
        subject=payload.subject,
        body=payload.body,
        is_injected=payload.is_injected,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    db.add(TicketMessage(ticket_id=t.id, direction="inbound",
                         author="external_submitter", body=payload.body, is_untrusted=True))
    db.commit()
    return t


@router.post("/{ticket_id}/triage", response_model=TicketOut)
def triage(ticket_id: int, payload: TriageIn, db: Session = Depends(get_session),
           principal: str = Depends(get_principal), run_id: str | None = Depends(get_run_id)):
    """Write a triage summary — the inter-agent handoff surface. What the triage
    agent writes here is read downstream as trusted input."""
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "ticket not found")
    t.triage_summary = payload.summary
    db.commit()
    log_action(db, principal=principal, action="write_triage", resource="ticket",
               target_id=ticket_id, payload=payload.summary, run_id=run_id)
    db.refresh(t)
    return t
