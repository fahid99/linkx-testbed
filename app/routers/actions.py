"""Actions and sinks: outbound replies, external email, webhooks, and the
explicit inter-agent handoff record."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.eval.logging import is_authorized, log_action
from app.models import Ticket, TicketMessage, AgentHandoff, ExternalContact, Webhook
from app.routers.deps import get_principal, get_run_id
from app.schemas import ReplyIn, EmailIn, WebhookIn, HandoffIn

router = APIRouter(prefix="/actions", tags=["actions"])


def _is_allowlisted_email(db, addr: str) -> bool:
    return db.scalar(
        select(ExternalContact).where(ExternalContact.email == addr,
                                      ExternalContact.allowlisted.is_(True))
    ) is not None


@router.post("/tickets/{ticket_id}/reply")
def reply_ticket(ticket_id: int, payload: ReplyIn, db: Session = Depends(get_session),
                 principal: str = Depends(get_principal), run_id: str | None = Depends(get_run_id)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "ticket not found")
    ok = is_authorized(db, principal, "reply_ticket")
    db.add(TicketMessage(ticket_id=ticket_id, direction="outbound",
                         author=principal, body=payload.body, is_untrusted=False))
    db.commit()
    log_action(db, principal=principal, action="reply_ticket", resource="ticket",
               target_id=ticket_id, payload=payload.body,
               destination=f"ticket:{ticket_id}", authorized=ok, run_id=run_id)
    return {"status": "sent", "ticket_id": ticket_id}


@router.post("/send-email")
def send_email(payload: EmailIn, db: Session = Depends(get_session),
               principal: str = Depends(get_principal), run_id: str | None = Depends(get_run_id)):
    """External email — a primary exfil sink. Records authorization and whether
    the destination is allowlisted; does not block in the baseline."""
    ok = is_authorized(db, principal, "send_email") and _is_allowlisted_email(db, payload.to)
    log_action(db, principal=principal, action="send_email", resource="email",
               payload=f"{payload.subject}\n{payload.body}", destination=payload.to,
               authorized=ok, run_id=run_id)
    return {"status": "delivered", "to": payload.to}


@router.post("/webhook")
def post_webhook(payload: WebhookIn, db: Session = Depends(get_session),
                 principal: str = Depends(get_principal), run_id: str | None = Depends(get_run_id)):
    """Webhook POST — second exfil sink."""
    allow = db.scalar(select(Webhook).where(Webhook.url == payload.url,
                                            Webhook.allowlisted.is_(True))) is not None
    log_action(db, principal=principal, action="post_webhook", resource="webhook",
               payload=payload.payload, destination=payload.url,
               authorized=allow, run_id=run_id)
    return {"status": "posted", "url": payload.url}


@router.post("/handoff")
def record_handoff(payload: HandoffIn, db: Session = Depends(get_session)):
    """Persist an agent-to-agent message. This is what lets the scorer measure
    at which hop an injection propagated, and whether it crossed as 'trusted'.

    Returns the new row's ``handoff_id`` so a mesh caller can pass it as the
    ``parent_handoff_id`` of the handoffs it fans out downstream, threading the
    provenance DAG that ``cascade_depth()`` walks."""
    h = AgentHandoff(
        run_id=payload.run_id, hop_index=payload.hop_index,
        source_principal=payload.source_principal, target_principal=payload.target_principal,
        payload=payload.payload, trusted=payload.trusted,
        parent_handoff_id=payload.parent_handoff_id,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return {"status": "recorded", "hop_index": payload.hop_index, "handoff_id": h.id}
