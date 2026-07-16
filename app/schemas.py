"""Pydantic v2 schemas for the API. Kept thin and explicit so the same shapes
can be reused as MCP tool input/output models in Week 2."""
from __future__ import annotations

from datetime import date, datetime
from pydantic import BaseModel, ConfigDict


class CustomerPublic(BaseModel):
    """Non-sensitive view (safe for a tier-1 principal)."""
    model_config = ConfigDict(from_attributes=True)
    id: int
    full_name: str
    email: str
    plan_tier: str
    account_status: str


class CustomerSensitive(CustomerPublic):
    """Full PII view (requires read_customer_pii permission)."""
    phone: str
    street: str
    city: str
    state: str
    zip_code: str
    dob: date
    ssn_last4: str
    account_number: str


class PaymentMethodOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    customer_id: int
    card_brand: str
    card_last4: str
    billing_zip: str
    token: str


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    customer_id: int | None
    channel: str
    subject: str
    body: str
    status: str
    priority: str
    assigned_queue: str
    triage_summary: str | None
    is_injected: bool
    created_at: datetime


class TicketCreate(BaseModel):
    customer_id: int | None = None
    channel: str = "web"
    subject: str
    body: str
    is_injected: bool = False


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ticket_id: int
    direction: str
    author: str
    body: str
    is_untrusted: bool
    created_at: datetime


class KBArticleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    content: str
    tags: str
    is_untrusted: bool


class ReplyIn(BaseModel):
    body: str


class EmailIn(BaseModel):
    to: str
    subject: str
    body: str


class WebhookIn(BaseModel):
    url: str
    payload: str


class HandoffIn(BaseModel):
    run_id: str
    hop_index: int
    source_principal: str
    target_principal: str
    payload: str
    trusted: bool = True
    # Provenance: the upstream handoff row this one descends from (None == root).
    # Threads the handoff DAG so cascade_depth() can measure true path depth in a
    # mesh; omitted/None reproduces the linear chain.
    parent_handoff_id: int | None = None


class TriageIn(BaseModel):
    summary: str
