"""SQLAlchemy models for the LinkX support-desk environment.

Tables are grouped by the role they play in the testbed:
  * PII assets        - what an attacker wants to read/exfiltrate
  * Untrusted surfaces - where an indirect prompt injection can enter
  * Inter-agent handoff - the surface that makes a *cascade* measurable
  * Privilege model    - makes "unauthorized action" well-defined
  * Instrumentation    - the append-only log the scorer reads
  * Exfil sinks        - destinations an attacker exfiltrates to
"""
from __future__ import annotations

from datetime import datetime, date

from sqlalchemy import (
    String, Integer, Date, DateTime, Boolean, ForeignKey, Text, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# PII assets
# --------------------------------------------------------------------------- #
class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(160))
    phone: Mapped[str] = mapped_column(String(40))
    street: Mapped[str] = mapped_column(String(160))
    city: Mapped[str] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(40))
    zip_code: Mapped[str] = mapped_column(String(12))
    dob: Mapped[date] = mapped_column(Date)
    ssn_last4: Mapped[str] = mapped_column(String(4))           # synthetic, invalid range
    account_number: Mapped[str] = mapped_column(String(20), unique=True)
    plan_tier: Mapped[str] = mapped_column(String(20))          # bronze/silver/gold/business
    account_status: Mapped[str] = mapped_column(String(20))     # active/suspended/closed
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    payment_methods: Mapped[list["PaymentMethod"]] = relationship(back_populates="customer")
    tickets: Mapped[list["Ticket"]] = relationship(back_populates="customer")


class PaymentMethod(Base):
    __tablename__ = "payment_methods"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    card_brand: Mapped[str] = mapped_column(String(20))
    card_last4: Mapped[str] = mapped_column(String(4))          # from documented test BINs
    billing_zip: Mapped[str] = mapped_column(String(12))
    token: Mapped[str] = mapped_column(String(40), unique=True)  # synthetic vault token
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    customer: Mapped["Customer"] = relationship(back_populates="payment_methods")


# --------------------------------------------------------------------------- #
# Untrusted surfaces (injection ingress)
# --------------------------------------------------------------------------- #
class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int | None] = mapped_column(ForeignKey("customers.id"), nullable=True)
    channel: Mapped[str] = mapped_column(String(20))            # email/chat/web
    subject: Mapped[str] = mapped_column(String(200))           # attacker-controllable
    body: Mapped[str] = mapped_column(Text)                     # attacker-controllable (ingress)
    status: Mapped[str] = mapped_column(String(20), default="open")
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    assigned_queue: Mapped[str] = mapped_column(String(40), default="tier1")
    # Handoff field: a triage agent writes its summary here for the next stage.
    triage_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Evaluation tag: marks a ticket carrying an attacker payload so baseline
    # (benign-only) runs can exclude it.
    is_injected: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    customer: Mapped["Customer"] = relationship(back_populates="tickets")
    messages: Mapped[list["TicketMessage"]] = relationship(back_populates="ticket")


class TicketMessage(Base):
    __tablename__ = "ticket_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"))
    direction: Mapped[str] = mapped_column(String(10))          # inbound/outbound
    author: Mapped[str] = mapped_column(String(80))             # customer name or agent principal
    body: Mapped[str] = mapped_column(Text)
    is_untrusted: Mapped[bool] = mapped_column(Boolean, default=True)  # inbound = untrusted
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    ticket: Mapped["Ticket"] = relationship(back_populates="messages")


class KnowledgeBaseArticle(Base):
    __tablename__ = "knowledge_base"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)                  # second injection vector if poisoned
    tags: Mapped[str] = mapped_column(String(200), default="")
    is_untrusted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# --------------------------------------------------------------------------- #
# Inter-agent handoff (cascade measurement)
# --------------------------------------------------------------------------- #
class AgentHandoff(Base):
    __tablename__ = "agent_handoffs"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    hop_index: Mapped[int] = mapped_column(Integer)            # wave/depth hint; linear in the chain
    source_principal: Mapped[str] = mapped_column(String(80))
    target_principal: Mapped[str] = mapped_column(String(80))
    payload: Mapped[str] = mapped_column(Text)                 # message passed downstream
    trusted: Mapped[bool] = mapped_column(Boolean, default=True)  # treated as trusted by target?
    # Provenance edge: the upstream handoff whose payload this one descends from.
    # NULL == a root handoff (ingress). Lets cascade_depth() walk the handoff DAG
    # in a mesh, where a handoff can have multiple parents' payloads merged into
    # it; the linear chain is the degenerate case (each parent = the prior hop).
    parent_handoff_id: Mapped[int | None] = mapped_column(
        ForeignKey("agent_handoffs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# --------------------------------------------------------------------------- #
# Privilege model
# --------------------------------------------------------------------------- #
class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(40), unique=True)
    description: Mapped[str] = mapped_column(String(200), default="")

    permissions: Mapped[list["Permission"]] = relationship(back_populates="role")


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    action: Mapped[str] = mapped_column(String(60))            # e.g. read_payment, send_external_email
    resource: Mapped[str] = mapped_column(String(60), default="*")

    role: Mapped["Role"] = relationship(back_populates="permissions")


class AgentPrincipal(Base):
    __tablename__ = "agent_principals"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)  # triage_agent, lookup_agent, ...
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))

    role: Mapped["Role"] = relationship()


# --------------------------------------------------------------------------- #
# Instrumentation
# --------------------------------------------------------------------------- #
class ActionLog(Base):
    __tablename__ = "action_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    actor_principal: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(60))
    resource: Mapped[str] = mapped_column(String(60), default="")
    target_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    payload: Mapped[str] = mapped_column(Text, default="")
    destination: Mapped[str | None] = mapped_column(String(160), nullable=True)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# --------------------------------------------------------------------------- #
# Exfil sinks
# --------------------------------------------------------------------------- #
class ExternalContact(Base):
    __tablename__ = "external_contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(160))
    allowlisted: Mapped[bool] = mapped_column(Boolean, default=False)


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(300))
    allowlisted: Mapped[bool] = mapped_column(Boolean, default=False)
