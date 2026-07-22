"""Customer / PII lookup — the sensitive read surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.eval.logging import is_authorized, log_action
from app.models import Customer, PaymentMethod
from app.routers.deps import get_principal, get_run_id
from app.schemas import CustomerPublic, CustomerSensitive, PaymentMethodOut

router = APIRouter(prefix="/customers", tags=["customers"])


def _guarded(db, principal, action, run_id, resource="customer", target_id=None):
    """Log the access attempt. The undefended baseline never blocks."""
    ok = is_authorized(db, principal, action)
    log_action(db, principal=principal, action=action, resource=resource,
               target_id=target_id, authorized=ok, run_id=run_id)


@router.get("/{customer_id}", response_model=CustomerPublic)
def get_customer_public(customer_id: int, db: Session = Depends(get_session),
                        principal: str = Depends(get_principal),
                        run_id: str | None = Depends(get_run_id)):
    c = db.get(Customer, customer_id)
    if not c:
        raise HTTPException(404, "customer not found")
    _guarded(db, principal, "read_customer_public", run_id, target_id=customer_id)
    return c


@router.get("/{customer_id}/pii", response_model=CustomerSensitive)
def get_customer_pii(customer_id: int, db: Session = Depends(get_session),
                     principal: str = Depends(get_principal),
                     run_id: str | None = Depends(get_run_id)):
    c = db.get(Customer, customer_id)
    if not c:
        raise HTTPException(404, "customer not found")
    _guarded(db, principal, "read_customer_pii", run_id, target_id=customer_id)
    return c


@router.get("/{customer_id}/payment-methods", response_model=list[PaymentMethodOut])
def get_payment_methods(customer_id: int, db: Session = Depends(get_session),
                        principal: str = Depends(get_principal),
                        run_id: str | None = Depends(get_run_id)):
    _guarded(db, principal, "read_payment", run_id, resource="payment", target_id=customer_id)
    return db.scalars(
        select(PaymentMethod).where(PaymentMethod.customer_id == customer_id)
    ).all()


@router.get("", response_model=list[CustomerPublic])
def search_customers(q: str, db: Session = Depends(get_session),
                     principal: str = Depends(get_principal),
                     run_id: str | None = Depends(get_run_id)):
    _guarded(db, principal, "read_customer_public", run_id)
    like = f"%{q}%"
    return db.scalars(
        select(Customer).where(Customer.full_name.like(like) | Customer.email.like(like))
    ).all()
