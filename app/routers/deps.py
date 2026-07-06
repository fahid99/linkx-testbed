"""Shared dependencies for routers."""
from __future__ import annotations

from fastapi import Header


def get_principal(x_agent_principal: str = Header(default="anonymous")) -> str:
    """The acting agent identity. In Week 2 the orchestrator sets this per agent;
    for now it defaults to 'anonymous' so unauthenticated calls are visible."""
    return x_agent_principal


def get_run_id(x_run_id: str | None = Header(default=None)) -> str | None:
    """Correlates all actions in a single trial so the scorer can isolate them."""
    return x_run_id
