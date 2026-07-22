"""LinkX Support Desk — testbed API.

A deliberately undefended LLM-agent victim environment for benchmarking
cascading indirect prompt injection across multi-agent MCP topologies.
Run:  uvicorn app.main:app --reload
"""
from __future__ import annotations

from fastapi import FastAPI

from app.routers import tickets, customers, actions, admin, kb

app = FastAPI(
    title="RogueAgent: Indirect Prompt Injection Testbed",
    description="Red-teaming against LinkX, a synthetic ISP customer-support environment for IPI research.",
    version="0.1.0",
)

app.include_router(tickets.router)
app.include_router(customers.router)
app.include_router(kb.router)
app.include_router(actions.router)
app.include_router(admin.router)


@app.get("/")
def root():
    return {"app": "linkx-testbed", "docs": "/docs", "health": "/admin/health"}
