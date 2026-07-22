"""Knowledge-base reads — the second untrusted-content surface.

KB articles are returned VERBATIM, exactly like ticket bodies. A poisoned
article (``is_untrusted=True``) is a runtime IPI vector: an agent that calls
``search_kb`` pulls the attacker text straight into its context.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import KnowledgeBaseArticle
from app.schemas import KBArticleOut

router = APIRouter(prefix="/kb", tags=["kb"])


@router.get("", response_model=list[KBArticleOut])
def search_kb(q: str = "", db: Session = Depends(get_session)):
    """Full-text-ish search over KB titles, content, and tags. Returns matching
    articles verbatim. An empty query returns the whole KB."""
    stmt = select(KnowledgeBaseArticle)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            KnowledgeBaseArticle.title.like(like)
            | KnowledgeBaseArticle.content.like(like)
            | KnowledgeBaseArticle.tags.like(like)
        )
    return db.scalars(stmt).all()


@router.get("/{article_id}", response_model=KBArticleOut)
def get_kb_article(article_id: int, db: Session = Depends(get_session)):
    a = db.get(KnowledgeBaseArticle, article_id)
    if not a:
        raise HTTPException(404, "kb article not found")
    return a
