"""Typed results and shared validation for retrieval components."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from langchain_core.documents import Document


class RetrievalError(ValueError):
    """Raised when a retrieval request or document set is invalid."""


def document_key(document: Document) -> str:
    """Return the stable identity used to merge retriever results."""

    if document.id is not None and str(document.id).strip():
        return str(document.id)
    attack_id = document.metadata.get("attack_id")
    if isinstance(attack_id, str) and attack_id.strip():
        return attack_id
    raise RetrievalError("Every retrieval document must have an ID or attack_id")


@dataclass(frozen=True, slots=True)
class ComponentHit:
    """A ranked result produced by one retrieval component."""

    document: Document
    rank: int
    score: float


@dataclass(frozen=True, slots=True)
class HybridHit:
    """A result after reciprocal-rank fusion."""

    document: Document
    rank: int
    fusion_score: float
    bm25_rank: int | None
    bm25_score: float | None
    dense_rank: int | None
    dense_score: float | None

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        """Return an inspectable representation suitable for CLI JSON output."""

        result: dict[str, Any] = {
            "rank": self.rank,
            "attack_id": document_key(self.document),
            "name": self.document.metadata.get("name"),
            "source_url": self.document.metadata.get("source_url"),
            "tactics": self.document.metadata.get("tactic_names", []),
            "platforms": self.document.metadata.get("platforms", []),
            "fusion_score": self.fusion_score,
            "bm25": {"rank": self.bm25_rank, "score": self.bm25_score},
            "dense": {"rank": self.dense_rank, "score": self.dense_score},
        }
        if include_content:
            result["page_content"] = self.document.page_content
        return result
