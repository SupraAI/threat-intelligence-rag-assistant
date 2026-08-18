"""Combine BM25 and semantic rankings with Reciprocal Rank Fusion."""

from __future__ import annotations

from dataclasses import dataclass

from langchain_core.documents import Document

from threat_intelligence_rag.retrieval.bm25 import BM25Index
from threat_intelligence_rag.retrieval.retrieval_results import (
    ComponentHit,
    HybridHit,
    RetrievalError,
    document_key,
)
from threat_intelligence_rag.retrieval.semantic_retrieval import DenseIndex


@dataclass(slots=True)
class _FusionCandidate:
    document: Document
    fusion_score: float = 0.0
    bm25_rank: int | None = None
    bm25_score: float | None = None
    dense_rank: int | None = None
    dense_score: float | None = None


class HybridRetriever:
    """Retrieve independently, then fuse ranks without mixing score scales."""

    def __init__(
        self,
        bm25_index: BM25Index,
        dense_index: DenseIndex,
        *,
        rrf_constant: int = 60,
        bm25_weight: float = 1.0,
        dense_weight: float = 1.0,
    ) -> None:
        if rrf_constant <= 0:
            raise RetrievalError("RRF constant must be greater than zero")
        if bm25_weight < 0 or dense_weight < 0:
            raise RetrievalError("Retriever weights cannot be negative")
        if bm25_weight == 0 and dense_weight == 0:
            raise RetrievalError("At least one retriever weight must be positive")

        self.bm25_index = bm25_index
        self.dense_index = dense_index
        self.rrf_constant = rrf_constant
        self.bm25_weight = bm25_weight
        self.dense_weight = dense_weight

    def _add_hits(
        self,
        candidates: dict[str, _FusionCandidate],
        hits: list[ComponentHit],
        *,
        channel: str,
        weight: float,
    ) -> None:
        for hit in hits:
            key = document_key(hit.document)
            candidate = candidates.setdefault(
                key,
                _FusionCandidate(document=hit.document),
            )
            candidate.fusion_score += weight / (self.rrf_constant + hit.rank)
            if channel == "bm25":
                candidate.bm25_rank = hit.rank
                candidate.bm25_score = hit.score
            elif channel == "dense":
                candidate.dense_rank = hit.rank
                candidate.dense_score = hit.score
            else:
                raise RetrievalError(f"Unknown retrieval channel: {channel}")

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        candidate_k: int = 20,
    ) -> list[HybridHit]:
        """Return top-k documents after fusing both candidate rankings."""

        if top_k <= 0:
            raise RetrievalError("top_k must be greater than zero")
        if candidate_k < top_k:
            raise RetrievalError("candidate_k must be greater than or equal to top_k")

        bm25_hits = self.bm25_index.search(query, k=candidate_k)
        dense_hits = self.dense_index.search(query, k=candidate_k)
        candidates: dict[str, _FusionCandidate] = {}
        self._add_hits(
            candidates,
            bm25_hits,
            channel="bm25",
            weight=self.bm25_weight,
        )
        self._add_hits(
            candidates,
            dense_hits,
            channel="dense",
            weight=self.dense_weight,
        )

        ordered = sorted(
            candidates.values(),
            key=lambda item: (-item.fusion_score, document_key(item.document)),
        )
        return [
            HybridHit(
                document=candidate.document,
                rank=rank,
                fusion_score=candidate.fusion_score,
                bm25_rank=candidate.bm25_rank,
                bm25_score=candidate.bm25_score,
                dense_rank=candidate.dense_rank,
                dense_score=candidate.dense_score,
            )
            for rank, candidate in enumerate(ordered[:top_k], start=1)
        ]
