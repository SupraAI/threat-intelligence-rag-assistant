"""Unit tests for lexical, dense, and hybrid retrieval."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

from threat_intelligence_rag.retrieval.bm25 import BM25Index, tokenize_for_bm25
from threat_intelligence_rag.retrieval.hybrid_retriever import HybridRetriever
from threat_intelligence_rag.retrieval.retrieval_results import RetrievalError
from threat_intelligence_rag.retrieval.retriever_builder import (
    load_or_build_dense_index,
)
from threat_intelligence_rag.retrieval.semantic_retrieval import DenseIndex


class KeywordEmbeddings(Embeddings):
    """Small deterministic embedding model used only by unit tests."""

    semantic_groups = (
        {"dns", "domain", "name", "query", "queries", "resolver"},
        {"powershell", "script", "scripting", "command"},
        {"smb", "share", "shares", "file"},
    )

    def _embed(self, text: str) -> list[float]:
        tokens = set(re.findall(r"[a-z0-9]+", text.casefold()))
        return [
            float(len(tokens.intersection(group)))
            for group in self.semantic_groups
        ]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


def _documents() -> list[Document]:
    return [
        Document(
            id="T-DNS",
            page_content="DNS tunneling through name server queries.",
            metadata={"attack_id": "T-DNS", "name": "DNS Technique"},
        ),
        Document(
            id="T-POWERSHELL",
            page_content="PowerShell command and script execution.",
            metadata={
                "attack_id": "T-POWERSHELL",
                "name": "PowerShell Technique",
            },
        ),
        Document(
            id="T-SMB",
            page_content="Access files on a remote SMB share.",
            metadata={"attack_id": "T-SMB", "name": "SMB Technique"},
        ),
    ]


def test_tokenizer_preserves_security_identifiers() -> None:
    tokens = tokenize_for_bm25("T1071.004 via rundll32.exe over command-and-control")

    assert tokens == [
        "t1071.004",
        "via",
        "rundll32.exe",
        "over",
        "command-and-control",
    ]


def test_bm25_ranks_exact_lexical_evidence() -> None:
    index = BM25Index(_documents())

    hits = index.search("PowerShell script", k=2)

    assert hits[0].document.id == "T-POWERSHELL"
    assert hits[0].rank == 1
    assert hits[0].score > 0


def test_bm25_omits_documents_without_lexical_overlap() -> None:
    index = BM25Index(_documents())

    assert index.search("beaconing", k=3) == []


def test_dense_index_ranks_semantically_related_terms() -> None:
    index = DenseIndex.from_documents(_documents(), KeywordEmbeddings())

    hits = index.search("domain resolver activity", k=2)

    assert hits[0].document.id == "T-DNS"
    assert hits[0].rank == 1
    assert hits[0].score > hits[1].score


def test_hybrid_retrieval_exposes_both_rank_traces() -> None:
    documents = _documents()
    retriever = HybridRetriever(
        BM25Index(documents),
        DenseIndex.from_documents(documents, KeywordEmbeddings()),
    )

    hits = retriever.search("DNS queries", top_k=2, candidate_k=3)

    assert hits[0].document.id == "T-DNS"
    assert hits[0].bm25_rank == 1
    assert hits[0].dense_rank == 1
    assert hits[0].fusion_score == pytest.approx(2 / 61)


def test_hybrid_retrieval_rejects_too_small_candidate_pool() -> None:
    documents = _documents()
    retriever = HybridRetriever(
        BM25Index(documents),
        DenseIndex.from_documents(documents, KeywordEmbeddings()),
    )

    with pytest.raises(RetrievalError, match="candidate_k"):
        retriever.search("DNS", top_k=3, candidate_k=2)


def test_dense_index_cache_is_reused_when_manifest_matches(
    tmp_path: Path,
) -> None:
    documents = _documents()
    embeddings = KeywordEmbeddings()
    index_path = tmp_path / "dense.json"

    first_index, first_was_rebuilt = load_or_build_dense_index(
        documents,
        embeddings,
        embedding_model_name="test-keywords-v1",
        index_path=index_path,
    )
    second_index, second_was_rebuilt = load_or_build_dense_index(
        documents,
        embeddings,
        embedding_model_name="test-keywords-v1",
        index_path=index_path,
    )

    assert first_was_rebuilt is True
    assert second_was_rebuilt is False
    assert first_index.search("DNS", k=1)[0].document.id == "T-DNS"
    assert second_index.search("DNS", k=1)[0].document.id == "T-DNS"
