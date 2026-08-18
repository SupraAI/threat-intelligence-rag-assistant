"""Transparent BM25 lexical retrieval over LangChain documents."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

from langchain_core.documents import Document
from rank_bm25 import BM25Okapi

from threat_intelligence_rag.retrieval.retrieval_results import (
    ComponentHit,
    RetrievalError,
    document_key,
)

TECHNICAL_TOKEN_PATTERN = re.compile(
    r"[a-z0-9]+(?:[._:/\\-][a-z0-9]+)*",
    flags=re.IGNORECASE,
)


def tokenize_for_bm25(text: str) -> list[str]:
    """Preserve cybersecurity identifiers while normalizing case."""

    return [token.casefold() for token in TECHNICAL_TOKEN_PATTERN.findall(text)]


class BM25Index:
    """Rank documents using exact lexical evidence and expose raw BM25 scores."""

    def __init__(
        self,
        documents: Sequence[Document],
        *,
        tokenizer: Callable[[str], list[str]] = tokenize_for_bm25,
    ) -> None:
        if not documents:
            raise RetrievalError("BM25 requires at least one document")

        self.documents = tuple(documents)
        self.tokenizer = tokenizer
        document_ids = [document_key(document) for document in self.documents]
        if len(set(document_ids)) != len(document_ids):
            raise RetrievalError("BM25 document IDs must be unique")

        tokenized_corpus = [
            self.tokenizer(document.page_content) for document in self.documents
        ]
        if any(not tokens for tokens in tokenized_corpus):
            raise RetrievalError("BM25 documents must contain indexable text")
        self.vectorizer = BM25Okapi(tokenized_corpus)

    def search(self, query: str, *, k: int) -> list[ComponentHit]:
        """Return up to k lexical matches; omit documents with no query overlap."""

        if k <= 0:
            raise RetrievalError("BM25 k must be greater than zero")
        query_tokens = self.tokenizer(query)
        if not query_tokens:
            raise RetrievalError("BM25 query must contain at least one token")

        scores = self.vectorizer.get_scores(query_tokens)
        candidates = [
            (document, float(score))
            for document, score in zip(self.documents, scores, strict=True)
            if float(score) != 0.0
        ]
        candidates.sort(key=lambda item: (-item[1], document_key(item[0])))

        return [
            ComponentHit(document=document, rank=rank, score=score)
            for rank, (document, score) in enumerate(candidates[:k], start=1)
        ]
