"""Generate text embeddings and perform semantic vector retrieval."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import truststore
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import InMemoryVectorStore

from threat_intelligence_rag.retrieval.retrieval_results import (
    ComponentHit,
    RetrievalError,
    document_key,
)

DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_MODEL_CACHE = Path("data/models/fastembed")


class LocalFastEmbedEmbeddings(Embeddings):
    """Convert document and query text into local FastEmbed vectors."""

    def __init__(
        self,
        *,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
        cache_dir: Path = DEFAULT_MODEL_CACHE,
        batch_size: int = 64,
        threads: int | None = None,
    ) -> None:
        if batch_size <= 0:
            raise ValueError("Embedding batch_size must be greater than zero")

        # This is application code, so using the operating system's trusted CA
        # store is appropriate and keeps model downloads TLS-verified.
        truststore.inject_into_ssl()
        from fastembed import TextEmbedding

        cache_dir.mkdir(parents=True, exist_ok=True)
        self.model_name = model_name
        self.batch_size = batch_size
        self.cache_dir = cache_dir
        self._model = TextEmbedding(
            model_name=model_name,
            cache_dir=str(cache_dir),
            threads=threads,
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed document passages in batches."""

        if not texts:
            return []
        return [
            vector.tolist()
            for vector in self._model.passage_embed(
                texts,
                batch_size=self.batch_size,
            )
        ]

    def embed_query(self, text: str) -> list[float]:
        """Embed one search query using the model's query encoding path."""

        if not text.strip():
            raise ValueError("Embedding query must not be empty")
        vectors: list[Any] = list(self._model.query_embed(text))
        if len(vectors) != 1:
            raise RuntimeError("FastEmbed did not return exactly one query vector")
        return vectors[0].tolist()


class DenseIndex:
    """Own a vector store and expose semantic results with cosine scores."""

    def __init__(self, vector_store: InMemoryVectorStore) -> None:
        self.vector_store = vector_store

    @classmethod
    def from_documents(
        cls,
        documents: Sequence[Document],
        embeddings: Embeddings,
    ) -> DenseIndex:
        if not documents:
            raise RetrievalError("Dense retrieval requires at least one document")
        document_ids = [document_key(document) for document in documents]
        if len(set(document_ids)) != len(document_ids):
            raise RetrievalError("Dense document IDs must be unique")

        vector_store = InMemoryVectorStore(embedding=embeddings)
        vector_store.add_documents(documents=list(documents), ids=document_ids)
        return cls(vector_store)

    @classmethod
    def load(cls, path: Path, embeddings: Embeddings) -> DenseIndex:
        if not path.is_file():
            raise RetrievalError(f"Dense index not found: {path}")
        return cls(InMemoryVectorStore.load(str(path), embedding=embeddings))

    def dump(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.vector_store.dump(str(path))

    def search(self, query: str, *, k: int) -> list[ComponentHit]:
        if k <= 0:
            raise RetrievalError("Dense k must be greater than zero")
        if not query.strip():
            raise RetrievalError("Dense query must not be empty")

        results = self.vector_store.similarity_search_with_score(query=query, k=k)
        return [
            ComponentHit(document=document, rank=rank, score=float(score))
            for rank, (document, score) in enumerate(results, start=1)
        ]
