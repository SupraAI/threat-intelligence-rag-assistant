"""Build the project's lexical, semantic, and hybrid retrievers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

from threat_intelligence_rag.retrieval.bm25 import BM25Index
from threat_intelligence_rag.retrieval.hybrid_retriever import HybridRetriever
from threat_intelligence_rag.retrieval.retrieval_results import document_key
from threat_intelligence_rag.retrieval.semantic_retrieval import DenseIndex

DEFAULT_DENSE_INDEX_PATH = Path("data/indexes/dense_store.json")
INDEX_MANIFEST_SCHEMA_VERSION = 1


def fingerprint_documents(documents: Sequence[Document]) -> str:
    """Fingerprint all searchable content and metadata deterministically."""

    digest = hashlib.sha256()
    for document in sorted(documents, key=document_key):
        payload = {
            "id": document_key(document),
            "page_content": document.page_content,
            "metadata": document.metadata,
        }
        digest.update(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _manifest_path(index_path: Path) -> Path:
    return index_path.with_suffix(index_path.suffix + ".manifest.json")


def _expected_manifest(
    documents: Sequence[Document], embedding_model_name: str
) -> dict[str, Any]:
    return {
        "schema_version": INDEX_MANIFEST_SCHEMA_VERSION,
        "embedding_model": embedding_model_name,
        "document_count": len(documents),
        "document_fingerprint": fingerprint_documents(documents),
    }


def _read_manifest(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except (OSError, json.JSONDecodeError):
        return None
    return manifest if isinstance(manifest, dict) else None


def load_or_build_dense_index(
    documents: Sequence[Document],
    embeddings: Embeddings,
    *,
    embedding_model_name: str,
    index_path: Path = DEFAULT_DENSE_INDEX_PATH,
    rebuild: bool = False,
) -> tuple[DenseIndex, bool]:
    """Load a compatible index or rebuild it when content/model changed."""

    expected_manifest = _expected_manifest(documents, embedding_model_name)
    manifest_path = _manifest_path(index_path)
    if (
        not rebuild
        and index_path.is_file()
        and _read_manifest(manifest_path) == expected_manifest
    ):
        return DenseIndex.load(index_path, embeddings), False

    dense_index = DenseIndex.from_documents(documents, embeddings)
    dense_index.dump(index_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as manifest_file:
        json.dump(
            expected_manifest,
            manifest_file,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        manifest_file.write("\n")
    return dense_index, True


def build_hybrid_retriever(
    documents: Sequence[Document],
    embeddings: Embeddings,
    *,
    embedding_model_name: str,
    index_path: Path = DEFAULT_DENSE_INDEX_PATH,
    rebuild_dense_index: bool = False,
    rrf_constant: int = 60,
    bm25_weight: float = 1.0,
    dense_weight: float = 1.0,
) -> tuple[HybridRetriever, bool]:
    """Create BM25 every run and load or build the persistent dense index."""

    bm25_index = BM25Index(documents)
    dense_index, rebuilt = load_or_build_dense_index(
        documents,
        embeddings,
        embedding_model_name=embedding_model_name,
        index_path=index_path,
        rebuild=rebuild_dense_index,
    )
    return (
        HybridRetriever(
            bm25_index,
            dense_index,
            rrf_constant=rrf_constant,
            bm25_weight=bm25_weight,
            dense_weight=dense_weight,
        ),
        rebuilt,
    )
