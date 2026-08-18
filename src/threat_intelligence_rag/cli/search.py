"""Search ATT&CK techniques with hybrid BM25 and dense retrieval."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from threat_intelligence_rag.ingestion.technique_documents import (
    DEFAULT_INPUT_PATH,
    load_technique_documents,
)
from threat_intelligence_rag.retrieval.retriever_builder import (
    DEFAULT_DENSE_INDEX_PATH,
    build_hybrid_retriever,
)
from threat_intelligence_rag.retrieval.semantic_retrieval import (
    DEFAULT_EMBEDDING_MODEL,
    DEFAULT_MODEL_CACHE,
    LocalFastEmbedEmbeddings,
)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Retrieve ATT&CK techniques with BM25 + local embeddings."
    )
    parser.add_argument("query", help="Natural-language behavior description")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--candidate-k", type=int, default=20)
    parser.add_argument(
        "--normalized-data",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Normalized ATT&CK JSON used to build the documents",
    )
    parser.add_argument("--model", default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("--model-cache", type=Path, default=DEFAULT_MODEL_CACHE)
    parser.add_argument("--index", type=Path, default=DEFAULT_DENSE_INDEX_PATH)
    parser.add_argument("--rebuild-index", action="store_true")
    parser.add_argument("--rrf-constant", type=int, default=60)
    parser.add_argument("--bm25-weight", type=float, default=1.0)
    parser.add_argument("--dense-weight", type=float, default=1.0)
    parser.add_argument("--include-content", action="store_true")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    documents = load_technique_documents(args.normalized_data)
    embeddings = LocalFastEmbedEmbeddings(
        model_name=args.model,
        cache_dir=args.model_cache,
    )
    retriever, rebuilt = build_hybrid_retriever(
        documents,
        embeddings,
        embedding_model_name=args.model,
        index_path=args.index,
        rebuild_dense_index=args.rebuild_index,
        rrf_constant=args.rrf_constant,
        bm25_weight=args.bm25_weight,
        dense_weight=args.dense_weight,
    )
    hits = retriever.search(
        args.query,
        top_k=args.top_k,
        candidate_k=args.candidate_k,
    )
    output = {
        "query": args.query,
        "top_k": args.top_k,
        "candidate_k": args.candidate_k,
        "embedding_model": args.model,
        "dense_index_rebuilt": rebuilt,
        "fusion": {
            "method": "reciprocal_rank_fusion",
            "rrf_constant": args.rrf_constant,
            "bm25_weight": args.bm25_weight,
            "dense_weight": args.dense_weight,
        },
        "results": [
            hit.to_dict(include_content=args.include_content) for hit in hits
        ],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
