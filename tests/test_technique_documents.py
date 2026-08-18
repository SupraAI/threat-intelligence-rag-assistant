"""Tests for LangChain technique-document creation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from langchain_core.documents import Document

from threat_intelligence_rag.ingestion.technique_documents import (
    TechniqueDocumentError,
    build_technique_documents,
    load_technique_documents,
    write_documents_jsonl,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_DATA = PROJECT_ROOT / "data" / "processed" / "enterprise_techniques.json"


def _normalized_data() -> dict[str, object]:
    return {
        "domain": "enterprise-attack",
        "source": {"bundle_id": "bundle--example"},
        "counts": {"techniques": 1},
        "techniques": [
            {
                "attack_id": "T1000",
                "stix_id": "attack-pattern--example",
                "name": "Example Technique",
                "retrieval_text": "ATT&CK technique T1000: Example Technique.",
                "url": "https://attack.mitre.org/techniques/T1000",
                "tactics": [
                    {
                        "attack_id": "TA0001",
                        "name": "Initial Access",
                    }
                ],
                "platforms": ["Windows", "Linux"],
                "version": "1.0",
                "modified": "2026-01-01T00:00:00.000Z",
                "detection_strategies": [{"detection_id": "DET0001"}],
                "procedure_examples": [{"description": "Example use."}],
            }
        ],
    }


def test_builds_one_langchain_document_per_technique() -> None:
    documents = build_technique_documents(_normalized_data())

    assert len(documents) == 1
    assert isinstance(documents[0], Document)
    assert documents[0].id == "T1000"
    assert documents[0].page_content.startswith("ATT&CK technique T1000")
    assert documents[0].metadata == {
        "document_type": "mitre_attack_parent_technique",
        "attack_id": "T1000",
        "stix_id": "attack-pattern--example",
        "name": "Example Technique",
        "domain": "enterprise-attack",
        "bundle_id": "bundle--example",
        "tactic_ids": ["TA0001"],
        "tactic_names": ["Initial Access"],
        "platforms": ["Linux", "Windows"],
        "attack_object_version": "1.0",
        "modified": "2026-01-01T00:00:00.000Z",
        "source_url": "https://attack.mitre.org/techniques/T1000",
        "detection_strategy_count": 1,
        "procedure_example_count": 1,
    }


def test_rejects_subtechniques() -> None:
    normalized_data = _normalized_data()
    normalized_data["techniques"][0]["attack_id"] = "T1000.001"

    with pytest.raises(TechniqueDocumentError, match="sub-technique"):
        build_technique_documents(normalized_data)


def test_writes_one_jsonl_record_per_document(tmp_path: Path) -> None:
    documents = build_technique_documents(_normalized_data())
    output_path = tmp_path / "documents.jsonl"

    write_documents_jsonl(documents, output_path)

    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    serialized = json.loads(lines[0])
    assert serialized["id"] == "T1000"
    assert serialized["metadata"]["attack_id"] == "T1000"


def test_supplied_normalized_data_creates_222_unique_documents() -> None:
    documents = load_technique_documents(NORMALIZED_DATA)

    assert len(documents) == 222
    assert len({document.id for document in documents}) == 222
    assert all(document.page_content for document in documents)
    assert all(document.metadata["source_url"] for document in documents)
