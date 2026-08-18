from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from langchain_core.documents import Document

DEFAULT_INPUT_PATH = Path("data/processed/enterprise_techniques.json")
DEFAULT_OUTPUT_PATH = Path("data/processed/technique_documents.jsonl")
EXPECTED_DOMAIN = "enterprise-attack"

JsonObject = dict[str, Any]


class TechniqueDocumentError(ValueError):
    """Raised when normalized technique data cannot produce valid documents."""


def _required_string(
    obj: Mapping[str, Any], field_name: str, *, context: str
) -> str:
    value = obj.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise TechniqueDocumentError(
            f"{context} must contain a non-empty string field {field_name!r}"
        )
    return value.strip()


def _normalized_tactics(technique: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    tactics = technique.get("tactics", [])
    if not isinstance(tactics, list) or not all(
        isinstance(tactic, Mapping) for tactic in tactics
    ):
        raise TechniqueDocumentError(
            "Technique 'tactics' must be a list of objects")
    return tactics


def _normalized_platforms(technique: Mapping[str, Any]) -> list[str]:
    platforms = technique.get("platforms", [])
    if not isinstance(platforms, list) or not all(
        isinstance(platform, str) for platform in platforms
    ):
        raise TechniqueDocumentError(
            "Technique 'platforms' must be a list of strings")
    return sorted(set(platforms))


def technique_to_document(
    technique: Mapping[str, Any], *, domain: str, bundle_id: str | None
) -> Document:
    """Convert one normalized ATT&CK technique to one LangChain Document."""

    attack_id = _required_string(technique, "attack_id", context="Technique")
    stix_id = _required_string(
        technique, "stix_id", context=f"Technique {attack_id}"
    )
    name = _required_string(
        technique, "name", context=f"Technique {attack_id}")
    retrieval_text = _required_string(
        technique, "retrieval_text", context=f"Technique {attack_id}"
    )
    source_url = _required_string(
        technique, "url", context=f"Technique {attack_id}"
    )

    if "." in attack_id:
        raise TechniqueDocumentError(
            f"Technique {attack_id} is a sub-technique; this document set is parent-only"
        )

    tactics = _normalized_tactics(technique)
    tactic_ids = [
        _required_string(tactic, "attack_id",
                         context=f"Tactic for {attack_id}")
        for tactic in tactics
    ]
    tactic_names = [
        _required_string(tactic, "name", context=f"Tactic for {attack_id}")
        for tactic in tactics
    ]
    platforms = _normalized_platforms(technique)

    detection_strategies = technique.get("detection_strategies", [])
    procedure_examples = technique.get("procedure_examples", [])
    if not isinstance(detection_strategies, list):
        raise TechniqueDocumentError(
            f"Technique {attack_id} 'detection_strategies' must be a list"
        )
    if not isinstance(procedure_examples, list):
        raise TechniqueDocumentError(
            f"Technique {attack_id} 'procedure_examples' must be a list"
        )

    return Document(
        id=attack_id,
        page_content=retrieval_text,
        metadata={
            "document_type": "mitre_attack_parent_technique",
            "attack_id": attack_id,
            "stix_id": stix_id,
            "name": name,
            "domain": domain,
            "bundle_id": bundle_id,
            "tactic_ids": tactic_ids,
            "tactic_names": tactic_names,
            "platforms": platforms,
            "attack_object_version": technique.get("version"),
            "modified": technique.get("modified"),
            "source_url": source_url,
            "detection_strategy_count": len(detection_strategies),
            "procedure_example_count": len(procedure_examples),
        },
    )


def build_technique_documents(normalized_data: Mapping[str, Any]) -> list[Document]:
    """Build and validate one document for every normalized technique."""

    domain = normalized_data.get("domain")
    if domain != EXPECTED_DOMAIN:
        raise TechniqueDocumentError(
            f"Expected domain {EXPECTED_DOMAIN!r}, received {domain!r}"
        )

    source = normalized_data.get("source", {})
    if not isinstance(source, Mapping):
        raise TechniqueDocumentError(
            "Normalized data 'source' must be an object")
    bundle_id = source.get("bundle_id")
    if bundle_id is not None and not isinstance(bundle_id, str):
        raise TechniqueDocumentError(
            "Source 'bundle_id' must be a string or null")

    techniques = normalized_data.get("techniques")
    if not isinstance(techniques, list):
        raise TechniqueDocumentError(
            "Normalized data must contain a 'techniques' list")
    if not all(isinstance(technique, Mapping) for technique in techniques):
        raise TechniqueDocumentError(
            "Every normalized technique must be an object")

    declared_count = normalized_data.get("counts", {}).get("techniques")
    if declared_count is not None and declared_count != len(techniques):
        raise TechniqueDocumentError(
            "Declared technique count does not match the techniques list: "
            f"{declared_count!r} != {len(techniques)}"
        )

    documents = [
        technique_to_document(
            technique,
            domain=domain,
            bundle_id=bundle_id,
        )
        for technique in techniques
    ]
    document_ids = [document.id for document in documents]
    if len(set(document_ids)) != len(document_ids):
        raise TechniqueDocumentError("Technique document IDs must be unique")

    return documents


def load_technique_documents(source_path: Path) -> list[Document]:
    """Load normalized JSON and return its LangChain technique documents."""

    try:
        with source_path.open(encoding="utf-8") as source_file:
            normalized_data = json.load(source_file)
    except FileNotFoundError as error:
        raise TechniqueDocumentError(
            f"Normalized technique file not found: {source_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise TechniqueDocumentError(
            f"Normalized technique file is not valid JSON: {source_path}: {error}"
        ) from error

    if not isinstance(normalized_data, Mapping):
        raise TechniqueDocumentError("Normalized JSON root must be an object")
    return build_technique_documents(normalized_data)


def document_to_json(document: Document) -> JsonObject:
    """Return a stable JSON representation for inspection and reproducibility."""

    return {
        "id": document.id,
        "page_content": document.page_content,
        "metadata": document.metadata,
    }


def write_documents_jsonl(documents: list[Document], output_path: Path) -> None:
    """Write one serialized LangChain document per JSONL line."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        for document in documents:
            json.dump(
                document_to_json(document),
                output_file,
                ensure_ascii=False,
                sort_keys=True,
            )
            output_file.write("\n")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build one LangChain Document per normalized ATT&CK technique."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Normalized technique JSON (default: {DEFAULT_INPUT_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Document JSONL output (default: {DEFAULT_OUTPUT_PATH})",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    try:
        documents = load_technique_documents(args.input)
        write_documents_jsonl(documents, args.output)
    except TechniqueDocumentError as error:
        raise SystemExit(
            f"Technique document creation failed: {error}") from error

    print(f"Created {len(documents)} LangChain technique documents.")
    print(f"Wrote inspectable documents to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
