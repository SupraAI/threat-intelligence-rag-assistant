"""Parse MITRE ATT&CK Enterprise STIX data into retrieval-ready records.

The first project iteration intentionally keeps active parent techniques only.
Sub-techniques, revoked techniques, and deprecated techniques are excluded.

Run from the project root with:

    uv run python -m threat_intelligence_rag.ingestion.mitre_parser
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

DEFAULT_INPUT_PATH = Path("data/enterprise-attack (2).json")
DEFAULT_OUTPUT_PATH = Path("data/processed/enterprise_techniques.json")

ATTACK_SOURCE_NAME = "mitre-attack"
ENTERPRISE_DOMAIN = "enterprise-attack"
PROCEDURE_SOURCE_TYPES = {"campaign", "intrusion-set", "malware", "tool"}

JsonObject = dict[str, Any]


class MitreParserError(ValueError):
    """Raised when a source file does not have the expected ATT&CK structure."""


def _is_active(obj: Mapping[str, Any]) -> bool:
    """Return whether an ATT&CK object is neither revoked nor deprecated."""

    return not obj.get("revoked", False) and not obj.get(
        "x_mitre_deprecated", False
    )


def _is_enterprise_object(obj: Mapping[str, Any]) -> bool:
    """Accept objects explicitly in Enterprise or without a domain annotation."""

    domains = obj.get("x_mitre_domains")
    return domains is None or ENTERPRISE_DOMAIN in domains


def _external_references(obj: Mapping[str, Any]) -> list[JsonObject]:
    """Normalize external references while preserving their source information."""

    references: list[JsonObject] = []
    for reference in obj.get("external_references", []):
        if not isinstance(reference, Mapping):
            continue
        normalized = {
            key: reference[key]
            for key in ("source_name", "external_id", "url", "description")
            if reference.get(key) is not None
        }
        if normalized:
            references.append(normalized)
    return references


def _attack_reference(obj: Mapping[str, Any]) -> JsonObject | None:
    """Return the canonical MITRE ATT&CK external reference for an object."""

    for reference in _external_references(obj):
        if reference.get("source_name") == ATTACK_SOURCE_NAME:
            return reference
    return None


def _require_attack_reference(
    obj: Mapping[str, Any], *, expected_prefix: str
) -> JsonObject:
    """Return a canonical ATT&CK reference or fail on malformed source data."""

    reference = _attack_reference(obj)
    external_id = reference.get("external_id") if reference else None
    if not isinstance(external_id, str) or not external_id.startswith(expected_prefix):
        object_id = obj.get("id", "<missing id>")
        raise MitreParserError(
            f"Object {object_id!r} has no MITRE ATT&CK {expected_prefix!r} reference"
        )
    return reference


def _validate_bundle(bundle: Mapping[str, Any]) -> list[JsonObject]:
    """Validate and return the source bundle's STIX object list."""

    if bundle.get("type") != "bundle":
        raise MitreParserError("Expected a STIX bundle with type='bundle'")

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise MitreParserError("The STIX bundle must contain an 'objects' list")
    if not objects:
        raise MitreParserError("The STIX bundle contains no objects")
    if not all(isinstance(obj, dict) for obj in objects):
        raise MitreParserError("Every item in the STIX objects list must be an object")

    return objects


def _index_objects(objects: Iterable[JsonObject]) -> dict[str, JsonObject]:
    """Index STIX objects by ID and reject duplicate or missing identifiers."""

    indexed: dict[str, JsonObject] = {}
    for obj in objects:
        object_id = obj.get("id")
        if not isinstance(object_id, str) or not object_id:
            raise MitreParserError("Every STIX object must have a non-empty string ID")
        if object_id in indexed:
            raise MitreParserError(f"Duplicate STIX object ID: {object_id}")
        indexed[object_id] = obj
    return indexed


def _extract_tactic(tactic: Mapping[str, Any], order: int) -> JsonObject:
    reference = _require_attack_reference(tactic, expected_prefix="TA")
    return {
        "attack_id": reference["external_id"],
        "stix_id": tactic["id"],
        "name": tactic.get("name", ""),
        "short_name": tactic.get("x_mitre_shortname", ""),
        "description": tactic.get("description", ""),
        "order": order,
        "version": tactic.get("x_mitre_version"),
        "created": tactic.get("created"),
        "modified": tactic.get("modified"),
        "url": reference.get("url"),
    }


def _extract_tactics(
    objects: list[JsonObject], objects_by_id: Mapping[str, JsonObject]
) -> tuple[list[JsonObject], dict[str, JsonObject]]:
    """Extract active Enterprise tactics in their matrix display order."""

    matrices = [
        obj
        for obj in objects
        if obj.get("type") == "x-mitre-matrix"
        and obj.get("name") == "Enterprise ATT&CK"
        and _is_active(obj)
    ]
    if len(matrices) != 1:
        raise MitreParserError(
            "Expected exactly one active 'Enterprise ATT&CK' matrix, "
            f"found {len(matrices)}"
        )

    tactics: list[JsonObject] = []
    tactics_by_short_name: dict[str, JsonObject] = {}
    for order, tactic_ref in enumerate(matrices[0].get("tactic_refs", []), start=1):
        tactic = objects_by_id.get(tactic_ref)
        if tactic is None or tactic.get("type") != "x-mitre-tactic":
            raise MitreParserError(f"Matrix references unknown tactic {tactic_ref!r}")
        if not _is_active(tactic):
            continue

        normalized = _extract_tactic(tactic, order)
        tactics.append(normalized)
        short_name = normalized["short_name"]
        if short_name:
            tactics_by_short_name[short_name] = normalized

    return tactics, tactics_by_short_name


def _group_relationships(
    objects: Iterable[JsonObject], relationship_type: str
) -> dict[str, list[JsonObject]]:
    """Group active relationships of one type by their target STIX ID."""

    relationships: dict[str, list[JsonObject]] = defaultdict(list)
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == relationship_type
            and _is_active(obj)
            and isinstance(obj.get("target_ref"), str)
        ):
            relationships[obj["target_ref"]].append(obj)
    return relationships


def _entity_identity(entity: Mapping[str, Any]) -> JsonObject:
    reference = _attack_reference(entity)
    return {
        "type": entity.get("type"),
        "stix_id": entity.get("id"),
        "attack_id": reference.get("external_id") if reference else None,
        "name": entity.get("name", ""),
        "url": reference.get("url") if reference else None,
    }


def _extract_procedures(
    technique_id: str,
    uses_by_target: Mapping[str, list[JsonObject]],
    objects_by_id: Mapping[str, JsonObject],
) -> list[JsonObject]:
    """Join active ATT&CK procedure examples attached through `uses` edges."""

    procedures: list[JsonObject] = []
    for relationship in uses_by_target.get(technique_id, []):
        source = objects_by_id.get(relationship.get("source_ref"))
        if (
            source is None
            or source.get("type") not in PROCEDURE_SOURCE_TYPES
            or not _is_active(source)
            or not _is_enterprise_object(source)
        ):
            continue

        procedures.append(
            {
                "relationship_stix_id": relationship["id"],
                "source": _entity_identity(source),
                "description": relationship.get("description", ""),
                "references": _external_references(relationship),
            }
        )

    return sorted(
        procedures,
        key=lambda item: (
            item["source"]["type"] or "",
            item["source"]["attack_id"] or "",
            item["source"]["name"],
            item["relationship_stix_id"],
        ),
    )


def _extract_analytic(analytic: Mapping[str, Any]) -> JsonObject:
    reference = _attack_reference(analytic)
    log_sources = [
        {
            key: log_source[key]
            for key in ("x_mitre_data_component_ref", "name", "channel")
            if log_source.get(key) is not None
        }
        for log_source in analytic.get("x_mitre_log_source_references", [])
        if isinstance(log_source, Mapping)
    ]
    return {
        "analytic_id": reference.get("external_id") if reference else None,
        "stix_id": analytic.get("id"),
        "name": analytic.get("name", ""),
        "description": analytic.get("description", ""),
        "platforms": sorted(analytic.get("x_mitre_platforms", [])),
        "log_sources": log_sources,
        "url": reference.get("url") if reference else None,
    }


def _extract_detection_strategies(
    technique_id: str,
    detects_by_target: Mapping[str, list[JsonObject]],
    objects_by_id: Mapping[str, JsonObject],
) -> list[JsonObject]:
    """Join active detection strategies and their active analytics."""

    strategies: list[JsonObject] = []
    for relationship in detects_by_target.get(technique_id, []):
        strategy = objects_by_id.get(relationship.get("source_ref"))
        if (
            strategy is None
            or strategy.get("type") != "x-mitre-detection-strategy"
            or not _is_active(strategy)
            or not _is_enterprise_object(strategy)
        ):
            continue

        reference = _require_attack_reference(strategy, expected_prefix="DET")
        analytics = []
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = objects_by_id.get(analytic_ref)
            if (
                analytic is not None
                and analytic.get("type") == "x-mitre-analytic"
                and _is_active(analytic)
                and _is_enterprise_object(analytic)
            ):
                analytics.append(_extract_analytic(analytic))

        strategies.append(
            {
                "detection_id": reference["external_id"],
                "stix_id": strategy["id"],
                "name": strategy.get("name", ""),
                "description": strategy.get("description", ""),
                "version": strategy.get("x_mitre_version"),
                "modified": strategy.get("modified"),
                "url": reference.get("url"),
                "analytics": sorted(
                    analytics,
                    key=lambda item: (item["analytic_id"] or "", item["stix_id"]),
                ),
            }
        )

    return sorted(
        strategies, key=lambda item: (item["detection_id"], item["stix_id"])
    )


def _technique_tactics(
    technique: Mapping[str, Any], tactics_by_short_name: Mapping[str, JsonObject]
) -> list[JsonObject]:
    """Resolve a technique's kill-chain phases to normalized tactics."""

    tactic_summaries: list[JsonObject] = []
    seen: set[str] = set()
    for phase in technique.get("kill_chain_phases", []):
        if (
            not isinstance(phase, Mapping)
            or phase.get("kill_chain_name") != ATTACK_SOURCE_NAME
        ):
            continue
        short_name = phase.get("phase_name")
        tactic = tactics_by_short_name.get(short_name)
        if tactic is None:
            raise MitreParserError(
                f"Technique {technique.get('id')!r} references unknown tactic "
                f"{short_name!r}"
            )
        if tactic["stix_id"] in seen:
            continue
        seen.add(tactic["stix_id"])
        tactic_summaries.append(
            {
                "attack_id": tactic["attack_id"],
                "name": tactic["name"],
                "short_name": tactic["short_name"],
                "order": tactic["order"],
            }
        )

    return sorted(tactic_summaries, key=lambda item: item["order"])


def _build_retrieval_text(
    attack_id: str,
    name: str,
    description: str,
    tactics: list[JsonObject],
    platforms: list[str],
) -> str:
    """Create deterministic core text for the future retrieval baseline."""

    sections = [f"ATT&CK technique {attack_id}: {name}."]
    if tactics:
        sections.append("Tactics: " + ", ".join(item["name"] for item in tactics) + ".")
    if platforms:
        sections.append("Platforms: " + ", ".join(platforms) + ".")
    if description:
        sections.append("Description: " + description.strip())
    return "\n".join(sections)


def _extract_technique(
    technique: Mapping[str, Any],
    tactics_by_short_name: Mapping[str, JsonObject],
    uses_by_target: Mapping[str, list[JsonObject]],
    detects_by_target: Mapping[str, list[JsonObject]],
    objects_by_id: Mapping[str, JsonObject],
) -> JsonObject:
    reference = _require_attack_reference(technique, expected_prefix="T")
    attack_id = reference["external_id"]
    if "." in attack_id:
        raise MitreParserError(
            f"Sub-technique {attack_id} reached the parent-technique extractor"
        )

    tactics = _technique_tactics(technique, tactics_by_short_name)
    platforms = sorted(technique.get("x_mitre_platforms", []))
    name = technique.get("name", "")
    description = technique.get("description", "")
    stix_id = technique["id"]

    return {
        "attack_id": attack_id,
        "stix_id": stix_id,
        "name": name,
        "description": description,
        "tactics": tactics,
        "platforms": platforms,
        "version": technique.get("x_mitre_version"),
        "created": technique.get("created"),
        "modified": technique.get("modified"),
        "url": reference.get("url"),
        "references": _external_references(technique),
        "detection_strategies": _extract_detection_strategies(
            stix_id, detects_by_target, objects_by_id
        ),
        "procedure_examples": _extract_procedures(
            stix_id, uses_by_target, objects_by_id
        ),
        "retrieval_text": _build_retrieval_text(
            attack_id, name, description, tactics, platforms
        ),
    }


def _attack_id_sort_key(technique: Mapping[str, Any]) -> tuple[int, str]:
    attack_id = technique["attack_id"]
    match = re.fullmatch(r"T(\d+)", attack_id)
    if match is None:
        raise MitreParserError(f"Unexpected parent technique ID: {attack_id!r}")
    return int(match.group(1)), attack_id


def parse_enterprise_attack_bundle(bundle: Mapping[str, Any]) -> JsonObject:
    """Normalize active Enterprise parent techniques from a STIX bundle."""

    objects = _validate_bundle(bundle)
    objects_by_id = _index_objects(objects)
    tactics, tactics_by_short_name = _extract_tactics(objects, objects_by_id)
    uses_by_target = _group_relationships(objects, "uses")
    detects_by_target = _group_relationships(objects, "detects")

    source_techniques = [
        obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("x_mitre_is_subtechnique", False)
        and _is_active(obj)
        and _is_enterprise_object(obj)
    ]
    techniques = [
        _extract_technique(
            technique,
            tactics_by_short_name,
            uses_by_target,
            detects_by_target,
            objects_by_id,
        )
        for technique in source_techniques
    ]
    techniques.sort(key=_attack_id_sort_key)

    return {
        "schema_version": 1,
        "domain": ENTERPRISE_DOMAIN,
        "scope": {
            "includes_parent_techniques": True,
            "includes_subtechniques": False,
            "includes_revoked": False,
            "includes_deprecated": False,
        },
        "source": {
            "bundle_id": bundle.get("id"),
            "object_count": len(objects),
        },
        "counts": {
            "tactics": len(tactics),
            "techniques": len(techniques),
            "detection_strategy_links": sum(
                len(item["detection_strategies"]) for item in techniques
            ),
            "procedure_examples": sum(
                len(item["procedure_examples"]) for item in techniques
            ),
        },
        "tactics": tactics,
        "techniques": techniques,
    }


def parse_enterprise_attack_file(source_path: Path) -> JsonObject:
    """Load and normalize an ATT&CK Enterprise JSON bundle from disk."""

    try:
        with source_path.open(encoding="utf-8") as source_file:
            bundle = json.load(source_file)
    except FileNotFoundError as error:
        raise MitreParserError(f"Source file not found: {source_path}") from error
    except json.JSONDecodeError as error:
        raise MitreParserError(
            f"Source file is not valid JSON: {source_path}: {error}"
        ) from error

    if not isinstance(bundle, Mapping):
        raise MitreParserError("The JSON root must be an object")
    return parse_enterprise_attack_bundle(bundle)


def write_parsed_data(parsed_data: Mapping[str, Any], output_path: Path) -> None:
    """Write normalized ATT&CK data in a stable, human-readable JSON format."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(parsed_data, output_file, ensure_ascii=False, indent=2, sort_keys=True)
        output_file.write("\n")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parse active parent techniques from a MITRE ATT&CK Enterprise STIX "
            "bundle."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Source STIX JSON file (default: {DEFAULT_INPUT_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Normalized JSON output (default: {DEFAULT_OUTPUT_PATH})",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    try:
        parsed_data = parse_enterprise_attack_file(args.input)
        write_parsed_data(parsed_data, args.output)
    except MitreParserError as error:
        raise SystemExit(f"ATT&CK parsing failed: {error}") from error

    counts = parsed_data["counts"]
    print(
        "Parsed "
        f"{counts['techniques']} active parent techniques, "
        f"{counts['tactics']} tactics, "
        f"{counts['detection_strategy_links']} detection strategy links, and "
        f"{counts['procedure_examples']} procedure examples."
    )
    print(f"Wrote normalized data to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
