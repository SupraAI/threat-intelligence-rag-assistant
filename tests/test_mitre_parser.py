"""Tests for the ATT&CK Enterprise parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.parser.mitre_parser import (
    MitreParserError,
    parse_enterprise_attack_bundle,
    parse_enterprise_attack_file,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUPPLIED_BUNDLE = PROJECT_ROOT / "data" / "enterprise-attack (2).json"


def _reference(external_id: str, path: str) -> list[dict[str, str]]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
            "url": f"https://attack.mitre.org/{path}",
        }
    ]


def _synthetic_bundle() -> dict[str, object]:
    tactic_id = "x-mitre-tactic--00000000-0000-4000-8000-000000000001"
    technique_id = "attack-pattern--00000000-0000-4000-8000-000000000002"
    strategy_id = "x-mitre-detection-strategy--00000000-0000-4000-8000-000000000003"
    analytic_id = "x-mitre-analytic--00000000-0000-4000-8000-000000000004"
    group_id = "intrusion-set--00000000-0000-4000-8000-000000000005"

    base_technique = {
        "type": "attack-pattern",
        "id": technique_id,
        "name": "Example Technique",
        "description": "An adversary may perform an example behavior.",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-02T00:00:00.000Z",
        "revoked": False,
        "x_mitre_deprecated": False,
        "x_mitre_is_subtechnique": False,
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_platforms": ["Windows", "Linux"],
        "x_mitre_version": "1.0",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "example-tactic"}
        ],
        "external_references": _reference("T1000", "techniques/T1000"),
    }

    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--00000000-0000-4000-8000-000000000000",
                "name": "Enterprise ATT&CK",
                "tactic_refs": [tactic_id],
            },
            {
                "type": "x-mitre-tactic",
                "id": tactic_id,
                "name": "Example Tactic",
                "description": "Example tactic description.",
                "x_mitre_shortname": "example-tactic",
                "external_references": _reference("TA0001", "tactics/TA0001"),
            },
            base_technique,
            {
                **base_technique,
                "id": "attack-pattern--00000000-0000-4000-8000-000000000006",
                "name": "Excluded Sub-technique",
                "x_mitre_is_subtechnique": True,
                "external_references": _reference(
                    "T1000.001", "techniques/T1000/001"
                ),
            },
            {
                **base_technique,
                "id": "attack-pattern--00000000-0000-4000-8000-000000000007",
                "name": "Excluded Revoked Technique",
                "revoked": True,
                "external_references": _reference("T1001", "techniques/T1001"),
            },
            {
                **base_technique,
                "id": "attack-pattern--00000000-0000-4000-8000-000000000008",
                "name": "Excluded Deprecated Technique",
                "x_mitre_deprecated": True,
                "external_references": _reference("T1002", "techniques/T1002"),
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": strategy_id,
                "name": "Example Detection",
                "x_mitre_analytic_refs": [analytic_id],
                "external_references": _reference(
                    "DET0001", "detectionstrategies/DET0001"
                ),
            },
            {
                "type": "x-mitre-analytic",
                "id": analytic_id,
                "name": "Example Analytic",
                "description": "Detect the example behavior.",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_log_source_references": [
                    {"name": "example:log", "channel": "events"}
                ],
                "external_references": _reference(
                    "AN0001", "detectionstrategies/DET0001#AN0001"
                ),
            },
            {
                "type": "intrusion-set",
                "id": group_id,
                "name": "Example Group",
                "external_references": _reference("G0001", "groups/G0001"),
            },
            {
                "type": "relationship",
                "id": "relationship--00000000-0000-4000-8000-000000000009",
                "relationship_type": "detects",
                "source_ref": strategy_id,
                "target_ref": technique_id,
            },
            {
                "type": "relationship",
                "id": "relationship--00000000-0000-4000-8000-000000000010",
                "relationship_type": "uses",
                "source_ref": group_id,
                "target_ref": technique_id,
                "description": "The example group used the example technique.",
                "external_references": [
                    {"source_name": "Example report", "url": "https://example.test"}
                ],
            },
        ],
    }


def test_parser_keeps_only_active_parent_techniques_and_joins_context() -> None:
    parsed = parse_enterprise_attack_bundle(_synthetic_bundle())

    assert parsed["counts"] == {
        "tactics": 1,
        "techniques": 1,
        "detection_strategy_links": 1,
        "procedure_examples": 1,
    }
    technique = parsed["techniques"][0]
    assert technique["attack_id"] == "T1000"
    assert technique["platforms"] == ["Linux", "Windows"]
    assert technique["tactics"][0]["attack_id"] == "TA0001"
    assert technique["detection_strategies"][0]["detection_id"] == "DET0001"
    assert (
        technique["detection_strategies"][0]["analytics"][0]["analytic_id"]
        == "AN0001"
    )
    assert technique["procedure_examples"][0]["source"]["attack_id"] == "G0001"
    assert "Example Technique" in technique["retrieval_text"]


def test_parser_rejects_non_bundle_json() -> None:
    with pytest.raises(MitreParserError, match="type='bundle'"):
        parse_enterprise_attack_bundle({"type": "not-a-bundle", "objects": []})


def test_supplied_bundle_has_expected_first_iteration_scope() -> None:
    parsed = parse_enterprise_attack_file(SUPPLIED_BUNDLE)

    assert parsed["source"]["object_count"] == 26_085
    assert parsed["counts"]["tactics"] == 15
    assert parsed["counts"]["techniques"] == 222
    assert all("." not in item["attack_id"] for item in parsed["techniques"])
    assert all(item["url"] for item in parsed["techniques"])
