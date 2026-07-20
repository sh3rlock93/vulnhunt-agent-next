"""SARIF 2.1.0 exporter and offline structural validation."""
from __future__ import annotations

from typing import Any

from jsonschema import Draft7Validator

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)

# Offline acceptance subset of the OASIS SARIF 2.1.0 schema. The exporter emits
# only this deliberately small profile; consumers can additionally validate the
# `$schema` URI against the complete OASIS schema.
SARIF_PROFILE_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["version", "$schema", "runs"],
    "additionalProperties": False,
    "properties": {
        "version": {"const": "2.1.0"},
        "$schema": {"const": SARIF_SCHEMA_URI},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "automationDetails": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {"id": {"type": "string", "minLength": 1}},
                    },
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "rules"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "semanticVersion": {"type": "string"},
                                    "informationUri": {"type": "string", "format": "uri"},
                                    "rules": {"type": "array", "minItems": 1},
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": [
                                "ruleId", "ruleIndex", "level", "message", "locations"
                            ],
                            "properties": {
                                "ruleId": {"type": "string", "minLength": 1},
                                "ruleIndex": {"type": "integer", "minimum": 0},
                                "level": {"enum": ["none", "note", "warning", "error"]},
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                    "properties": {
                                        "text": {"type": "string", "minLength": 1}
                                    },
                                },
                                "locations": {"type": "array", "minItems": 1},
                                "relatedLocations": {"type": "array"},
                                "partialFingerprints": {"type": "object"},
                                "properties": {"type": "object"},
                            },
                        },
                    },
                },
            },
        },
    },
}

Draft7Validator.check_schema(SARIF_PROFILE_SCHEMA)
_VALIDATOR = Draft7Validator(SARIF_PROFILE_SCHEMA)


def build_sarif(canonical: dict) -> dict:
    finding = canonical["finding"]
    classification = canonical["classification"]
    entry = finding["entrypoint"]
    sink = finding.get("sink")
    severity = classification["severity"]
    cwe = classification["cwe_id"]
    rule = {
        "id": cwe,
        "name": cwe.replace("-", ""),
        "shortDescription": {"text": finding["title"]},
        "helpUri": (
            "https://cwe.mitre.org/data/definitions/"
            f"{cwe.removeprefix('CWE-')}.html"
        ),
        "properties": {
            "security-severity": f"{classification['cvss_score']:.1f}",
            "tags": ["security", cwe],
        },
    }
    result = {
        "ruleId": cwe,
        "ruleIndex": 0,
        "level": _sarif_level(severity),
        "message": {
            "text": finding["title"] + ": " + "; ".join(finding["impact"])
        },
        "locations": [{"physicalLocation": _physical_location(entry)}],
        "relatedLocations": (
            [{"id": 1, "message": {"text": "vulnerable sink"},
              "physicalLocation": _physical_location(sink)}]
            if sink else []
        ),
        "partialFingerprints": {
            "vulnhunt/v1": finding["fingerprint"],
        },
        "properties": {
            "candidateId": finding["candidate_id"],
            "cvssVector": classification["cvss_vector"],
            "evidenceIds": canonical["provenance"]["evidence_ids"],
            "sourceSnapshot": canonical["run"]["source_snapshot"],
            "reviewers": canonical["provenance"]["reviewers"],
        },
    }
    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA_URI,
        "runs": [{
            "automationDetails": {"id": canonical["run"]["run_id"]},
            "tool": {
                "driver": {
                    "name": "VulnHunt Agent",
                    "semanticVersion": "0.1.0",
                    "informationUri": "https://github.com/sh3rlock93/vulnhunt-agent-next",
                    "rules": [rule],
                }
            },
            "results": [result],
        }],
    }
    validate_sarif(sarif)
    return sarif


def validate_sarif(sarif: dict) -> None:
    errors = sorted(_VALIDATOR.iter_errors(sarif), key=lambda item: list(item.path))
    if errors:
        raise ValueError("invalid SARIF 2.1.0 profile: " + errors[0].message)


def _physical_location(location: dict) -> dict:
    region = {"startLine": location["line"]}
    if location.get("end_line"):
        region["endLine"] = location["end_line"]
    return {
        "artifactLocation": {"uri": location["path"], "uriBaseId": "%SRCROOT%"},
        "region": region,
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
