"""SARIF export for code scanning and security review systems."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding, TrustReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build_sarif(report: TrustReport) -> dict[str, Any]:
    rules = [_rule(finding) for finding in _unique_findings(report.findings)]
    results = [_result(finding) for finding in report.findings]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenClaw SkillTrust",
                        "informationUri": "https://github.com/ejikezebedee/openclaw-skilltrust",
                        "rules": rules,
                        "semanticVersion": "0.1.0",
                    }
                },
                "automationDetails": {"id": f"skilltrust/{report.policy}"},
                "properties": {
                    "skilltrust:target": report.path,
                    "skilltrust:policy": report.policy,
                    "skilltrust:verdict": report.verdict,
                    "skilltrust:score": report.score,
                    "skilltrust:assurance_level": report.assurance_level,
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: TrustReport, output: str | Path) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_sarif(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path


def _unique_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        unique.append(finding)
    return tuple(unique)


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.remediation or finding.title},
        "help": {"text": finding.remediation or "Review the finding before installing or executing this extension."},
        "properties": {
            "category": finding.category,
            "confidence": finding.confidence,
            "security-severity": str(_security_severity(finding.severity)),
        },
        "defaultConfiguration": {"level": _sarif_level(finding.severity)},
    }


def _result(finding: Finding) -> dict[str, Any]:
    region = {"startLine": finding.line or 1}
    if finding.evidence:
        region["snippet"] = {"text": finding.evidence}
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": f"{finding.title}: {finding.remediation}".strip()},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": region,
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "confidence": finding.confidence,
        },
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _security_severity(severity: str) -> float:
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
    }.get(severity, 1.0)
