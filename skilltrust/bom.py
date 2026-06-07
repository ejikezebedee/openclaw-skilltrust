"""CycloneDX-style inventory export for SkillTrust evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .scanner import scan_path


def build_bom(path: str | Path, policy: str = "baseline") -> dict[str, Any]:
    report = scan_path(path, policy=policy)
    components = [
        {
            "type": "file",
            "name": manifest.name or manifest.path,
            "version": "",
            "scope": "required",
            "properties": [
                {"name": "skilltrust:manifest_kind", "value": manifest.kind},
                {"name": "skilltrust:path", "value": manifest.path},
            ],
        }
        for manifest in report.manifests
    ]
    for capability in report.capabilities:
        components.append(
            {
                "type": "service",
                "name": f"capability:{capability}",
                "scope": "required",
                "properties": [{"name": "skilltrust:capability", "value": capability}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-skilltrust-local",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "SkillTrust scanned extension",
                "version": "local",
                "properties": [
                    {"name": "skilltrust:target", "value": report.path},
                    {"name": "skilltrust:policy", "value": report.policy},
                    {"name": "skilltrust:verdict", "value": report.verdict},
                    {"name": "skilltrust:trust_score", "value": str(report.score)},
                ],
            }
        },
        "components": components,
        "vulnerabilities": [
            {
                "id": finding.rule_id,
                "source": {"name": "SkillTrust"},
                "ratings": [{"severity": finding.severity}],
                "description": finding.title,
                "recommendation": finding.remediation,
                "affects": [{"ref": finding.path}],
            }
            for finding in report.findings
        ],
    }


def write_bom(path: str | Path, output: str | Path, policy: str = "baseline") -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_bom(path, policy=policy), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path
