"""Controlled adversarial probes for defensive extension review."""

from __future__ import annotations

from pathlib import Path

from .models import Finding, ProbeResult, relative_path


PROBE_MAP: dict[str, tuple[str, str, str]] = {
    "ST005": ("PROBE-001", "prompt-injection", "OWASP LLM01 / Agentic excessive agency"),
    "ST006": ("PROBE-002", "credential-exfiltration", "OWASP LLM02 / sensitive information disclosure"),
    "ST004": ("PROBE-003", "unsafe-install-flow", "OWASP LLM05 / supply chain risk"),
    "ST003": ("PROBE-004", "destructive-action", "OWASP Agentic cascading impact"),
}


BOUNDARY_MARKERS = (
    "defensive",
    "explicit approval",
    "human review",
    "do not reveal",
    "least privilege",
    "quarantine",
)


def run_adversarial_probes(root: Path, findings: tuple[Finding, ...]) -> tuple[ProbeResult, ...]:
    results: list[ProbeResult] = []
    triggered = {finding.rule_id for finding in findings}

    for rule_id, (probe_id, category, mapped_risk) in PROBE_MAP.items():
        if rule_id in triggered:
            results.append(
                ProbeResult(
                    probe_id=probe_id,
                    category=category,
                    status="fail",
                    title=f"Adversarial probe matched detector {rule_id}",
                    detail="Existing scan evidence contains language that this probe is designed to catch.",
                    mapped_risk=mapped_risk,
                )
            )
        else:
            results.append(
                ProbeResult(
                    probe_id=probe_id,
                    category=category,
                    status="pass",
                    title=f"No {category} probe trigger detected",
                    detail="No matching detector evidence appeared in scanned files.",
                    mapped_risk=mapped_risk,
                )
            )

    boundary_status, boundary_detail = _boundary_status(root)
    results.append(
        ProbeResult(
            probe_id="PROBE-005",
            category="instruction-boundary",
            status=boundary_status,
            title="Instruction boundary evidence",
            detail=boundary_detail,
            mapped_risk="OWASP Agentic human-agent trust boundaries",
        )
    )
    return tuple(results)


def _boundary_status(root: Path) -> tuple[str, str]:
    marker_hits: list[str] = []
    files = [root] if root.is_file() else [path for path in root.rglob("*") if path.is_file()]
    for path in files[:200]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for marker in BOUNDARY_MARKERS:
            if marker in text and marker not in marker_hits:
                marker_hits.append(marker)

    if marker_hits:
        return "pass", "Boundary language detected: " + ", ".join(sorted(marker_hits))
    return "review", "No explicit boundary language detected; add least-privilege and human-review instructions."
