"""Unified SkillTrust scan flow."""

from __future__ import annotations

from pathlib import Path

from .capabilities import classify_text
from .compliance import map_compliance
from .detectors import detect_file
from .discovery import discover_files
from .manifest import parse_manifest
from .models import ControlCheck, Manifest, TrustReport, portable_path
from .policies import get_policy_pack
from .probes import run_adversarial_probes
from .readiness import quarantine_readiness_score
from .runtime_guard import default_runtime_decisions
from .supply_chain import supply_chain_checks
from .trust_score import score


def scan_path(path: str | Path, policy: str = "baseline") -> TrustReport:
    root = Path(path).resolve()
    policy_pack = get_policy_pack(policy)
    files = discover_files(root)
    manifests: list[Manifest] = []
    findings = []
    capabilities: set[str] = set()

    for file_path in files:
        manifest = parse_manifest(file_path, root if root.is_dir() else root.parent)
        if manifest:
            manifests.append(manifest)
            capabilities.update(manifest.declared_capabilities)

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        capabilities.update(classify_text(text))
        findings.extend(detect_file(file_path, root if root.is_dir() else root.parent))

    final_score, verdict, remediation, summary, score_factors = score(findings, capabilities)
    severity_counts = _severity_counts(findings)
    control_checks = _control_checks(findings, capabilities, policy_pack) + supply_chain_checks(root)
    runtime_decisions = default_runtime_decisions(capabilities, policy_pack.name)
    probe_results = run_adversarial_probes(root, tuple(findings))
    compliance_mappings = map_compliance(control_checks, probe_results)
    readiness = quarantine_readiness_score(
        verdict,
        tuple(findings),
        remediation,
        control_checks,
        runtime_decisions,
        probe_results,
        compliance_mappings,
    )
    assurance_level = _assurance_level(final_score, verdict, findings, control_checks)
    return TrustReport(
        path=portable_path(root),
        score=final_score,
        verdict=verdict,
        policy=policy_pack.name,
        assurance_level=assurance_level,
        capabilities=tuple(sorted(capabilities)),
        findings=tuple(findings),
        manifests=tuple(manifests),
        scanned_files=len(files),
        summary=summary,
        remediation=remediation,
        severity_counts=severity_counts,
        score_factors=score_factors,
        control_checks=control_checks,
        runtime_decisions=runtime_decisions,
        probe_results=probe_results,
        compliance_mappings=compliance_mappings,
        quarantine_readiness=readiness,
    )


def _severity_counts(findings) -> dict[str, int]:
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {severity: count for severity, count in counts.items() if count}


def _control_checks(findings, capabilities: set[str], policy_pack) -> tuple[ControlCheck, ...]:
    finding_rules = {finding.rule_id for finding in findings}
    gated = sorted(capability for capability in capabilities if capability in policy_pack.gated_capabilities)
    reviewed = sorted(capability for capability in capabilities if capability in policy_pack.review_capabilities)
    blocked = sorted(rule_id for rule_id in finding_rules if rule_id in policy_pack.block_rules)

    checks = [
        ControlCheck(
            "POL-001",
            "fail" if blocked else "pass",
            "Blocking rule enforcement",
            "Policy block rules triggered: " + ", ".join(blocked) if blocked else "No policy block rules triggered.",
        ),
        ControlCheck(
            "POL-002",
            "review" if gated else "pass",
            "Gated capability review",
            "Gated capabilities detected: " + ", ".join(gated) if gated else "No gated capabilities detected.",
        ),
        ControlCheck(
            "POL-003",
            "review" if reviewed else "pass",
            "Declared review boundary",
            "Review capabilities detected: " + ", ".join(reviewed) if reviewed else "No review-boundary capabilities detected.",
        ),
        ControlCheck(
            "EVD-001",
            "pass" if findings or capabilities else "review",
            "Evidence availability",
            "Scanner collected findings or capability evidence."
            if findings or capabilities
            else "No findings or capability evidence collected; perform maintainer review.",
        ),
        ControlCheck(
            "RUN-001",
            "review" if gated or reviewed else "pass",
            "Runtime guard preview",
            "Runtime guard will require review for detected gated or review-boundary capabilities."
            if gated or reviewed
            else "Runtime guard found no detected capability that requires review.",
        ),
        ControlCheck(
            "ADV-001",
            "review" if any(rule_id in finding_rules for rule_id in {"ST003", "ST004", "ST005", "ST006"}) else "pass",
            "Adversarial probe coverage",
            "Adversarial probes should be reviewed because high-risk detector evidence exists."
            if any(rule_id in finding_rules for rule_id in {"ST003", "ST004", "ST005", "ST006"})
            else "Adversarial probes did not detect high-risk prompt, exfiltration, install, or destructive-action evidence.",
        ),
    ]
    return tuple(checks)


def _assurance_level(score_value: int, verdict: str, findings, control_checks: tuple[ControlCheck, ...]) -> str:
    if verdict == "block" or any(check.status == "fail" for check in control_checks):
        return "blocked"
    if verdict == "quarantine":
        return "quarantine-required"
    if verdict == "review" or any(check.status == "review" for check in control_checks):
        return "human-review-required"
    if score_value >= 95 and not findings:
        return "high-assurance"
    return "standard-assurance"
