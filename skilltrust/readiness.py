"""Quarantine readiness scoring for remediation evidence completeness."""

from __future__ import annotations

from .models import ComplianceMapping, ControlCheck, Finding, ProbeResult, ReadinessScore, RuntimeDecision


def quarantine_readiness_score(
    verdict: str,
    findings: tuple[Finding, ...],
    remediation: tuple[str, ...],
    control_checks: tuple[ControlCheck, ...],
    runtime_decisions: tuple[RuntimeDecision, ...],
    probe_results: tuple[ProbeResult, ...],
    compliance_mappings: tuple[ComplianceMapping, ...],
) -> ReadinessScore:
    """Score whether a quarantined item has enough evidence to remediate safely.

    This is not the trust score. A risky extension can have a low trust score and
    still have a high quarantine-readiness score if the review package is
    complete, actionable, and governance-ready.
    """

    if verdict not in {"quarantine", "block", "review"}:
        return ReadinessScore(
            score=100,
            status="not-required",
            title="Quarantine readiness not required",
            factors=("No quarantine workflow required for this verdict.",),
        )

    score = 40
    factors: list[str] = ["base quarantine workflow evidence: +40"]

    if findings:
        score += 12
        factors.append("detector evidence captured: +12")
    if remediation:
        score += 12
        factors.append("remediation actions generated: +12")
    if control_checks and all(check.status in {"pass", "review", "fail"} for check in control_checks):
        score += 10
        factors.append("policy control evidence present: +10")
    if runtime_decisions:
        score += 8
        factors.append("runtime guard decisions present: +8")
    if probe_results:
        score += 8
        factors.append("adversarial probe evidence present: +8")
    if compliance_mappings:
        score += 5
        factors.append("governance mappings present: +5")
    supply_chain_ids = {check.control_id for check in control_checks if check.control_id.startswith(("SCM-", "SLSA-", "BOM-"))}
    if {"SCM-001", "SCM-002", "SCM-003", "SLSA-001", "BOM-001"} <= supply_chain_ids:
        score += 3
        factors.append("supply-chain, provenance, and BOM evidence present: +3")

    if any(finding.severity == "critical" for finding in findings):
        score = min(score, 85)
        factors.append("critical finding caps readiness at 85 until removed")
    elif verdict == "quarantine":
        cap = 98 if {"SCM-001", "SCM-002", "SCM-003", "SLSA-001", "BOM-001"} <= supply_chain_ids else 95
        score = min(score, cap)
        factors.append(f"quarantine verdict caps readiness at {cap} until risky source is fixed")
    elif verdict == "review":
        score = min(score, 97)
        factors.append("review verdict caps readiness at 97 until review is closed")

    final_score = max(0, min(100, score))
    status = "remediation-ready" if final_score >= 95 else "needs-evidence" if final_score >= 75 else "incomplete"
    return ReadinessScore(
        score=final_score,
        status=status,
        title="Quarantine remediation readiness",
        factors=tuple(factors),
    )
