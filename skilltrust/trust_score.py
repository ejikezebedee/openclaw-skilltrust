"""Trust scoring for SkillTrust reports."""

from __future__ import annotations

from .models import Finding

WEIGHTS = {
    "critical": 35,
    "high": 22,
    "medium": 10,
    "low": 4,
}

CAPABILITY_WEIGHTS = {
    "credentials": 8,
    "shell": 8,
    "deployment": 7,
    "payment": 7,
    "filesystem": 4,
    "network": 4,
    "messaging": 3,
    "browser": 3,
    "memory": 2,
    "scheduler": 2,
}


def score(findings: list[Finding], capabilities: set[str]) -> tuple[int, str, tuple[str, ...], str, tuple[str, ...]]:
    penalty = 0
    factors: list[str] = []
    for finding in findings:
        weight = WEIGHTS.get(finding.severity, 5)
        penalty += weight
        factors.append(f"{finding.rule_id}: -{weight} for {finding.severity} finding")
    for capability in capabilities:
        weight = CAPABILITY_WEIGHTS.get(capability, 1)
        penalty += weight
        factors.append(f"capability:{capability}: -{weight} exposure weight")

    final_score = max(0, min(100, 100 - penalty))
    verdict = verdict_for(final_score, findings)
    remediation = tuple(_remediation(findings, capabilities, verdict))
    summary = _summary(final_score, verdict, findings)
    return final_score, verdict, remediation, summary, tuple(factors)


def verdict_for(final_score: int, findings: list[Finding]) -> str:
    if any(f.severity == "critical" for f in findings):
        return "block"
    if final_score < 45 or sum(1 for f in findings if f.severity == "high") >= 2:
        return "quarantine"
    if final_score < 80 or findings:
        return "review"
    return "trusted"


def _remediation(findings: list[Finding], capabilities: set[str], verdict: str) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.remediation and finding.remediation not in seen:
            items.append(finding.remediation)
            seen.add(finding.remediation)
    if verdict in {"review", "quarantine", "block"} and capabilities:
        items.append("Verify declared capabilities match maintainer intent before installation.")
    if not items:
        items.append("No blocking remediation detected; keep normal maintainer review.")
    return items


def _summary(final_score: int, verdict: str, findings: list[Finding]) -> str:
    if not findings:
        return f"{verdict.upper()}: score {final_score}; no detector findings."
    top = findings[0]
    return f"{verdict.upper()}: score {final_score}; top issue {top.rule_id} {top.title}."
