"""Shared data models for SkillTrust."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    line: int | None = None
    evidence: str = ""
    remediation: str = ""
    category: str = "general"
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class Manifest:
    path: str
    kind: str
    name: str = ""
    description: str = ""
    declared_capabilities: tuple[str, ...] = ()
    raw_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "name": self.name,
            "description": self.description,
            "declared_capabilities": list(self.declared_capabilities),
            "raw_keys": list(self.raw_keys),
        }


@dataclass(frozen=True)
class ControlCheck:
    control_id: str
    status: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RuntimeDecision:
    action: str
    decision: str
    capability: str
    policy: str
    reason: str
    matched_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "decision": self.decision,
            "capability": self.capability,
            "policy": self.policy,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
        }


@dataclass(frozen=True)
class ProbeResult:
    probe_id: str
    category: str
    status: str
    title: str
    detail: str
    mapped_risk: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "category": self.category,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "mapped_risk": self.mapped_risk,
        }


@dataclass(frozen=True)
class ComplianceMapping:
    framework: str
    control: str
    status: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "control": self.control,
            "status": self.status,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ReadinessScore:
    score: int
    status: str
    title: str
    factors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "status": self.status,
            "title": self.title,
            "factors": list(self.factors),
        }


@dataclass(frozen=True)
class TrustReport:
    path: str
    score: int
    verdict: str
    policy: str
    assurance_level: str
    capabilities: tuple[str, ...]
    findings: tuple[Finding, ...]
    manifests: tuple[Manifest, ...]
    scanned_files: int
    summary: str
    remediation: tuple[str, ...] = field(default_factory=tuple)
    severity_counts: dict[str, int] = field(default_factory=dict)
    score_factors: tuple[str, ...] = field(default_factory=tuple)
    control_checks: tuple[ControlCheck, ...] = field(default_factory=tuple)
    runtime_decisions: tuple[RuntimeDecision, ...] = field(default_factory=tuple)
    probe_results: tuple[ProbeResult, ...] = field(default_factory=tuple)
    compliance_mappings: tuple[ComplianceMapping, ...] = field(default_factory=tuple)
    quarantine_readiness: ReadinessScore | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "openclaw.skilltrust.report.v1",
            "path": self.path,
            "score": self.score,
            "verdict": self.verdict,
            "policy": self.policy,
            "assurance_level": self.assurance_level,
            "capabilities": list(self.capabilities),
            "findings": [finding.to_dict() for finding in self.findings],
            "manifests": [manifest.to_dict() for manifest in self.manifests],
            "scanned_files": self.scanned_files,
            "summary": self.summary,
            "remediation": list(self.remediation),
            "severity_counts": dict(self.severity_counts),
            "score_factors": list(self.score_factors),
            "control_checks": [check.to_dict() for check in self.control_checks],
            "runtime_decisions": [decision.to_dict() for decision in self.runtime_decisions],
            "probe_results": [probe.to_dict() for probe in self.probe_results],
            "compliance_mappings": [mapping.to_dict() for mapping in self.compliance_mappings],
            "quarantine_readiness": self.quarantine_readiness.to_dict() if self.quarantine_readiness else None,
        }


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def portable_path(path: Path) -> str:
    """Render user-facing paths without leaking machine-specific parents."""

    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name
