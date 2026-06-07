"""Governance evidence mappings for AI-agent extension reviews."""

from __future__ import annotations

from .models import ComplianceMapping, ControlCheck, ProbeResult


def map_compliance(
    control_checks: tuple[ControlCheck, ...],
    probe_results: tuple[ProbeResult, ...],
) -> tuple[ComplianceMapping, ...]:
    failed_controls = [check.control_id for check in control_checks if check.status == "fail"]
    review_controls = [check.control_id for check in control_checks if check.status == "review"]
    failed_probes = [probe.probe_id for probe in probe_results if probe.status == "fail"]

    control_status = "fail" if failed_controls else "review" if review_controls else "pass"
    probe_status = "fail" if failed_probes else "pass"

    return (
        ComplianceMapping(
            framework="SOC 2",
            control="CC6.1 logical access controls",
            status=control_status,
            evidence=_evidence("policy controls", failed_controls or review_controls),
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control="AI system impact and risk treatment",
            status="fail" if failed_controls or failed_probes else "review" if review_controls else "pass",
            evidence=_evidence("control/probe evidence", failed_controls + review_controls + failed_probes),
        ),
        ComplianceMapping(
            framework="OWASP LLM / Agentic",
            control="Prompt injection, sensitive data, excessive agency, and supply-chain review",
            status=probe_status,
            evidence=_evidence("adversarial probes", failed_probes),
        ),
        ComplianceMapping(
            framework="OWASP Agentic AI",
            control="Goal hijacking and instruction-boundary integrity",
            status="fail" if "PROBE-001" in failed_probes else "pass",
            evidence=_evidence("prompt-injection probes", [probe for probe in failed_probes if probe == "PROBE-001"]),
        ),
        ComplianceMapping(
            framework="OWASP Agentic AI",
            control="Tool misuse and excessive agency controls",
            status=control_status,
            evidence=_evidence("runtime and policy gates", failed_controls or review_controls),
        ),
        ComplianceMapping(
            framework="OWASP Agentic AI",
            control="Memory, credential, and data exfiltration boundaries",
            status="fail" if "PROBE-002" in failed_probes else "review" if review_controls else "pass",
            evidence=_evidence("exfiltration probes", [probe for probe in failed_probes if probe == "PROBE-002"]),
        ),
        ComplianceMapping(
            framework="OpenSSF / SLSA readiness",
            control="Repository security, BOM, and provenance evidence",
            status=control_status,
            evidence=_evidence(
                "supply-chain controls",
                [item for item in failed_controls + review_controls if item.startswith(("SCM-", "SLSA-", "BOM-"))],
            ),
        ),
        ComplianceMapping(
            framework="EU AI Act readiness",
            control="Risk-management evidence and human oversight",
            status="review" if review_controls else "pass" if not failed_controls else "fail",
            evidence=_evidence("human oversight gates", failed_controls or review_controls),
        ),
    )


def _evidence(prefix: str, items: list[str]) -> str:
    if items:
        return f"{prefix}: " + ", ".join(items)
    return f"{prefix}: no blocking evidence detected"
