"""Markdown report rendering."""

from __future__ import annotations

from .models import TrustReport


def render_markdown(report: TrustReport) -> str:
    lines = [
        "# SkillTrust Report",
        "",
        f"- Verdict: `{report.verdict}`",
        f"- Score: `{report.score}`",
        f"- Policy: `{report.policy}`",
        f"- Assurance level: `{report.assurance_level}`",
        f"- Scanned files: `{report.scanned_files}`",
        f"- Summary: {report.summary}",
        "",
        "## Severity Breakdown",
        "",
    ]
    if report.severity_counts:
        lines.extend(
            f"- `{severity}`: {report.severity_counts[severity]}"
            for severity in ("critical", "high", "medium", "low")
            if severity in report.severity_counts
        )
    else:
        lines.append("- None detected")

    lines.extend(
        [
            "",
            "## Control Checks",
            "",
        ]
    )
    if report.control_checks:
        lines.extend(
            f"- `{check.status}` `{check.control_id}` {check.title}: {check.detail}"
            for check in report.control_checks
        )
    else:
        lines.append("- None recorded")

    lines.extend(
        [
            "",
            "## Runtime Guard Preview",
            "",
        ]
    )
    if report.runtime_decisions:
        lines.extend(
            f"- `{decision.decision}` `{decision.capability}` {decision.reason}"
            for decision in report.runtime_decisions
        )
    else:
        lines.append("- No runtime guard decisions generated")

    lines.extend(
        [
            "",
            "## Adversarial Probes",
            "",
        ]
    )
    if report.probe_results:
        lines.extend(
            f"- `{probe.status}` `{probe.probe_id}` {probe.category}: {probe.detail}"
            for probe in report.probe_results
        )
    else:
        lines.append("- No probe results generated")

    lines.extend(
        [
            "",
            "## Compliance Mapping",
            "",
        ]
    )
    if report.compliance_mappings:
        lines.extend(
            f"- `{mapping.status}` {mapping.framework} - {mapping.control}: {mapping.evidence}"
            for mapping in report.compliance_mappings
        )
    else:
        lines.append("- No compliance mappings generated")

    lines.extend(
        [
            "",
            "## Quarantine Readiness",
            "",
        ]
    )
    if report.quarantine_readiness:
        lines.append(
            f"- `{report.quarantine_readiness.score}/100` `{report.quarantine_readiness.status}` "
            f"{report.quarantine_readiness.title}"
        )
        lines.extend(f"- {factor}" for factor in report.quarantine_readiness.factors)
    else:
        lines.append("- No quarantine readiness score generated")

    lines.extend([
        "",
        "## Capabilities",
        "",
    ])
    if report.capabilities:
        lines.extend(f"- `{capability}`" for capability in report.capabilities)
    else:
        lines.append("- None detected")

    lines.extend(["", "## Manifests", ""])
    if report.manifests:
        for manifest in report.manifests:
            lines.append(f"- `{manifest.path}` ({manifest.kind}) {manifest.name}".rstrip())
    else:
        lines.append("- None detected")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings:
            location = finding.path
            if finding.line:
                location += f":{finding.line}"
            lines.append(f"- `{finding.severity}` `{finding.rule_id}` {finding.title} at `{location}`")
            if finding.evidence:
                lines.append(f"  Evidence: `{finding.evidence}`")
    else:
        lines.append("- No detector findings")

    lines.extend(["", "## Remediation", ""])
    lines.extend(f"- {item}" for item in report.remediation)
    lines.extend(["", "## Score Factors", ""])
    if report.score_factors:
        lines.extend(f"- {factor}" for factor in report.score_factors)
    else:
        lines.append("- No penalties applied")
    lines.append("")
    return "\n".join(lines)
