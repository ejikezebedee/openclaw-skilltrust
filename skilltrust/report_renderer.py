"""Markdown report rendering."""

from __future__ import annotations

from .models import TrustReport


def render_markdown(report: TrustReport) -> str:
    lines = [
        "# SkillTrust Report",
        "",
        f"- Verdict: {_code(report.verdict)}",
        f"- Score: {_code(report.score)}",
        f"- Policy: {_code(report.policy)}",
        f"- Assurance level: {_code(report.assurance_level)}",
        f"- Scanned files: {_code(report.scanned_files)}",
        f"- Summary: {_text(report.summary)}",
        "",
        "## Severity Breakdown",
        "",
    ]
    if report.severity_counts:
        lines.extend(
            f"- {_code(severity)}: {report.severity_counts[severity]}"
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
            f"- {_code(check.status)} {_code(check.control_id)} {_text(check.title)}: {_text(check.detail)}"
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
            f"- {_code(decision.decision)} {_code(decision.capability)} {_text(decision.reason)}"
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
            f"- {_code(probe.status)} {_code(probe.probe_id)} {_text(probe.category)}: {_text(probe.detail)}"
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
            f"- {_code(mapping.status)} {_text(mapping.framework)} - {_text(mapping.control)}: {_text(mapping.evidence)}"
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
            f"- {_code(str(report.quarantine_readiness.score) + '/100')} "
            f"{_code(report.quarantine_readiness.status)} {_text(report.quarantine_readiness.title)}"
        )
        lines.extend(f"- {_text(factor)}" for factor in report.quarantine_readiness.factors)
    else:
        lines.append("- No quarantine readiness score generated")

    lines.extend([
        "",
        "## Capabilities",
        "",
    ])
    if report.capabilities:
        lines.extend(f"- {_code(capability)}" for capability in report.capabilities)
    else:
        lines.append("- None detected")

    lines.extend(["", "## Manifests", ""])
    if report.manifests:
        for manifest in report.manifests:
            lines.append(f"- {_code(manifest.path)} ({_text(manifest.kind)}) {_text(manifest.name)}".rstrip())
    else:
        lines.append("- None detected")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings:
            location = finding.path
            if finding.line:
                location += f":{finding.line}"
            lines.append(
                f"- {_code(finding.severity)} {_code(finding.rule_id)} {_text(finding.title)} at {_code(location)}"
            )
            if finding.evidence:
                lines.append(f"  Evidence: {_code(finding.evidence)}")
    else:
        lines.append("- No detector findings")

    lines.extend(["", "## Remediation", ""])
    lines.extend(f"- {_text(item)}" for item in report.remediation)
    lines.extend(["", "## Score Factors", ""])
    if report.score_factors:
        lines.extend(f"- {_text(factor)}" for factor in report.score_factors)
    else:
        lines.append("- No penalties applied")
    lines.append("")
    return "\n".join(lines)


def _text(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def _code(value: object) -> str:
    text = _text(value)
    longest_run = 0
    current_run = 0
    for char in text:
        if char == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    fence = "`" * (longest_run + 1)
    if text.startswith("`") or text.endswith("`") or longest_run:
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"
