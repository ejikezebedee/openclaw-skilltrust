"""Command interface for OpenClaw SkillTrust."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bom import write_bom
from .quarantine import write_quarantine_bundle
from .evidence import write_evidence_bundle
from .report_renderer import render_markdown
from .scanner import scan_path
from .policies import list_policy_packs
from .models import portable_path
from .runtime_guard import evaluate_action

EXIT_BY_VERDICT = {
    "trusted": 0,
    "review": 10,
    "quarantine": 20,
    "block": 30,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skilltrust")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a skill, plugin, connector, or tool folder")
    scan.add_argument("path")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--markdown")
    scan.add_argument("--summary", action="store_true")
    scan.add_argument("--fail-on", choices=["review", "quarantine", "block"])
    scan.add_argument(
        "--policy",
        default="baseline",
        choices=[pack.name for pack in list_policy_packs()],
        help="policy pack to apply to enterprise control checks",
    )

    quarantine = sub.add_parser("quarantine", help="write a local review evidence bundle")
    quarantine.add_argument("path")
    quarantine.add_argument("--output", required=True)

    evidence = sub.add_parser("evidence", help="write executive evidence reports for release review")
    evidence.add_argument("path")
    evidence.add_argument("--output", required=True)
    evidence.add_argument(
        "--policy",
        default="baseline",
        choices=[pack.name for pack in list_policy_packs()],
        help="policy pack to apply to evidence generation",
    )

    bom = sub.add_parser("bom", help="write a CycloneDX-style capability and finding inventory")
    bom.add_argument("path")
    bom.add_argument("--output", required=True)
    bom.add_argument(
        "--policy",
        default="baseline",
        choices=[pack.name for pack in list_policy_packs()],
        help="policy pack to apply to BOM generation",
    )

    policies = sub.add_parser("policies", help="list built-in policy packs")
    policies.add_argument("--json", action="store_true")

    guard = sub.add_parser("guard", help="evaluate a proposed runtime action against a policy pack")
    guard.add_argument("action")
    guard.add_argument(
        "--policy",
        default="baseline",
        choices=[pack.name for pack in list_policy_packs()],
        help="policy pack to apply to runtime action review",
    )
    guard.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "scan":
        report = scan_path(args.path, policy=args.policy)
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.markdown:
            Path(args.markdown).write_text(render_markdown(report), encoding="utf-8")
        if args.summary:
            print(_render_summary(report))
        else:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        if args.fail_on and _should_fail(report.verdict, args.fail_on):
            return EXIT_BY_VERDICT[report.verdict]
        return 0

    if args.command == "quarantine":
        output = write_quarantine_bundle(args.path, args.output)
        print(portable_path(output))
        return 0

    if args.command == "evidence":
        output = write_evidence_bundle(args.path, args.output, policy=args.policy)
        print(portable_path(output))
        return 0

    if args.command == "bom":
        output = write_bom(args.path, args.output, policy=args.policy)
        print(portable_path(output))
        return 0

    if args.command == "policies":
        packs = list_policy_packs()
        if args.json:
            print(json.dumps([pack.__dict__ for pack in packs], indent=2, sort_keys=True))
        else:
            for pack in packs:
                print(f"{pack.name}: {pack.description}")
        return 0

    if args.command == "guard":
        decision = evaluate_action(args.action, policy=args.policy)
        if args.json:
            print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
        else:
            print(
                "\n".join(
                    [
                        f"Decision: {decision.decision.upper()}",
                        f"Policy: {decision.policy}",
                        f"Capability: {decision.capability}",
                        f"Reason: {decision.reason}",
                    ]
                )
            )
        if decision.decision == "block":
            return EXIT_BY_VERDICT["block"]
        return 0 if decision.decision == "allow" else EXIT_BY_VERDICT["review"]

    return 2


def _should_fail(verdict: str, threshold: str) -> bool:
    order = {"trusted": 0, "review": 1, "quarantine": 2, "block": 3}
    return order[verdict] >= order[threshold]


def _render_summary(report) -> str:
    severity_counts: dict[str, int] = {}
    for finding in report.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    severity_text = ", ".join(
        f"{severity}={severity_counts[severity]}"
        for severity in ("critical", "high", "medium", "low")
        if severity in severity_counts
    ) or "none"
    capabilities = ", ".join(report.capabilities) or "none"
    lines = [
        f"Verdict: {report.verdict.upper()}",
        f"Score: {report.score}/100",
        f"Policy: {report.policy}",
        f"Assurance: {report.assurance_level}",
        f"Findings: {len(report.findings)} ({severity_text})",
        f"Capabilities: {capabilities}",
        f"Scanned files: {report.scanned_files}",
    ]
    if report.findings:
        top = report.findings[0]
        location = top.path + (f":{top.line}" if top.line else "")
        lines.append(f"Top issue: {top.severity.upper()} {top.rule_id} {top.title} at {location}")
    if report.quarantine_readiness:
        lines.append(
            f"Quarantine readiness: {report.quarantine_readiness.score}/100 "
            f"({report.quarantine_readiness.status})"
        )
    runtime_text = ", ".join(
        f"{decision.capability}:{decision.decision}" for decision in report.runtime_decisions
    ) or "none"
    probe_text = ", ".join(
        f"{probe.probe_id}:{probe.status}" for probe in report.probe_results
    ) or "none"
    lines.append(f"Runtime guard: {runtime_text}")
    lines.append(f"Adversarial probes: {probe_text}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
