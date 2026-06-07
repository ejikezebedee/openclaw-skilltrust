from pathlib import Path

from skilltrust.bom import build_bom, write_bom
from skilltrust.cli import main
from skilltrust.evidence import write_evidence_bundle
from skilltrust.policies import list_policy_packs
from skilltrust.quarantine import write_quarantine_bundle
from skilltrust.runtime_guard import evaluate_action
from skilltrust.scanner import scan_path


ROOT = Path(__file__).resolve().parents[1]


def test_safe_sample_is_review_or_trusted():
    report = scan_path(ROOT / "examples" / "sample-safe-skill")
    assert report.verdict in {"trusted", "review"}
    assert "filesystem" in report.capabilities
    assert not any(f.severity == "critical" for f in report.findings)


def test_risky_sample_blocks_or_quarantines():
    report = scan_path(ROOT / "examples" / "sample-risky-skill")
    assert report.verdict in {"quarantine", "block"}
    assert any(f.rule_id == "ST002" for f in report.findings)
    assert any(f.rule_id == "ST005" for f in report.findings)


def test_cli_scan_summary_returns_zero_without_threshold():
    assert main(["scan", str(ROOT / "examples" / "sample-safe-skill"), "--summary"]) == 0


def test_quarantine_bundle_writes_reports(tmp_path):
    bundle = write_quarantine_bundle(ROOT / "examples" / "sample-risky-skill", tmp_path / "bundle")
    assert (bundle / "skilltrust-report.json").exists()
    assert (bundle / "skilltrust-report.md").exists()


def test_report_path_is_portable():
    report = scan_path(ROOT / "examples" / "sample-safe-skill")
    assert report.path == "examples/sample-safe-skill"


def test_policy_packs_include_release_profiles():
    names = {pack.name for pack in list_policy_packs()}
    assert {"baseline", "mcp-tools", "skills", "plugins", "repo-hygiene"} <= names


def test_scan_report_includes_enterprise_evidence():
    report = scan_path(ROOT / "examples" / "sample-risky-skill", policy="skills")
    assert report.policy == "skills"
    assert report.assurance_level in {"blocked", "quarantine-required", "human-review-required"}
    assert report.severity_counts
    assert report.score_factors
    assert {check.control_id for check in report.control_checks} >= {"POL-001", "POL-002", "EVD-001", "RUN-001", "ADV-001"}


def test_cli_accepts_policy_pack_for_summary():
    assert main(["scan", str(ROOT / "examples" / "sample-safe-skill"), "--summary", "--policy", "repo-hygiene"]) == 0


def test_stage_four_evidence_is_included():
    report = scan_path(ROOT / "examples" / "sample-risky-skill", policy="skills")
    assert report.runtime_decisions
    assert report.probe_results
    assert report.compliance_mappings
    assert any(probe.status == "fail" for probe in report.probe_results)
    assert report.quarantine_readiness
    assert report.quarantine_readiness.score == 98
    assert report.quarantine_readiness.status == "remediation-ready"
    assert {check.control_id for check in report.control_checks} >= {"SCM-001", "SLSA-001", "BOM-001"}
    assert any(mapping.framework == "OWASP Agentic AI" for mapping in report.compliance_mappings)


def test_runtime_guard_blocks_destructive_action():
    decision = evaluate_action("run rm -rf /", policy="baseline")
    assert decision.decision == "block"
    assert decision.matched_rule == "ST003"


def test_cli_guard_returns_review_for_gated_action():
    assert main(["guard", "deploy to production", "--policy", "baseline"]) == 10


def test_evidence_bundle_writes_executive_artifacts(tmp_path):
    bundle = write_evidence_bundle(
        ROOT / "examples" / "sample-risky-skill",
        tmp_path / "evidence",
        policy="skills",
    )
    expected = {
        "skilltrust-report.json",
        "skilltrust-report.md",
        "skilltrust-report.html",
        "executive-summary.md",
        "risk-register.csv",
        "remediation-checklist.md",
        "skilltrust-bom.json",
        "supply-chain-review.md",
    }
    assert expected <= {path.name for path in bundle.iterdir()}
    assert "Quarantine readiness: `98/100" in (bundle / "executive-summary.md").read_text(encoding="utf-8")
    assert "<title>SkillTrust Evidence Report</title>" in (bundle / "skilltrust-report.html").read_text(encoding="utf-8")


def test_cli_evidence_command_returns_zero(tmp_path):
    output = tmp_path / "cli-evidence"
    result = main(
        [
            "evidence",
            str(ROOT / "examples" / "sample-safe-skill"),
            "--output",
            str(output),
            "--policy",
            "repo-hygiene",
        ]
    )
    assert result == 0
    assert (output / "risk-register.csv").exists()


def test_bom_export_includes_capabilities_and_findings(tmp_path):
    bom = build_bom(ROOT / "examples" / "sample-risky-skill", policy="skills")
    assert bom["bomFormat"] == "CycloneDX"
    assert any(component["name"] == "capability:shell" for component in bom["components"])
    assert any(item["id"] == "ST005" for item in bom["vulnerabilities"])

    output = tmp_path / "bom.json"
    assert write_bom(ROOT / "examples" / "sample-risky-skill", output, policy="skills") == output
    assert output.exists()
