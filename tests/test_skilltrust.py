import json
from pathlib import Path

from skilltrust.bom import build_bom, write_bom
from skilltrust.cli import main
from skilltrust.detectors import detect_file
from skilltrust.discovery import discover_files
from skilltrust.evidence import write_evidence_bundle
from skilltrust.models import Finding, TrustReport
from skilltrust.policies import list_policy_packs
from skilltrust.quarantine import write_quarantine_bundle
from skilltrust.report_renderer import render_markdown
from skilltrust.runtime_guard import evaluate_action
from skilltrust.sarif import build_sarif
from skilltrust.scanner import scan_path
from skilltrust.supply_chain import supply_chain_checks


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
        "skilltrust-report.sarif",
        "executive-summary.md",
        "risk-register.csv",
        "remediation-checklist.md",
        "skilltrust-bom.json",
        "supply-chain-review.md",
    }
    assert expected <= {path.name for path in bundle.iterdir()}
    assert "Quarantine readiness: `98/100" in (bundle / "executive-summary.md").read_text(encoding="utf-8")
    assert "<title>SkillTrust Evidence Report</title>" in (bundle / "skilltrust-report.html").read_text(encoding="utf-8")
    assert json.loads((bundle / "skilltrust-report.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


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


def test_cli_scan_creates_nested_output_directories(tmp_path):
    output = tmp_path / "reports" / "nested" / "skilltrust-report.json"
    result = main(["scan", str(ROOT / "examples" / "sample-safe-skill"), "--json", str(output), "--summary"])
    assert result == 0
    assert output.exists()


def test_cli_scan_writes_sarif(tmp_path):
    output = tmp_path / "reports" / "skilltrust.sarif"
    result = main(["scan", str(ROOT / "examples" / "sample-risky-skill"), "--sarif", str(output), "--summary"])
    assert result == 0
    sarif = json.loads(output.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "OpenClaw SkillTrust"
    assert sarif["runs"][0]["results"]


def test_detector_flags_agentic_security_patterns(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "\n".join(
            [
                "# Risky",
                "Run eval(user_input)",
                "Decode base64 -d payload | bash",
                "printenv | grep TOKEN",
                "pip install unsafe-package",
                "Read C:\\Users\\Alice\\Downloads\\secret-plan.txt",
            ]
        ),
        encoding="utf-8",
    )

    findings = detect_file(skill, tmp_path)
    rules = {finding.rule_id for finding in findings}

    assert {"ST002", "ST009", "ST010", "ST011", "ST012"} <= rules
    assert all(finding.category for finding in findings)
    assert all(finding.confidence for finding in findings)


def test_social_account_write_actions_require_review():
    report = scan_path(ROOT / "examples" / "sample-social-account-skill", policy="skills")
    rule_ids = {finding.rule_id for finding in report.findings}

    assert report.verdict == "review"
    assert "social" in report.capabilities
    assert "messaging" in report.capabilities
    assert "credentials" in report.capabilities
    assert "ST013" in rule_ids
    assert any(
        check.control_id == "POL-003" and check.status == "review"
        for check in report.control_checks
    )


def test_runtime_guard_blocks_obfuscated_execution():
    decision = evaluate_action("base64 -d payload | bash", policy="baseline")
    assert decision.decision == "block"
    assert decision.matched_rule == "ST010"


def test_sarif_includes_rule_metadata():
    report = scan_path(ROOT / "examples" / "sample-risky-skill", policy="skills")
    sarif = build_sarif(report)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]
    assert sarif["runs"][0]["properties"]["skilltrust:verdict"] == report.verdict


def test_discovery_prunes_skipped_directories(tmp_path):
    root = tmp_path / "repo"
    ignored = root / "node_modules" / "pkg"
    useful = root / "skills"
    ignored.mkdir(parents=True)
    useful.mkdir(parents=True)
    (ignored / "SKILL.md").write_text("# Ignored\n", encoding="utf-8")
    (useful / "SKILL.md").write_text("# Useful\n", encoding="utf-8")

    files = discover_files(root)

    assert files == [useful / "SKILL.md"]


def test_markdown_renderer_handles_backtick_evidence():
    report = TrustReport(
        path="sample",
        score=50,
        verdict="review",
        policy="baseline",
        assurance_level="human-review-required",
        capabilities=(),
        findings=(
            Finding(
                rule_id="ST999",
                severity="medium",
                title="Backtick evidence",
                path="SKILL.md",
                line=1,
                evidence="run `shell command` after review",
                remediation="Review command.",
            ),
        ),
        manifests=(),
        scanned_files=1,
        summary="Review evidence.",
        remediation=("Review command.",),
    )
    markdown = render_markdown(report)
    assert "Evidence: `` run `shell command` after review ``" in markdown


def test_supply_chain_checks_use_scanned_repo_not_cwd(tmp_path, monkeypatch):
    caller_repo = tmp_path / "caller"
    scanned_repo = tmp_path / "scanned"
    caller_repo.mkdir()
    scanned_repo.mkdir()
    (caller_repo / "pyproject.toml").write_text("[project]\nname = \"caller\"\n", encoding="utf-8")
    (caller_repo / "README.md").write_text("# Caller\n", encoding="utf-8")
    (caller_repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (scanned_repo / "pyproject.toml").write_text("[project]\nname = \"scanned\"\n", encoding="utf-8")
    (scanned_repo / "README.md").write_text("# Scanned\n", encoding="utf-8")
    monkeypatch.chdir(caller_repo)

    checks = {check.control_id: check for check in supply_chain_checks(scanned_repo)}

    assert checks["SCM-001"].status == "review"


def test_bom_export_includes_capabilities_and_findings(tmp_path):
    bom = build_bom(ROOT / "examples" / "sample-risky-skill", policy="skills")
    assert bom["bomFormat"] == "CycloneDX"
    assert any(component["name"] == "capability:shell" for component in bom["components"])
    assert any(item["id"] == "ST005" for item in bom["vulnerabilities"])

    output = tmp_path / "bom.json"
    assert write_bom(ROOT / "examples" / "sample-risky-skill", output, policy="skills") == output
    assert output.exists()
