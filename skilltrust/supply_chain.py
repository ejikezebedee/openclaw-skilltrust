"""Supply-chain evidence checks for repository release review."""

from __future__ import annotations

import re
from pathlib import Path

from .models import ControlCheck


def supply_chain_checks(scan_root: Path) -> tuple[ControlCheck, ...]:
    release_root = _release_root(scan_root)
    workflow = release_root / ".github" / "workflows" / "skilltrust-evidence.yml"
    workflow_text = _read_text(workflow)
    actions = _actions_refs(workflow_text)
    unpinned = [action for action in actions if "@" not in action or action.endswith("@main")]

    checks = [
        ControlCheck(
            "SCM-001",
            "pass" if (release_root / "SECURITY.md").exists() else "review",
            "Security policy present",
            "Repository includes SECURITY.md." if (release_root / "SECURITY.md").exists() else "Add SECURITY.md before release.",
        ),
        ControlCheck(
            "SCM-002",
            "pass" if (release_root / "tests").exists() else "review",
            "Automated tests present",
            "Repository includes a tests directory." if (release_root / "tests").exists() else "Add automated tests.",
        ),
        ControlCheck(
            "SCM-003",
            "pass" if workflow.exists() else "review",
            "Evidence workflow present",
            "GitHub Actions evidence workflow is present."
            if workflow.exists()
            else "Add a GitHub Actions workflow that runs tests and uploads evidence artifacts.",
        ),
        ControlCheck(
            "SCM-004",
            "pass" if workflow_text and "permissions:" in workflow_text and "contents: read" in workflow_text else "review",
            "Workflow least-privilege permissions",
            "Workflow declares least-privilege permissions."
            if workflow_text and "permissions:" in workflow_text and "contents: read" in workflow_text
            else "Declare explicit least-privilege workflow permissions.",
        ),
        ControlCheck(
            "SLSA-001",
            "pass" if "actions/attest-build-provenance" in workflow_text else "review",
            "Provenance attestation readiness",
            "Workflow includes build provenance attestation readiness."
            if "actions/attest-build-provenance" in workflow_text
            else "Add artifact provenance attestation for generated evidence.",
        ),
        ControlCheck(
            "BOM-001",
            "pass",
            "BOM export available",
            "SkillTrust can export a CycloneDX-style tool and capability inventory.",
        ),
        ControlCheck(
            "SCM-005",
            "pass" if actions and not unpinned else "review",
            "Pinned GitHub Actions references",
            "Workflow action references are version-pinned."
            if actions and not unpinned
            else "Pin GitHub Actions references to stable versions before release.",
        ),
    ]
    return tuple(checks)


def _release_root(scan_root: Path) -> Path:
    root = scan_root.resolve()
    candidates = [root] + list(root.parents)
    for candidate in candidates:
        if (candidate / "pyproject.toml").exists() and (candidate / "README.md").exists():
            return candidate
    return root


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _actions_refs(workflow_text: str) -> list[str]:
    return re.findall(r"uses:\s*([^\s]+)", workflow_text)
