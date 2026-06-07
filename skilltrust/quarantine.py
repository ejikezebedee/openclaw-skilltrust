"""Local quarantine bundle writer."""

from __future__ import annotations

import json
from pathlib import Path

from .report_renderer import render_markdown
from .scanner import scan_path


def write_quarantine_bundle(path: str | Path, output: str | Path) -> Path:
    report = scan_path(path)
    output_path = Path(output).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "skilltrust-report.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_path / "skilltrust-report.md").write_text(render_markdown(report), encoding="utf-8")
    (output_path / "README.md").write_text(
        "# SkillTrust Quarantine Bundle\n\n"
        "This bundle contains review evidence only. Source files were not deleted "
        "or modified by SkillTrust.\n",
        encoding="utf-8",
    )
    return output_path
