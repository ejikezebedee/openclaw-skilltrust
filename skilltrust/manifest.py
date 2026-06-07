"""Manifest parsing for agent extension packages."""

from __future__ import annotations

import json
from pathlib import Path

from .capabilities import classify_text, normalize_capabilities
from .models import Manifest, relative_path


def parse_manifest(path: Path, root: Path) -> Manifest | None:
    name = path.name
    if name == "SKILL.md":
        text = _read_text(path)
        title = _first_heading(text)
        return Manifest(
            path=relative_path(path, root),
            kind="skill",
            name=title,
            description=_first_paragraph(text),
            declared_capabilities=tuple(sorted(classify_text(text))),
        )
    if name.endswith(".json") and name in {"plugin.json", "package.json", "manifest.json", "mcp.json"}:
        return _parse_json_manifest(path, root)
    if name == "pyproject.toml":
        text = _read_text(path)
        return Manifest(
            path=relative_path(path, root),
            kind="python-project",
            name=_toml_value(text, "name"),
            description=_toml_value(text, "description"),
            declared_capabilities=tuple(sorted(classify_text(text))),
        )
    return None


def _parse_json_manifest(path: Path, root: Path) -> Manifest | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    capability_values = []
    for key in ("capabilities", "permissions", "tools", "mcp", "connectors", "commands"):
        capability_values.append(data.get(key))

    return Manifest(
        path=relative_path(path, root),
        kind=path.name.removesuffix(".json"),
        name=str(data.get("name") or data.get("id") or ""),
        description=str(data.get("description") or ""),
        declared_capabilities=tuple(sorted(set().union(*(normalize_capabilities(v) for v in capability_values)))),
        raw_keys=tuple(sorted(str(key) for key in data.keys())),
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return ""


def _first_paragraph(text: str) -> str:
    for block in text.split("\n\n"):
        stripped = " ".join(line.strip() for line in block.splitlines()).strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:240]
    return ""


def _toml_value(text: str, key: str) -> str:
    prefix = key + " = "
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix):].strip().strip('"')[:240]
    return ""
