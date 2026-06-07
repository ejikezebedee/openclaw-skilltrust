"""Candidate file discovery for agent extensions."""

from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
}

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".ps1",
}

IMPORTANT_NAMES = {
    "SKILL.md",
    "README.md",
    "plugin.json",
    "package.json",
    "pyproject.toml",
    "manifest.json",
    "mcp.json",
}


def discover_files(root: Path, *, max_files: int = 500) -> list[Path]:
    root = root.resolve()
    if root.is_file():
        return [root]

    files: list[Path] = []
    for path in root.rglob("*"):
        if len(files) >= max_files:
            break
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
            files.append(path)
    return sorted(files)
