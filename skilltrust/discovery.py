"""Candidate file discovery for agent extensions."""

from __future__ import annotations

import os
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
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIP_DIRS]
        for filename in filenames:
            if len(files) >= max_files:
                return sorted(files)
            path = Path(dirpath) / filename
            if path.name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)
