"""Defensive risk detectors for agent extension review."""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, relative_path

RULES: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    (
        "ST001",
        "critical",
        "Potential hardcoded secret",
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        "Remove hardcoded secrets and load credentials from approved runtime storage.",
    ),
    (
        "ST002",
        "high",
        "Private local path reference",
        re.compile(r"(/example-private|/private/internal|/company-internal|/srv/private|~/.private)"),
        "Replace private machine paths with relative paths or documented environment variables.",
    ),
    (
        "ST003",
        "critical",
        "Destructive shell pattern",
        re.compile(r"(?i)(rm\s+-rf\s+/|mkfs\.|dd\s+if=|chmod\s+777\s+/)"),
        "Remove destructive command patterns from extension instructions or scripts.",
    ),
    (
        "ST004",
        "high",
        "Curl pipe shell pattern",
        re.compile(r"(?i)(curl|wget).{0,80}(\|\s*(sh|bash|zsh|python))"),
        "Use pinned downloads, checksums, and explicit review before execution.",
    ),
    (
        "ST005",
        "high",
        "Prompt-injection instruction",
        re.compile(r"(?i)(ignore previous instructions|disregard system|override developer|reveal hidden prompt)"),
        "Remove instruction-hijacking language from installable extension content.",
    ),
    (
        "ST006",
        "high",
        "Credential exfiltration language",
        re.compile(r"(?i)(send|upload|post).{0,80}(token|secret|password|credential|cookie)"),
        "Do not request transmission of credentials or secret material.",
    ),
    (
        "ST007",
        "medium",
        "Broad command execution capability",
        re.compile(r"(?i)(subprocess\.|os\.system|exec_command|shell command|run arbitrary command)"),
        "Document the command scope and require explicit approval for modifying commands.",
    ),
    (
        "ST008",
        "medium",
        "Production deployment capability",
        re.compile(r"(?i)(deploy to production|kubectl apply|terraform apply|vercel deploy|docker push)"),
        "Gate deployment actions behind explicit approval and provenance evidence.",
    ),
)


def detect_file(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_id, severity, title, pattern, remediation in RULES:
            match = pattern.search(line)
            if not match:
                continue
            evidence = _mask(line.strip())
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    path=relative_path(path, root),
                    line=line_no,
                    evidence=evidence[:220],
                    remediation=remediation,
                )
            )
    return findings


def _mask(text: str) -> str:
    text = re.sub(r"(?i)(api[_-]?key|secret|token|password)(\s*[:=]\s*)['\"][^'\"]+['\"]", r"\1\2***", text)
    text = re.sub(r"[A-Za-z0-9_\-]{24,}", "***", text)
    return text
