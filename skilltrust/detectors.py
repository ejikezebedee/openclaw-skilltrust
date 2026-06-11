"""Defensive risk detectors for agent extension review."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path

from .models import Finding, relative_path


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    remediation: str
    category: str
    confidence: str = "high"


RULES: tuple[Rule, ...] = (
    Rule(
        "ST001",
        "critical",
        "Potential hardcoded secret",
        re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        "Remove hardcoded secrets and load credentials from approved runtime storage.",
        "secrets",
    ),
    Rule(
        "ST002",
        "high",
        "Private local path reference",
        re.compile(r"(?i)(/example-private|/private/internal|/company-internal|/srv/private|~/.private|[A-Z]:\\Users\\[^\\\s]+\\(?:Desktop|Downloads|Documents)\\[^\\\s]+)"),
        "Replace private machine paths with relative paths or documented environment variables.",
        "privacy",
    ),
    Rule(
        "ST003",
        "critical",
        "Destructive shell pattern",
        re.compile(r"(?i)(rm\s+-rf\s+/|mkfs\.|dd\s+if=|chmod\s+777\s+/|Remove-Item\s+.+-Recurse\s+.+-Force)"),
        "Remove destructive command patterns from extension instructions or scripts.",
        "destructive-action",
    ),
    Rule(
        "ST004",
        "high",
        "Curl pipe shell pattern",
        re.compile(r"(?i)(curl|wget|irm|iwr|Invoke-WebRequest).{0,100}(\|\s*(sh|bash|zsh|python|iex|Invoke-Expression))"),
        "Use pinned downloads, checksums, and explicit review before execution.",
        "supply-chain",
    ),
    Rule(
        "ST005",
        "high",
        "Prompt-injection instruction",
        re.compile(r"(?i)(ignore previous instructions|disregard system|override developer|reveal hidden prompt|bypass safety|disable guardrails)"),
        "Remove instruction-hijacking language from installable extension content.",
        "prompt-injection",
    ),
    Rule(
        "ST006",
        "high",
        "Credential exfiltration language",
        re.compile(r"(?i)(send|upload|post|exfiltrate|copy).{0,100}(token|secret|password|credential|cookie|\.env)"),
        "Do not request transmission of credentials or secret material.",
        "exfiltration",
    ),
    Rule(
        "ST007",
        "medium",
        "Broad command execution capability",
        re.compile(r"(?i)(subprocess\.|os\.system|exec_command|shell command|run arbitrary command|child_process\.exec)"),
        "Document the command scope and require explicit approval for modifying commands.",
        "command-execution",
        "medium",
    ),
    Rule(
        "ST008",
        "medium",
        "Production deployment capability",
        re.compile(r"(?i)(deploy to production|kubectl apply|terraform apply|vercel deploy|docker push)"),
        "Gate deployment actions behind explicit approval and provenance evidence.",
        "deployment",
        "medium",
    ),
    Rule(
        "ST009",
        "high",
        "Unsafe dynamic code execution",
        re.compile(r"(?i)\b(eval|exec|Invoke-Expression|new Function)\s*\("),
        "Replace dynamic code execution with explicit, reviewed operations.",
        "command-execution",
    ),
    Rule(
        "ST010",
        "high",
        "Obfuscated execution chain",
        re.compile(r"(?i)(base64\s+-d|frombase64string|atob\(|b64decode).{0,120}(eval|exec|iex|Invoke-Expression|bash|sh|powershell)"),
        "Remove obfuscated execution chains and require readable, reviewable source.",
        "obfuscation",
    ),
    Rule(
        "ST011",
        "high",
        "Environment secret enumeration",
        re.compile(r"(?i)(printenv|env\s*\||Get-ChildItem\s+Env:|process\.env|os\.environ).{0,120}(token|secret|password|credential|key|cookie|\*)"),
        "Avoid enumerating runtime secrets; request only specific approved variables.",
        "secrets",
    ),
    Rule(
        "ST012",
        "medium",
        "Unpinned package installation",
        re.compile(r"(?i)(pip install|npm install|pnpm add|yarn add|cargo install|go install)\s+[A-Za-z0-9@._/\-]+(\s|$)(?!.*(==|@v?\d|--require-hashes|--frozen-lockfile|--locked))"),
        "Pin package versions or enforce lockfile/hash verification before installation.",
        "supply-chain",
        "medium",
    ),
    Rule(
        "ST013",
        "medium",
        "Social account write action",
        re.compile(
            r"(?i)\b(post|publish|send|reply|upload|delete|follow|unfollow|like|retweet)\b.{0,80}\b"
            r"(tweet|reply|direct message|dm|media|follower|x/twitter|twitter|social account)\b"
        ),
        "Document account scope, approval requirements, rate limits, and rollback steps for social-account write actions.",
        "social-account",
        "medium",
    ),
)


def detect_file(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            match = rule.pattern.search(line)
            if not match:
                continue
            evidence = _mask(line.strip())
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    path=relative_path(path, root),
                    line=line_no,
                    evidence=evidence[:220],
                    remediation=rule.remediation,
                    category=rule.category,
                    confidence=rule.confidence,
                )
            )
    return findings


def _mask(text: str) -> str:
    text = re.sub(r"(?i)(api[_-]?key|secret|token|password)(\s*[:=]\s*)['\"][^'\"]+['\"]", r"\1\2***", text)
    text = re.sub(r"[A-Za-z0-9_\-]{24,}", "***", text)
    return text
