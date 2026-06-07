"""Runtime policy decisions for proposed agent actions."""

from __future__ import annotations

import re

from .capabilities import classify_text
from .models import RuntimeDecision
from .policies import get_policy_pack


BLOCK_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("ST003", re.compile(r"(?i)(rm\s+-rf\s+/|mkfs\.|dd\s+if=|chmod\s+777\s+/)"), "destructive shell pattern"),
    ("ST004", re.compile(r"(?i)(curl|wget).{0,80}(\|\s*(sh|bash|zsh|python))"), "curl-pipe-shell pattern"),
    ("ST006", re.compile(r"(?i)(send|upload|post).{0,80}(token|secret|password|credential|cookie)"), "credential exfiltration language"),
)


REVIEW_ONLY_CAPABILITY = "review"
ALLOW = "allow"
BLOCK = "block"


def evaluate_action(action: str, policy: str = "baseline") -> RuntimeDecision:
    """Classify a proposed action as allow, review, or block."""

    policy_pack = get_policy_pack(policy)
    text = action.strip()
    capabilities = classify_text(text)
    capability = _primary_capability(capabilities)

    for rule_id, pattern, reason in BLOCK_PATTERNS:
        if pattern.search(text):
            return RuntimeDecision(
                action=text,
                decision=BLOCK,
                capability=capability,
                policy=policy_pack.name,
                reason=f"Blocked by runtime guard: {reason}.",
                matched_rule=rule_id,
            )

    if capability in policy_pack.gated_capabilities:
        return RuntimeDecision(
            action=text,
            decision=REVIEW_ONLY_CAPABILITY,
            capability=capability,
            policy=policy_pack.name,
            reason=f"Capability {capability!r} requires human approval under policy {policy_pack.name!r}.",
        )

    if capability in policy_pack.review_capabilities:
        return RuntimeDecision(
            action=text,
            decision=REVIEW_ONLY_CAPABILITY,
            capability=capability,
            policy=policy_pack.name,
            reason=f"Capability {capability!r} is review-boundary activity under policy {policy_pack.name!r}.",
        )

    return RuntimeDecision(
        action=text,
        decision=ALLOW,
        capability=capability,
        policy=policy_pack.name,
        reason="No runtime block or policy review boundary matched.",
    )


def default_runtime_decisions(capabilities: set[str], policy: str = "baseline") -> tuple[RuntimeDecision, ...]:
    """Create sample decisions that explain how detected capabilities would be gated."""

    actions = []
    for capability in sorted(capabilities):
        if capability == "shell":
            actions.append("run shell command")
        elif capability == "filesystem":
            actions.append("write file to project directory")
        elif capability == "network":
            actions.append("fetch external API data")
        elif capability == "messaging":
            actions.append("send message through external channel")
        elif capability == "payment":
            actions.append("submit payment transaction")
        elif capability == "deployment":
            actions.append("deploy to production")
        elif capability == "credentials":
            actions.append("read credential from runtime secret store")
    return tuple(evaluate_action(action, policy) for action in actions)


def _primary_capability(capabilities: set[str]) -> str:
    priority = ("payment", "deployment", "credentials", "shell", "messaging", "filesystem", "network", "browser", "memory", "scheduler")
    for capability in priority:
        if capability in capabilities:
            return capability
    return "general"
