"""Default policy packs for common agent extension reviews."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyPack:
    name: str
    description: str
    review_capabilities: tuple[str, ...]
    gated_capabilities: tuple[str, ...]
    block_rules: tuple[str, ...]


POLICY_PACKS: dict[str, PolicyPack] = {
    "baseline": PolicyPack(
        name="baseline",
        description="Default defensive review for installable agent extensions.",
        review_capabilities=("filesystem", "network", "browser", "memory", "messaging", "scheduler", "social"),
        gated_capabilities=("shell", "credentials", "deployment", "payment"),
        block_rules=("ST001", "ST003", "ST006"),
    ),
    "mcp-tools": PolicyPack(
        name="mcp-tools",
        description="Review profile for MCP tool servers and connector-style tools.",
        review_capabilities=("filesystem", "network", "browser", "memory", "messaging", "social"),
        gated_capabilities=("shell", "credentials", "deployment", "payment"),
        block_rules=("ST001", "ST003", "ST006"),
    ),
    "skills": PolicyPack(
        name="skills",
        description="Review profile for agent skills and reusable operating procedures.",
        review_capabilities=("filesystem", "network", "browser", "memory", "social"),
        gated_capabilities=("shell", "credentials", "messaging", "deployment", "payment"),
        block_rules=("ST001", "ST003", "ST005", "ST006"),
    ),
    "plugins": PolicyPack(
        name="plugins",
        description="Review profile for plugins with executable code or manifests.",
        review_capabilities=("filesystem", "network", "browser", "scheduler", "social"),
        gated_capabilities=("shell", "credentials", "deployment", "payment", "messaging"),
        block_rules=("ST001", "ST003", "ST006"),
    ),
    "repo-hygiene": PolicyPack(
        name="repo-hygiene",
        description="Strict profile for public release checks and repository hygiene.",
        review_capabilities=("filesystem", "network", "social"),
        gated_capabilities=("shell", "credentials", "deployment", "payment", "messaging", "memory"),
        block_rules=("ST001", "ST002", "ST003", "ST006"),
    ),
}


def get_policy_pack(name: str) -> PolicyPack:
    try:
        return POLICY_PACKS[name]
    except KeyError as exc:
        available = ", ".join(sorted(POLICY_PACKS))
        raise ValueError(f"unknown policy pack {name!r}; available: {available}") from exc


def list_policy_packs() -> tuple[PolicyPack, ...]:
    return tuple(POLICY_PACKS[name] for name in sorted(POLICY_PACKS))
