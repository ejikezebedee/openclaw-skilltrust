"""Capability classification for skills, plugins, and tool manifests."""

from __future__ import annotations

CAPABILITY_HINTS: dict[str, tuple[str, ...]] = {
    "shell": ("shell", "bash", "exec", "subprocess", "command", "terminal"),
    "filesystem": ("file", "filesystem", "read_file", "write_file", "path", "directory"),
    "network": ("http", "https", "request", "fetch", "webhook", "socket", "api"),
    "browser": ("browser", "playwright", "selenium", "chrome"),
    "memory": ("memory", "remember", "persistent", "recall"),
    "messaging": ("telegram", "slack", "discord", "email", "message", "send"),
    "social": (
        "social",
        "social account",
        "social media",
        "x/twitter",
        "twitter",
        "tweet",
        "follower",
        "direct message",
    ),
    "scheduler": ("cron", "schedule", "timer", "heartbeat"),
    "payment": ("payment", "stripe", "binance", "wallet", "crypto", "invoice"),
    "deployment": ("deploy", "vercel", "docker", "kubernetes", "ssh", "production"),
    "credentials": ("token", "secret", "credential", "api_key", "password", "oauth"),
}


def classify_text(text: str) -> set[str]:
    lowered = text.lower()
    capabilities: set[str] = set()
    for capability, hints in CAPABILITY_HINTS.items():
        if any(hint in lowered for hint in hints):
            capabilities.add(capability)
    return capabilities


def normalize_capabilities(values: object) -> set[str]:
    if values is None:
        return set()
    if isinstance(values, str):
        return classify_text(values)
    if isinstance(values, dict):
        text = " ".join(str(key) + " " + str(value) for key, value in values.items())
        return classify_text(text)
    if isinstance(values, (list, tuple, set)):
        return classify_text(" ".join(str(value) for value in values))
    return classify_text(str(values))
