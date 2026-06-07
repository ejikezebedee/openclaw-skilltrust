# Contributing

Thank you for helping improve OpenClaw SkillTrust.

SkillTrust is defensive-only. Contributions should help maintainers understand,
score, quarantine, or document agent extension risk. Do not submit exploitation
workflows, credential harvesting logic, stealth behavior, persistence routines,
or unauthorized-access instructions.

## Useful Contributions

- Add safe fixtures for skills, plugins, connectors, and MCP tool manifests.
- Improve capability classification.
- Improve report clarity.
- Add parser support for more manifest formats.
- Add CI examples and policy pack samples.

## Local Checks

```bash
python3 -m pytest
python3 -m skilltrust scan ./examples/sample-safe-skill
```

## Pull Requests

Please include:

- What changed
- Why it helps maintainers
- How it was tested
- Any new risk rule or scoring impact
