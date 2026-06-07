# SkillTrust Executive Summary

- Target: `examples/sample-risky-skill`
- Verdict: `quarantine`
- Trust score: `23/100`
- Policy: `skills`
- Assurance level: `blocked`
- Quarantine readiness: `98/100 (remediation-ready)`
- Scanned files: `2`

## Decision

Keep isolated until remediation is reviewed and risk findings are resolved.

## Top Risks

- `high` `ST005` Prompt-injection instruction at `SKILL.md`
- `medium` `ST007` Broad command execution capability at `SKILL.md`
- `high` `ST002` Private local path reference at `SKILL.md`

## Evidence Files

- `skilltrust-report.json`
- `skilltrust-report.md`
- `skilltrust-report.html`
- `risk-register.csv`
- `remediation-checklist.md`
- `skilltrust-bom.json`
- `supply-chain-review.md`
