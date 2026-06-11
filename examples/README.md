# Examples

`sample-safe-skill` is a low-risk mock extension.

`sample-risky-skill` is intentionally unsafe and exists only to prove defensive
detectors work. Do not install it as a real skill.

`sample-social-account-skill` models an X/Twitter automation skill with
TweetClaw-style read workflows and approval-gated social account write actions.

Generate enterprise-style evidence from the risky fixture:

```bash
python3 -m skilltrust scan ./examples/sample-risky-skill --summary --policy skills
python3 -m skilltrust scan ./examples/sample-risky-skill --markdown ./examples/risky-report.md --json ./examples/risky-report.json --policy skills
```

Generate baseline evidence from the safe fixture:

```bash
python3 -m skilltrust scan ./examples/sample-safe-skill --summary
python3 -m skilltrust scan ./examples/sample-safe-skill --markdown ./examples/safe-report.md --json ./examples/safe-report.json
```

Review a social account automation boundary:

```bash
python3 -m skilltrust scan ./examples/sample-social-account-skill --summary --policy skills
```
