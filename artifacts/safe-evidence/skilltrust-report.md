# SkillTrust Report

- Verdict: `trusted`
- Score: `96`
- Policy: `repo-hygiene`
- Assurance level: `human-review-required`
- Scanned files: `2`
- Summary: TRUSTED: score 96; no detector findings.

## Severity Breakdown

- None detected

## Control Checks

- `pass` `POL-001` Blocking rule enforcement: No policy block rules triggered.
- `pass` `POL-002` Gated capability review: No gated capabilities detected.
- `review` `POL-003` Declared review boundary: Review capabilities detected: filesystem
- `pass` `EVD-001` Evidence availability: Scanner collected findings or capability evidence.
- `review` `RUN-001` Runtime guard preview: Runtime guard will require review for detected gated or review-boundary capabilities.
- `pass` `ADV-001` Adversarial probe coverage: Adversarial probes did not detect high-risk prompt, exfiltration, install, or destructive-action evidence.
- `pass` `SCM-001` Security policy present: Repository includes SECURITY.md.
- `pass` `SCM-002` Automated tests present: Repository includes a tests directory.
- `pass` `SCM-003` Evidence workflow present: GitHub Actions evidence workflow is present.
- `pass` `SCM-004` Workflow least-privilege permissions: Workflow declares least-privilege permissions.
- `pass` `SLSA-001` Provenance attestation readiness: Workflow includes build provenance attestation readiness.
- `pass` `BOM-001` BOM export available: SkillTrust can export a CycloneDX-style tool and capability inventory.
- `pass` `SCM-005` Pinned GitHub Actions references: Workflow action references are version-pinned.

## Runtime Guard Preview

- `review` `filesystem` Capability 'filesystem' is review-boundary activity under policy 'repo-hygiene'.

## Adversarial Probes

- `pass` `PROBE-001` prompt-injection: No matching detector evidence appeared in scanned files.
- `pass` `PROBE-002` credential-exfiltration: No matching detector evidence appeared in scanned files.
- `pass` `PROBE-003` unsafe-install-flow: No matching detector evidence appeared in scanned files.
- `pass` `PROBE-004` destructive-action: No matching detector evidence appeared in scanned files.
- `review` `PROBE-005` instruction-boundary: No explicit boundary language detected; add least-privilege and human-review instructions.

## Compliance Mapping

- `review` SOC 2 - CC6.1 logical access controls: policy controls: POL-003, RUN-001
- `review` ISO/IEC 42001 - AI system impact and risk treatment: control/probe evidence: POL-003, RUN-001
- `pass` OWASP LLM / Agentic - Prompt injection, sensitive data, excessive agency, and supply-chain review: adversarial probes: no blocking evidence detected
- `pass` OWASP Agentic AI - Goal hijacking and instruction-boundary integrity: prompt-injection probes: no blocking evidence detected
- `review` OWASP Agentic AI - Tool misuse and excessive agency controls: runtime and policy gates: POL-003, RUN-001
- `review` OWASP Agentic AI - Memory, credential, and data exfiltration boundaries: exfiltration probes: no blocking evidence detected
- `review` OpenSSF / SLSA readiness - Repository security, BOM, and provenance evidence: supply-chain controls: no blocking evidence detected
- `review` EU AI Act readiness - Risk-management evidence and human oversight: human oversight gates: POL-003, RUN-001

## Quarantine Readiness

- `100/100` `not-required` Quarantine readiness not required
- No quarantine workflow required for this verdict.

## Capabilities

- `filesystem`

## Manifests

- `SKILL.md` (skill) Safe Research Skill
- `plugin.json` (plugin) safe-research-skill

## Findings

- No detector findings

## Remediation

- No blocking remediation detected; keep normal maintainer review.

## Score Factors

- capability:filesystem: -4 exposure weight
