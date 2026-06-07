# Enterprise Readiness

SkillTrust is not being launched at this stage. This file defines the internal
enterprise-readiness target before any public release decision.

## Current Level

Stage 5B: supply-chain and agentic-security release hardening.

This means the product has moved beyond MVP and commercial beta basics. It now
produces governance evidence that a maintainer, platform owner, or security
reviewer can inspect before allowing an AI-agent extension into a toolchain.
Stage 4 adds pre-execution policy decisions, adversarial probe evidence, and
framework-oriented compliance mappings. The quarantine workflow now also
separates raw trust risk from remediation readiness, allowing a quarantined
package to reach `98/100` readiness when the evidence bundle is complete.
Stage 5A adds printable HTML reports, executive summaries, risk registers,
remediation checklists, and GitHub Actions artifact generation for visible
proof in repository review workflows.
Stage 5B adds OpenSSF-style repository checks, SLSA/provenance readiness,
CycloneDX-style BOM export, and expanded OWASP Agentic AI control mapping.

## Enterprise Evidence Model

Each scan report should answer:

- Which policy pack was applied?
- Which assurance level was assigned?
- Which capabilities were detected?
- Which rules triggered findings?
- Which controls passed, failed, or require review?
- Which runtime actions would be allowed, reviewed, or blocked?
- Which adversarial probes passed, failed, or need review?
- Which governance framework mappings are supported by the evidence?
- Is the quarantine evidence complete enough to guide remediation?
- Which score factors reduced the trust score?
- Which remediation steps are required before approval?
- Which executive evidence files were generated for review?
- Which supply-chain, provenance, and BOM evidence is present?

## Review Controls

SkillTrust reports include these default controls:

- `POL-001`: blocking rule enforcement.
- `POL-002`: gated capability review.
- `POL-003`: declared review boundary.
- `EVD-001`: evidence availability.
- `RUN-001`: runtime guard preview.
- `ADV-001`: adversarial probe coverage.
- `SCM-001`: security policy present.
- `SCM-002`: automated tests present.
- `SCM-003`: evidence workflow present.
- `SCM-004`: workflow least-privilege permissions.
- `SCM-005`: pinned GitHub Actions references.
- `SLSA-001`: provenance attestation readiness.
- `BOM-001`: BOM export available.

## Stage 5A Evidence Artifacts

The `evidence` command writes:

- `skilltrust-report.json`
- `skilltrust-report.md`
- `skilltrust-report.html`
- `executive-summary.md`
- `risk-register.csv`
- `remediation-checklist.md`
- `skilltrust-bom.json`
- `supply-chain-review.md`

The HTML report is intentionally dependency-free and printable to PDF from a
browser, keeping the package portable for buyers and maintainers.

## Quarantine Readiness Target

Quarantine readiness can reach `98/100` while the package remains quarantined
when detector, remediation, policy, runtime, adversarial, governance,
supply-chain, provenance, and BOM evidence are present. The remaining gap
prevents false trust inflation while still showing that the review workflow has
collected enough evidence for a maintainer, security reviewer, or buyer-side
team to remediate the package.

These controls are intentionally simple and reviewable. They are suitable for
internal governance, CI checks, and buyer demonstrations without depending on a
hosted service.

## Controlled Self-Scan Note

Scanning the SkillTrust repository itself may produce a quarantine result
because the repository contains defensive detector signatures and intentionally
risky sample fixtures. That is expected test evidence, not an indication that
the packaged tool performs unsafe activity.

Release review should separately inspect:

- source code behavior
- generated package contents
- sample fixture labels
- documentation wording
- absence of real private paths, real credentials, and deployment automation

## Pre-Launch Gates

No launch should proceed until all of the following are true:

- final package includes only buyer-relevant files
- examples are clearly marked as safe or intentionally risky
- generated reports use portable paths
- evidence bundle includes JSON, Markdown, HTML, risk register, and checklist
- evidence bundle includes BOM and supply-chain review artifacts
- GitHub Actions evidence workflow passes and uploads review artifacts
- GitHub Actions workflow uses explicit permissions and provenance attestation
- no real credentials or internal infrastructure references are present
- test suite passes on a clean checkout
- README explains policy packs and assurance levels clearly
- runtime guard and adversarial probe examples are included in generated reports
- quarantine readiness score is visible and clearly separated from trust score
- compliance mappings are framed as review evidence, not certification claims
- sales page copy avoids security overclaims
- external publishing is explicitly approved
