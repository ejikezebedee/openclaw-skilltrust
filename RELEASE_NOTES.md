# Release Notes

## 0.1.0

Initial pre-release.

- Added local SkillTrust scan engine.
- Added capability classification for agent extensions.
- Added trust score and verdict model.
- Added Markdown and JSON reporting.
- Added quarantine evidence bundle.
- Added safe examples and tests.
- Added built-in policy packs for baseline, MCP tools, skills, plugins, and
  repo hygiene.
- Added enterprise report evidence: selected policy, assurance level, severity
  breakdown, control checks, and explainable score factors.
- Added `--policy` scan option for stricter context-specific review.
- Added Stage 4 runtime guard previews for pre-execution action decisions.
- Added `guard` CLI command for direct allow, review, or block checks.
- Added controlled adversarial probes for prompt injection, exfiltration,
  unsafe-install flows, destructive actions, and instruction boundaries.
- Added compliance evidence mappings for SOC 2, ISO/IEC 42001, OWASP
  LLM/Agentic, and EU AI Act readiness reviews.
- Added quarantine readiness scoring with a 98/100 evidence path for complete
  remediation, governance, supply-chain, provenance, and BOM evidence while
  quarantine remains active.
- Added GitHub-ready SVG screenshots for test results, quarantine readiness,
  and runtime guard blocking.
- Added Stage 5A evidence bundle generation with JSON, Markdown, printable
  HTML, executive summary, risk register, and remediation checklist outputs.
- Added GitHub Actions workflow for automated tests and generated evidence
  artifacts.
- Added Stage 5B supply-chain hardening with OpenSSF-style repository checks,
  SLSA/provenance readiness, and pinned workflow review.
- Added CycloneDX-style BOM export through the `bom` command and evidence
  bundles.
- Added expanded OWASP Agentic AI mappings for goal hijacking, tool misuse,
  excessive agency, memory/credential boundaries, and supply-chain readiness.
