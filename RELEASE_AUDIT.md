# Release Audit

## Open-Source Readiness

- [x] Defensive-only positioning
- [x] MIT license
- [x] README with community-focused value
- [x] Contribution guide
- [x] Security policy
- [x] Roadmap
- [x] Release notes
- [x] Safe examples
- [x] Standard-library runtime
- [x] No private tokens
- [x] No required machine-specific paths
- [x] Relative-path examples
- [x] Generated reports use portable paths
- [x] README has no missing local asset dependency
- [x] CLI summary output includes verdict, score, finding counts, capabilities, and top issue
- [x] Built-in policy packs cover baseline, MCP tools, skills, plugins, and repo hygiene
- [x] Scan reports include selected policy pack and assurance level
- [x] Scan reports include severity breakdown, control checks, and explainable score factors
- [x] CLI supports `--policy` for stricter review profiles
- [x] Documentation explains policy packs without requiring hosted infrastructure
- [x] Enterprise readiness note documents Stage 4 level and pre-launch gates
- [x] Runtime guard preview included in JSON and Markdown reports
- [x] CLI supports `guard` action review with allow, review, and block decisions
- [x] Adversarial probe results included in scan evidence
- [x] Compliance mappings included as review evidence, not certification claims
- [x] Quarantine readiness score reaches 98/100 for complete quarantine evidence
- [x] Quarantine readiness is documented as separate from raw trust score
- [x] GitHub-ready SVG screenshots show tests, quarantine readiness, and guard blocking
- [x] GitHub release gate documented near top of README
- [x] Local cache/build/log files ignored before publication
- [x] Repository line endings normalized for cross-platform buyers
- [x] CLI supports `evidence` bundle generation for release review artifacts
- [x] Evidence bundle includes JSON, Markdown, printable HTML, executive summary, risk register, and remediation checklist
- [x] GitHub Actions workflow runs tests and generates safe/quarantine evidence artifacts
- [x] GitHub Actions avoids provenance attestation on pull requests where token permissions may be restricted
- [x] GitHub Actions evidence artifacts have explicit retention
- [x] CLI supports CycloneDX-style BOM export
- [x] Evidence bundle includes BOM and supply-chain review artifacts
- [x] Supply-chain checks cover security policy, tests, evidence workflow, permissions, provenance readiness, and action pinning
- [x] Compliance mappings include OWASP Agentic AI and OpenSSF/SLSA readiness evidence
- [x] Repository self-scan quarantine behavior is documented as controlled fixture/signature evidence
- [x] No deployment or external publishing performed by default

## Final Gate

External publishing, repository creation, package release, and mandatory core
enforcement remain approval-gated.

## Verification

- `python3 -m pytest -q`
- `python3 -m skilltrust scan ./examples/sample-risky-skill --summary`
- `python3 -m skilltrust scan ./examples/sample-safe-skill --summary`
- `python3 -m skilltrust scan ./examples/sample-risky-skill --summary --policy skills`
- `python3 -m skilltrust guard "deploy to production" --policy baseline`
- `python3 -m skilltrust guard "run rm -rf /" --policy baseline --json`
- `python3 -m skilltrust evidence ./examples/sample-risky-skill --policy skills --output ./artifacts/quarantine-evidence`
- `python3 -m skilltrust bom ./examples/sample-risky-skill --policy skills --output ./artifacts/skilltrust-bom.json`
- `python3 -m skilltrust policies`

## Latest Local Verification

Date: 2026-06-07

- Tests: `14 passed`
- Safe fixture: `TRUSTED`, score `96/100`, quarantine readiness `100/100`
- Risky fixture under `skills` policy: `QUARANTINE`, score `23/100`,
  quarantine readiness `98/100`
- Runtime guard destructive command: `block`, matched rule `ST003`
- Evidence artifacts regenerated under `./artifacts/safe-evidence` and
  `./artifacts/quarantine-evidence`
- Repository BOM regenerated at `./artifacts/skilltrust-bom.json`
- Private-path/token audit: no root-home workspace paths, OpenClaw workspace
  paths, private keys, GitHub tokens, Slack tokens, or AWS access key patterns
  found in buyer-facing files
- Cache audit: no `.pytest_cache`, `__pycache__`, build, dist, egg-info, or
  Python bytecode files remain in the release folder
