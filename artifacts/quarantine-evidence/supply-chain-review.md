# SkillTrust Supply-Chain Review

Target: `examples/sample-risky-skill`

- `pass` `SCM-001` Security policy present: Repository includes SECURITY.md.
- `pass` `SCM-002` Automated tests present: Repository includes a tests directory.
- `pass` `SCM-003` Evidence workflow present: GitHub Actions evidence workflow is present.
- `pass` `SCM-004` Workflow least-privilege permissions: Workflow declares least-privilege permissions.
- `pass` `SLSA-001` Provenance attestation readiness: Workflow includes build provenance attestation readiness.
- `pass` `BOM-001` BOM export available: SkillTrust can export a CycloneDX-style tool and capability inventory.
- `pass` `SCM-005` Pinned GitHub Actions references: Workflow action references are version-pinned.

## Release Notes

- Treat BOM and provenance outputs as review evidence, not certification.
- Keep generated artifacts attached to CI runs for buyer and maintainer inspection.
