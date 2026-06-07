# SkillTrust Remediation Checklist

Target: `examples/sample-risky-skill`

- [ ] Remove instruction-hijacking language from installable extension content.
- [ ] Document the command scope and require explicit approval for modifying commands.
- [ ] Replace private machine paths with relative paths or documented environment variables.
- [ ] Verify declared capabilities match maintainer intent before installation.

## Finding Review

- [ ] Review `ST005` at `SKILL.md` and document disposition.
- [ ] Review `ST007` at `SKILL.md` and document disposition.
- [ ] Review `ST002` at `SKILL.md` and document disposition.

## Release Gate

- [ ] Confirm generated reports use portable paths only.
- [ ] Confirm no real credentials or private infrastructure references are present.
- [ ] Confirm compliance mappings are framed as review evidence, not certification.
- [ ] Confirm external publishing has explicit approval.
