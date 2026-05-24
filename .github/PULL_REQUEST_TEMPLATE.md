<!-- Thanks for contributing! Keep IOCs defanged everywhere. See CONTRIBUTING.md. -->

## Summary

<!-- What does this PR add or change, and why? Link any related issue: Closes #123 -->

## Type of change

- [ ] New detection rule
- [ ] Update / tuning of an existing rule (incl. false-positive fix)
- [ ] New / updated IOCs
- [ ] Tooling / CI / validators
- [ ] Documentation
- [ ] Other

## Platforms touched

- [ ] Sigma (`sigma/`)
- [ ] Microsoft Sentinel (`sentinel/`)
- [ ] Google SecOps / Chronicle (`chronicle/`)
- [ ] IOCs (`iocs/iocs.csv`)
- [ ] ATT&CK Navigator layers (`attack-navigator/`)

## Threat & MITRE

- **Family:** <!-- Banana RAT / TrickMo / TCLBANKER / other -->
- **ATT&CK techniques:** <!-- e.g. T1059.001, T1105 -->

## Checklist

- [ ] New detection authored in Sigma (`sigma/`), plus Sentinel/Chronicle where applicable
- [ ] Fresh, unique UUID for any new Sigma rule
- [ ] MITRE tactics + techniques set on Sentinel rules; `attack.*` tags on Sigma
- [ ] IOCs defanged everywhere; `iocs.csv` updated + enriched if applicable
- [ ] `validate_sigma.py` / `validate_sentinel.py` / `validate_chronicle.py` all pass locally
- [ ] References to the source advisory/report included
- [ ] (If coverage changed) `attack-navigator/*.json` updated

## Notes for reviewers

<!-- Tenant validation done? Known limitations? Follow-ups? -->
