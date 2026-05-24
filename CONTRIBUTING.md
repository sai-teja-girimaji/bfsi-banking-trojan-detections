# Contributing

Thanks for helping improve BFSI banking-trojan detection coverage. This repo is
**detection-as-code**: every rule is reviewed, validated in CI, and mapped to MITRE
ATT&CK. These guidelines keep submissions consistent and mergeable.

By contributing, you agree your work is licensed under the repo's [MIT License](LICENSE).

---

## Ways to contribute

- **New detections** for the in-scope families (Banana RAT / SHADOW-WATER-063, TrickMo /
  Coper, TCLBANKER) — new behaviors, or additional platform variants (Splunk, Elastic, etc.).
- **New IOCs** for these families (with enrichment — see below).
- **False-positive reports** — include the telemetry/log source, the rule name, and a
  sanitized sample of what fired.
- **Coverage improvements** — closing a 🟥 gap shown in the ATT&CK Navigator layers.
- **Docs / tooling** — validator improvements, new backend conversions, fixes.

Open an **issue** to propose anything non-trivial before a large PR.

---

## Before you start

1. **Fork** and create a topic branch: `feat/<short-name>` or `fix/<short-name>`.
2. Keep PRs focused — one logical change set per PR.
3. Run the validators locally (see [Local validation](#local-validation)) — PRs must pass CI.
4. **Defang all indicators** in code, issues, and PRs: `evil[.]com`, `10[.]0[.]0[.]1`,
   `hxxp://`. Hashes may be bare. Never commit live malware samples.

---

## Where things go

| Path | Contents | Naming |
|------|----------|--------|
| `sigma/` | Vendor-neutral source rules (canonical logic) | `snake_case.yml` |
| `sentinel/` | Microsoft Sentinel ARM analytics-rule templates | `NN-kebab-case.json` |
| `chronicle/` | Google SecOps YARA-L 2.0 rules | `NN_snake_case.yaral` |
| `chronicle/reference_lists/` | Reference-list contents (one value per line) | `<list_name>.txt` |
| `iocs/iocs.csv` | Defanged indicators + GTI verdicts | (append rows) |
| `attack-navigator/` | ATT&CK Navigator coverage layers | `*-coverage.json` |

**Author Sigma first** (it's the source of truth), then add the Sentinel and/or Chronicle
equivalents. A PR that adds a detection should ideally include all three, but a Sigma-only
PR is acceptable if you note which platforms are still needed.

---

## Rule requirements

### Sigma (`sigma/*.yml`)
Required by CI (`scripts/validate_sigma.py`):
- Valid YAML with `title`, `id`, `logsource`, `detection`.
- `id` is a **unique, valid UUID** (generate a fresh one — never copy an existing id).
- `logsource` has at least one of `category` / `product` / `service`.
- `detection` has a `condition`, and every identifier referenced in the condition
  exists as a selection block.
- `level` is one of `informational | low | medium | high | critical`.
- `tags` use the `attack.tXXXX[.XXX]` / `attack.<tactic>` convention.

Expected (review, not all CI-enforced): `status`, `description`, `references` (the source
advisory/report), `author`, `date` (`YYYY-MM-DD`), and realistic `falsepositives`.

### Microsoft Sentinel (`sentinel/*.json`)
Required by CI (`scripts/validate_sentinel.py`):
- Valid JSON ARM template: `$schema` (deploymentTemplate), `contentVersion`, non-empty
  `resources` with an `alertRules` resource that has a `kind`.
- `properties` include: `displayName`, `description`, `severity`
  (`Informational | Low | Medium | High`), a non-trivial `query`, `queryFrequency`,
  `queryPeriod`, `triggerOperator`, `triggerThreshold`.
- **`entityMappings`** non-empty (map Host/Account/IP/URL/DNS/File/FileHash/Process).
- **`tactics`** non-empty and **`techniques`** in `TXXXX[.XXX]` format.

Use parent technique IDs in `techniques` for API compatibility; note sub-techniques in
the description. Add `alertDetailsOverride` and `customDetails` where useful.

### Google SecOps / Chronicle (`chronicle/*.yaral`)
Required by CI (`scripts/validate_chronicle.py`):
- A `rule <name> { ... }` declaration with **balanced braces**.
- `meta:`, `events:`, and `condition:` sections present.
- `meta` should carry `author`, `description`, `reference`, `severity`, and ATT&CK keys.
- Any `%reference_list` you use must have a matching non-empty file in
  `chronicle/reference_lists/<name>.txt`.

> CI runs **offline structural** validation only. Full validation requires
> `az deployment group validate` (Sentinel) and the SecOps `rules.verifyRuleText` API
> (Chronicle), both needing live tenant auth — please validate against your own tenant
> when you can and mention it in the PR.

---

## IOC contributions

- Add indicators to `iocs/iocs.csv` (defanged) with all columns:
  `indicator,type,threat,actor,role,gti_verdict,gti_detections,registration,infrastructure,notes`.
- **Enrich before submitting**: include a Google Threat Intelligence / VirusTotal verdict
  (engine count) and basic infra (ASN/registrar, NRD date).
- If an indicator is sourced from a report but you did **not** independently verify it,
  set `gti_verdict` to `advisory-sourced` and note `not re-verified`. Don't overstate.
- Prefer indicators with detection value (C2, staging, loaders) over shared/CDN infra.

---

## Local validation

CI mirrors these exactly — run them before pushing:

```bash
# Sigma (needs PyYAML; sigma-cli optional for the advisory check)
pip install pyyaml
python scripts/validate_sigma.py sigma/

# Sentinel + Chronicle (stdlib only)
python scripts/validate_sentinel.py sentinel/
python scripts/validate_chronicle.py chronicle/
```

All three must exit `0`. The **Validate Detections** workflow runs the same checks on
every push and pull request.

---

## Commit & PR conventions

- Commit messages: imperative subject (≤ ~72 chars), e.g.
  `Add Sigma rule for <family> <behavior>`; explain *why* in the body.
- Keep the branch up to date with `main`; squash noisy WIP commits if you can.
- Open a PR with a clear description and a filled-out checklist:

```
## PR checklist
- [ ] New detection authored in Sigma (sigma/), plus Sentinel/Chronicle where applicable
- [ ] Fresh, unique UUID for any new Sigma rule
- [ ] MITRE tactics + techniques set on Sentinel rules; tags on Sigma
- [ ] IOCs defanged everywhere; iocs.csv updated + enriched if applicable
- [ ] `validate_sigma.py` / `validate_sentinel.py` / `validate_chronicle.py` all pass locally
- [ ] References to the source advisory/report included
- [ ] (If coverage changed) attack-navigator/*.json updated
```

---

## Scope & conduct

- This repo is for **defensive** detection content. Do not submit offensive tooling,
  working exploit code, or live malware.
- Be respectful and constructive in reviews and issues.

Questions? Open an issue with the `question` label.
