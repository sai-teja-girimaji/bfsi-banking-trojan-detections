# bfsi-banking-trojan-detections

> Detection-as-code for three active banking-trojan threats targeting the **BFSI**
> (Banking, Financial Services & Insurance) sector — shipped as Sigma source plus
> compiled **Microsoft Sentinel** and **Google SecOps (Chronicle)** rules.

[![Validate Detections](https://github.com/sai-teja-girimaji/bfsi-banking-trojan-detections/actions/workflows/validate-sigma.yml/badge.svg)](https://github.com/sai-teja-girimaji/bfsi-banking-trojan-detections/actions/workflows/validate-sigma.yml)
![Rules](https://img.shields.io/badge/detection_rules-6-blue)
![Platforms](https://img.shields.io/badge/platforms-Sigma%20%7C%20Sentinel%20%7C%20Chronicle-success)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)
![Threats](https://img.shields.io/badge/threats-3-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Overview

This repository operationalizes threat intelligence on three banking trojans into
deployable detections. Each threat was triaged from a threat-advisory feed, its
indicators were enriched against **Google Threat Intelligence (GTI / VirusTotal)**,
and the resulting detection logic is published in three forms:

- **Sigma** — vendor-neutral source rules (the canonical detection logic).
- **Microsoft Sentinel** — ARM analytics-rule templates (KQL) with entity mappings,
  MITRE metadata, dynamic alert titles, and incident grouping.
- **Google SecOps / Chronicle** — YARA-L 2.0 rules over UDM, plus a reference list.

Everything here is **defensive** content: it identifies attacker activity for SOC
detection and threat hunting. IOCs are defanged.

---

## Threats covered

| # | Threat | Actor / Operator | Platform | Primary geography | Severity |
|---|--------|------------------|----------|-------------------|----------|
| 1 | **Banana RAT** | SHADOW-WATER-063 (financially motivated) | Windows | Brazil (banks + crypto) | High |
| 2 | **TrickMo (Coper lineage)** | Unattributed crew | Android | France, Italy, Austria | High |
| 3 | **TCLBANKER** | Unattributed (BR operators) | Windows (.NET) | Brazil (59 financial domains) | High |

### 1. Banana RAT — *SHADOW-WATER-063*
A financially motivated actor running the Banana RAT banking trojan against Brazilian
financial institutions and cryptocurrency platforms. Delivery via phishing lures and
malicious batch files, followed by **PowerShell fileless execution** that pulls staging
payloads (`st.txt`, `payload.php`) from actor C2. Capabilities: banking overlays, QR-code
interception, keylogging, clipboard theft, and remote access.

### 2. TrickMo (Coper lineage)
An Android banking trojan variant targeting banking, fintech, wallet, and authenticator
app users. Notable for a redesigned architecture using **TON-based C2**, runtime-loaded
modules, SSH tunneling, and SOCKS5 proxying — turning infected handsets into network
pivots. Distributed as sideloaded APKs masquerading as popular apps (e.g. `TikTok18.apk`).

### 3. TCLBANKER
An advanced **.NET banking trojan** that uses environment-gated execution to evade
sandboxes and targets 59 Brazilian financial domains. Uses a WPF overlay framework for
real-time social engineering, **DLL side-loading** via a binary forged to look like a
Logitech plugin (`screen_retriever_plugin.dll`), and self-propagates by hijacking
WhatsApp and Outlook sessions.

---

## Repository structure

```
bfsi-banking-trojan-detections/
├── README.md
├── sigma/                          # vendor-neutral source rules
│   ├── banana_rat_powershell_c2.yml
│   ├── trickmo_apk_sideload.yml
│   ├── tclbanker_dll_sideload.yml
│   ├── fin_c2_domains_dns.yml
│   ├── banana_rat_c2_ip.yml
│   └── fin_known_hashes.yml
├── sentinel/                       # ARM analytics-rule templates (KQL)
│   ├── 01-banana-rat-powershell-c2.json
│   ├── 02-trickmo-apk-sideload.json
│   ├── 03-tclbanker-dll-sideload.json
│   ├── 04-c2-domains-dns.json
│   ├── 05-banana-rat-c2-ip.json
│   └── 06-known-hashes.json
├── chronicle/                      # Google SecOps YARA-L 2.0 rules
│   ├── 01_banana_rat_powershell_c2.yaral
│   ├── 02_trickmo_apk_sideload.yaral
│   ├── 03_tclbanker_dll_sideload.yaral
│   ├── 04_fin_c2_domains_dns.yaral
│   ├── 05_banana_rat_c2_ip.yaral
│   ├── 06_fin_known_hashes.yaral
│   └── reference_lists/
│       └── fin_bt_hashes.txt
├── iocs/
│   └── iocs.csv                    # defanged indicators + GTI verdicts
└── attack-navigator/               # MITRE ATT&CK Navigator layer JSONs
    ├── enterprise-coverage.json
    └── mobile-coverage.json
```

---

## Detection rules

| Rule | What it catches | Log source (Sentinel / Chronicle) | Confidence |
|------|-----------------|-----------------------------------|------------|
| `banana_rat_powershell_c2` | PowerShell pulling Banana RAT payloads from C2 | DeviceProcessEvents / PROCESS_LAUNCH | High |
| `trickmo_apk_sideload` | TikTok-themed APK download over proxy | CommonSecurityLog / NETWORK_HTTP | Medium (hunt) |
| `tclbanker_dll_sideload` | Spoofed `screen_retriever_plugin.dll` side-load | DeviceImageLoadEvents / module load | High |
| `fin_c2_domains_dns` | Resolution of the 3 C2/staging domains | DnsEvents / NETWORK_DNS | High |
| `banana_rat_c2_ip` | Outbound to Banana RAT C2 IPs | DeviceNetworkEvents / NETWORK_CONNECTION | High |
| `fin_known_hashes` | Any of 8 known sample hashes | union / file+process sha256 | High |

Every rule carries author, description, references, severity, and ATT&CK metadata.
Sentinel rules additionally include **entity mappings** (Host, Account, IP, URL, DNS,
File, FileHash, Process), `alertDetailsOverride` for dynamic titles, `customDetails`
(Advisory + ThreatActor), and incident grouping by all entities.

---

## MITRE ATT&CK coverage

Legend: ✅ detected by a rule in this repo · ⬚ documented for the threat but not yet
covered (hunting gap).

### Banana RAT (SHADOW-WATER-063)
| Technique | Name | Tactic | Covered |
|-----------|------|--------|:------:|
| T1059.001 | PowerShell | Execution | ✅ |
| T1105 | Ingress Tool Transfer | Command & Control | ✅ |
| T1071.001 | Web Protocols (C2 domain) | Command & Control | ✅ |
| T1571 | Non-Standard Port / direct C2 IP | Command & Control | ✅ |
| T1204.002 | Malicious File (hash) | Execution | ✅ |
| T1566 | Phishing | Initial Access | ⬚ |
| T1053.005 | Scheduled Task | Persistence | ⬚ |
| T1056.001 | Keylogging | Collection | ⬚ |
| T1115 | Clipboard Data | Collection | ⬚ |
| T1055 | Process Injection | Defense Evasion | ⬚ |

### TrickMo (Coper)
| Technique | Name | Tactic | Covered |
|-----------|------|--------|:------:|
| T1566 / T1660 (mobile) | Phishing (APK delivery) | Initial Access | ✅ |
| T1204.002 | Malicious File (hash) | Execution | ✅ |
| T1572 | Protocol Tunneling (SSH) | Command & Control | ⬚ |
| T1090 | Proxy (SOCKS5) | Command & Control | ⬚ |
| T1417 | Input Capture | Collection | ⬚ |
| T1513 | Screen Capture | Collection | ⬚ |

> Network detection for TrickMo is limited: observed contacts were benign Google /
> Cloudflare CDN infrastructure, so coverage relies on the proxy heuristic + hashes.
> Full coverage requires mobile telemetry (MTD/EMM), not endpoint logs.

### TCLBANKER
| Technique | Name | Tactic | Covered |
|-----------|------|--------|:------:|
| T1574.002 | DLL Side-Loading | Defense Evasion | ✅ |
| T1036.001 | Invalid Code Signature | Defense Evasion | ✅ |
| T1071.001 | Web Protocols (C2 domains) | Command & Control | ✅ |
| T1204.002 | Malicious File (hash) | Execution | ✅ |
| T1497 | Sandbox Evasion | Defense Evasion | ⬚ |
| T1055 | Process Injection | Defense Evasion | ⬚ |
| T1113 | Screen Capture | Collection | ⬚ |

### Interactive ATT&CK Navigator layers

Visualize coverage in the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
— choose **Open Existing Layer → Upload from local** and select a file below.

| Layer | Matrix | Contents |
|-------|--------|----------|
| [`attack-navigator/enterprise-coverage.json`](attack-navigator/enterprise-coverage.json) | Enterprise | Banana RAT + TCLBANKER — 7 techniques detected, 1 partial/hunt, 16 documented gaps |
| [`attack-navigator/mobile-coverage.json`](attack-navigator/mobile-coverage.json) | Mobile | TrickMo / Coper — 14 documented TTPs, all detection gaps (needs MTD/EMM telemetry) |

Color key: 🟩 detected by a repo rule · 🟧 hunt-level heuristic · 🟥 documented TTP, detection gap.

---

## IOC sources & enrichment

**Provenance pipeline:** Threat-advisory feed → IOC extraction → **GTI/VirusTotal**
verdict check → detection authoring. Indicators below are defanged.

| Indicator | Type | Threat | GTI verdict | Notes |
|-----------|------|--------|-------------|-------|
| `24.199.90.58` | IPv4 | Banana RAT | 🔴 13/91 malicious | DigitalOcean; payload host (`/payload.php`, `/st.txt`) |
| `162.141.111.227` | IPv4 | Banana RAT | 🔴 13 mal + 3 susp | LACNIC/Brazil; C2 |
| `c.windowsk-cdn[.]com` | Domain | Banana RAT | 🔴 17 malicious | **DGA**-tagged; NRD 2026-04-19 |
| `38dfeb…06e39d8f` | SHA256 | Banana RAT | 🔴 21/61 (`trojan.boxter`) | PowerShell downloader (`st.txt`) |
| `d7545b…6a70cdaa` | SHA256 | Banana RAT | ⚪ advisory-sourced | not individually re-verified |
| `01889a…63aa8c21` | SHA256 | TrickMo | 🔴 21 mal (banker/dropper) | `TikTok18.apk`; forged Huawei cert |
| `143c0e…0119c026` | SHA256 | TrickMo | 🔴 18 mal (`trojan.coper`) | `data.apk` |
| `arquivos-omie[.]com` | Domain | TCLBANKER | 🔴 19 mal + 3 susp | NRD 2026-04-15; Cloudflare-fronted |
| `doccompartilhe[.]com` | Domain | TCLBANKER | 🔴 19 mal + 3 susp | multi-vendor malicious category |
| `701d51…4995b626` | SHA256 | TCLBANKER | 🔴 46/71; Elastic YARA match | forged "Logitech Inc" signature |
| `8a174a…eb537059` | SHA256 | TCLBANKER | ⚪ advisory-sourced | not individually re-verified |
| `668f93…52342f40` | SHA256 | TCLBANKER | ⚪ advisory-sourced | not individually re-verified |
| `63beb7…2d900394` | SHA256 | TCLBANKER | ⚪ advisory-sourced | not individually re-verified |

Full machine-readable indicators (with first-seen, ASN, registrar) live in
[`iocs/iocs.csv`](iocs/iocs.csv).

> ⚠️ **Operational caveats**
> - TCLBANKER domains are **Cloudflare-fronted** — detect via DNS, not IP blocking.
> - GTI `reputation` read 0 on several freshly-weaponized network IOCs while 13–19
>   engines flagged them; trust engine/YARA detections over the lagging reputation score.
> - All domains were **newly registered (Apr 2026)** — NRD correlation is a strong pivot.

---

## Quick start

### Microsoft Sentinel
```bash
for f in sentinel/*.json; do
  az deployment group create -g <sentinel-rg> \
    --template-file "$f" --parameters workspaceName=<law-name>
done
```
Templates assume Defender XDR (MDE) tables + the DNS and CEF connectors. Swap to
`SecurityEvent`/Sysmon equivalents if that's your telemetry.

### Google SecOps / Chronicle
1. Create a **STRING** reference list `fin_bt_hashes` from
   `chronicle/reference_lists/fin_bt_hashes.txt`.
2. Import each `chronicle/*.yaral` rule and set it Live (+ Alerting as desired).

### Sigma (convert to any backend)
```bash
sigma convert -t <backend> -p <pipeline> sigma/*.yml
```

---

## Validation status

| Item | Status |
|------|--------|
| Sentinel ARM templates | JSON-validated |
| KQL backslash/escaping | verified round-trip |
| Chronicle YARA-L syntax | authored to YARA-L 2.0; validate in your tenant |
| IOC verdicts | GTI-checked 2026-05-25 (see table for re-verification scope) |

---

## Contributing

Issues and PRs welcome — especially additional log-source variants (Splunk, Elastic),
new IOCs for these families, and false-positive reports with context. Please keep IOCs
defanged in issues and include the telemetry/log source for any FP report.

## Disclaimer

Provided for **defensive security and detection engineering**. Rules are starting points:
validate against your own data and tune thresholds before enabling in production. No
warranty of completeness or fitness for a particular environment.

## License

MIT — see [`LICENSE`](LICENSE).

---

*Intelligence triaged from a threat-advisory feed; indicators enriched via Google Threat
Intelligence. Detection content authored as a detection-engineering deliverable.*
