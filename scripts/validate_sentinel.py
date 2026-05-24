#!/usr/bin/env python3
"""Structurally validate Microsoft Sentinel ARM analytics-rule templates.

Offline structural checks (no Azure auth required): JSON well-formedness, ARM
template envelope, and per-rule required properties including severity enum,
scheduling fields, entity mappings, and MITRE tactics/techniques.

Full deployment validation (`az deployment group validate`) needs a live
workspace and is out of scope for CI; this enforces authoring standards.

Usage: python scripts/validate_sentinel.py [path]   (default: sentinel/)
"""
import argparse
import glob
import json
import os
import re
import sys

SEVERITIES = {"Informational", "Low", "Medium", "High"}
REQUIRED_PROPS = (
    "displayName", "description", "severity", "query",
    "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
)
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_file(path, errs, warns):
    try:
        doc = json.load(open(path))
    except Exception as exc:  # noqa: BLE001
        errs.append(f"{path}: JSON parse error: {exc}")
        return

    if "deploymentTemplate" not in str(doc.get("$schema", "")):
        warns.append(f"{path}: $schema is not an ARM deploymentTemplate")
    if "contentVersion" not in doc:
        errs.append(f"{path}: missing contentVersion")

    resources = doc.get("resources")
    if not isinstance(resources, list) or not resources:
        errs.append(f"{path}: resources must be a non-empty list")
        return

    rule_resources = [r for r in resources if "alertRules" in str(r.get("type", ""))]
    if not rule_resources:
        errs.append(f"{path}: no alertRules resource found")
        return

    for res in rule_resources:
        if not res.get("kind"):
            errs.append(f"{path}: alertRules resource missing 'kind'")
        props = res.get("properties") or {}

        for prop in REQUIRED_PROPS:
            if prop not in props or props[prop] in ("", None):
                errs.append(f"{path}: properties missing '{prop}'")

        sev = props.get("severity")
        if sev and sev not in SEVERITIES:
            errs.append(f"{path}: invalid severity '{sev}'")

        if not isinstance(props.get("query"), str) or len(props.get("query", "")) < 10:
            errs.append(f"{path}: query is empty or too short")

        ents = props.get("entityMappings")
        if not isinstance(ents, list) or not ents:
            errs.append(f"{path}: entityMappings missing or empty")
        else:
            for em in ents:
                if not em.get("entityType") or not em.get("fieldMappings"):
                    errs.append(f"{path}: entityMapping missing entityType/fieldMappings")

        tactics = props.get("tactics")
        if not isinstance(tactics, list) or not tactics:
            errs.append(f"{path}: tactics missing or empty")

        techniques = props.get("techniques") or []
        if not techniques:
            warns.append(f"{path}: no techniques listed")
        for tech in techniques:
            if not TECHNIQUE_RE.match(str(tech)):
                errs.append(f"{path}: malformed technique id '{tech}'")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Sentinel ARM templates.")
    parser.add_argument("path", nargs="?", default="sentinel/")
    args = parser.parse_args()

    files = sorted(glob.glob(os.path.join(args.path, "*.json")))
    if not files:
        print(f"No Sentinel templates found under {args.path!r}")
        return 1

    errs, warns = [], []
    for path in files:
        validate_file(path, errs, warns)
        if not any(e.startswith(path) for e in errs):
            print(f"OK   {path}")

    print(f"\n{len(files)} template(s) | errors={len(errs)} | warnings={len(warns)}")
    for warning in warns:
        print("WARN", warning)
    for error in errs:
        print("ERR ", error)

    if errs:
        print("\nSentinel validation FAILED.")
        return 1
    print("\nSentinel validation PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
