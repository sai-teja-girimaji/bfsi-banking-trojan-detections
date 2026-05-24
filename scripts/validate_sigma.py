#!/usr/bin/env python3
"""Deep-validate Sigma rules for CI.

Checks: YAML well-formedness, required fields, valid + unique rule UUIDs,
logsource presence, condition tokens resolving to declared selections, and
standard ``attack.*`` tag formatting. Exits non-zero if any errors are found;
warnings are printed but non-fatal.

Usage: python scripts/validate_sigma.py [path]   (default: sigma/)
"""
import argparse
import glob
import os
import re
import sys
import uuid

import yaml

LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
COND_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "sum", "min", "max"}


def is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


def validate_file(path, ids, errs, warns) -> None:
    try:
        doc = yaml.safe_load(open(path))
    except Exception as exc:  # noqa: BLE001
        errs.append(f"{path}: YAML parse error: {exc}")
        return
    if not isinstance(doc, dict):
        errs.append(f"{path}: top-level document is not a mapping")
        return

    for key in ("title", "id", "logsource", "detection"):
        if key not in doc:
            errs.append(f"{path}: missing required field '{key}'")

    rid = doc.get("id")
    if rid is not None:
        if not is_uuid(rid):
            errs.append(f"{path}: id '{rid}' is not a valid UUID")
        ids.setdefault(str(rid), []).append(path)

    if doc.get("status") and doc["status"] not in STATUS:
        warns.append(f"{path}: unusual status '{doc['status']}'")
    if doc.get("level") and doc["level"] not in LEVELS:
        errs.append(f"{path}: invalid level '{doc['level']}'")

    logsource = doc.get("logsource") or {}
    if not (logsource.get("category") or logsource.get("product") or logsource.get("service")):
        errs.append(f"{path}: logsource needs category/product/service")

    detection = doc.get("detection") or {}
    if "condition" not in detection:
        errs.append(f"{path}: detection has no condition")
    else:
        selections = [k for k in detection if k != "condition"]
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(detection["condition"])):
            if token in COND_KEYWORDS:
                continue
            if token not in selections and not any(
                s.startswith(token.rstrip("*")) for s in selections
            ):
                warns.append(f"{path}: condition token '{token}' not in selections {selections}")

    for tag in doc.get("tags", []) or []:
        if not re.match(r"^attack\.(t\d{4}(\.\d{3})?|[a-z0-9_]+)$", tag):
            warns.append(f"{path}: non-standard tag '{tag}'")


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep-validate Sigma rules.")
    parser.add_argument("path", nargs="?", default="sigma/", help="directory of Sigma rules")
    args = parser.parse_args()

    files = sorted(
        glob.glob(os.path.join(args.path, "*.yml"))
        + glob.glob(os.path.join(args.path, "*.yaml"))
    )
    if not files:
        print(f"No Sigma rules found under {args.path!r}")
        return 1

    ids, errs, warns = {}, [], []
    for path in files:
        validate_file(path, ids, errs, warns)
        if not any(e.startswith(path) for e in errs):
            print(f"OK   {path}")

    for rid, paths in ids.items():
        if len(paths) > 1:
            errs.append(f"duplicate id {rid} in: {', '.join(paths)}")

    print(f"\n{len(files)} rule(s) | errors={len(errs)} | warnings={len(warns)}")
    for warning in warns:
        print("WARN", warning)
    for error in errs:
        print("ERR ", error)

    if errs:
        print("\nSigma validation FAILED.")
        return 1
    print("\nSigma validation PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
