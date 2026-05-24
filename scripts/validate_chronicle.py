#!/usr/bin/env python3
"""Structurally lint Google SecOps (Chronicle) YARA-L 2.0 rules.

Offline structural checks (a full YARA-L compile requires the SecOps backend
`rules.verifyRuleText` API): a valid `rule <name> { ... }` declaration with
balanced braces, presence of the meta / events / condition sections, a valid
rule identifier, and that every referenced reference list (`%name`) has a
matching, non-empty file under reference_lists/.

Usage: python scripts/validate_chronicle.py [path]   (default: chronicle/)
"""
import argparse
import glob
import os
import re
import sys

RULE_DECL_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
IDENT_RE = re.compile(r"^[a-z][a-zA-Z0-9_]*$")
REF_LIST_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)")


def validate_file(path, reflist_dir, errs, warns):
    text = open(path).read()
    if not text.strip():
        errs.append(f"{path}: file is empty")
        return

    decl = RULE_DECL_RE.search(text)
    if not decl:
        errs.append(f"{path}: no 'rule <name> {{' declaration found")
    else:
        name = decl.group(1)
        if not IDENT_RE.match(name):
            warns.append(f"{path}: rule name '{name}' is not snake_case-ish")

    opens, closes = text.count("{"), text.count("}")
    if opens != closes:
        errs.append(f"{path}: unbalanced braces ({opens} '{{' vs {closes} '}}')")

    for section in ("meta:", "events:", "condition:"):
        if section not in text:
            errs.append(f"{path}: missing required section '{section}'")

    for ref in set(REF_LIST_RE.findall(text)):
        ref_path = os.path.join(reflist_dir, f"{ref}.txt")
        if not os.path.isfile(ref_path):
            errs.append(f"{path}: references list %{ref} but {ref_path} is missing")
        elif os.path.getsize(ref_path) == 0:
            errs.append(f"{path}: reference list {ref_path} is empty")


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint Chronicle YARA-L rules.")
    parser.add_argument("path", nargs="?", default="chronicle/")
    args = parser.parse_args()

    files = sorted(glob.glob(os.path.join(args.path, "*.yaral")))
    if not files:
        print(f"No YARA-L rules found under {args.path!r}")
        return 1

    reflist_dir = os.path.join(args.path, "reference_lists")
    errs, warns = [], []
    for path in files:
        validate_file(path, reflist_dir, errs, warns)
        if not any(e.startswith(path) for e in errs):
            print(f"OK   {path}")

    print(f"\n{len(files)} rule(s) | errors={len(errs)} | warnings={len(warns)}")
    for warning in warns:
        print("WARN", warning)
    for error in errs:
        print("ERR ", error)

    if errs:
        print("\nChronicle validation FAILED.")
        return 1
    print("\nChronicle validation PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
