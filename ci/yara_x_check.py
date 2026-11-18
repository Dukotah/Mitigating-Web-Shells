#!/usr/bin/env python3
"""Check the rules against YARA-X (the Rust rewrite of YARA).

core:      must compile and give the same corpus results as libyara (tests/expected.json).
extended:  does not compile on YARA-X because of three regular expressions with an unescaped "{"
           that libyara accepts. This script finds every line YARA-X rejects (by disabling the reported
           line and retrying) and fails if the set differs from KNOWN_EXTENDED_ERRORS, so a new
           incompatibility, or a fix, is noticed. The rest of the extended set must then match the corpus
           expectations, except for the strings that were disabled.
"""
import json
import os
import re
import sys

import yara_x

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(REPO, "tests", "corpus")

KNOWN_EXTENDED_ERRORS = {
    84: "$variable_variable = /\\${\\$[0-9a-zA-z]+}/",
    114: "$shellshock = /\\(\\)\\s*{\\s*[a-z:]\\s*;\\s*}\\s*;/",
    118: "$double_var = /\\${\\s*\\${/",
}


def compile_rejecting(path):
    """Compile, disabling each line YARA-X rejects. Returns (rules, {lineno: text})."""
    with open(path) as f:
        lines = f.read().split("\n")
    rejected = {}
    for _ in range(50):
        compiler = yara_x.Compiler()
        try:
            compiler.add_source("\n".join(lines), origin=os.path.basename(path))
            return compiler.build(), rejected
        except yara_x.CompileError as e:
            m = re.search(r":(\d+):\d+", str(e))
            if not m:
                raise
            n = int(m.group(1))
            if n in rejected:
                raise
            rejected[n] = lines[n - 1].strip()
            print("  rejected line %d: %s" % (n, str(e).splitlines()[0]))
            lines[n - 1] = "// " + lines[n - 1]
    raise SystemExit("too many errors")


def scan(rules):
    scanner = yara_x.Scanner(rules)
    hits = {}
    for dirpath, _, filenames in os.walk(CORPUS):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, CORPUS).replace(os.sep, "/")
            hits[rel] = sorted(r.identifier for r in scanner.scan_file(full).matching_rules)
    return hits


def main():
    with open(os.path.join(REPO, "tests", "expected.json")) as f:
        expected = json.load(f)
    failed = False

    for ruleset in ("core", "extended"):
        path = os.path.join(REPO, "%s.webshell_detection.yara" % ruleset)
        print("%s:" % ruleset)
        rules, rejected = compile_rejecting(path)
        want_rejected = KNOWN_EXTENDED_ERRORS if ruleset == "extended" else {}
        if rejected != want_rejected:
            print("  FAIL rejected lines changed: got %s, expected %s" % (sorted(rejected), sorted(want_rejected)))
            failed = True
        hits = scan(rules)
        for rel in sorted(expected[ruleset]):
            if hits.get(rel) != expected[ruleset][rel]:
                print("  FAIL %s: expected %s, got %s" % (rel, expected[ruleset][rel], hits.get(rel)))
                failed = True
        print("  %d rejected line(s), %d corpus files checked" % (len(rejected), len(hits)))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
