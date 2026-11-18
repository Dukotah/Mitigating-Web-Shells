#!/usr/bin/env python3
"""Scan the test corpus (or any tree) with the YARA rules and compare against expectations.

Backends:
  python  - yara-python (default)
  cli     - a yara binary given with --yara (any version, e.g. 3.11 or 4.x)

Examples:
  python tests/run_corpus.py --set core
  python tests/run_corpus.py --set extended --yara ~/yara-4.5.8/bin/yara
  python tests/run_corpus.py --set core --rules build/core.yara.bin --compiled --yara ~/yara-4.5.8/bin/yara
  python tests/run_corpus.py --set core --tree /tmp/wordpress --baseline tests/fp-baseline/wordpress-core.txt
  python tests/run_corpus.py --set core --update      # rewrite tests/expected.json for this set

Exit status is 0 when every file matches exactly the expected rules, 1 otherwise.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CORPUS = os.path.join(HERE, "corpus")
EXPECTED = os.path.join(HERE, "expected.json")
SOURCES = {
    "core": os.path.join(REPO, "core.webshell_detection.yara"),
    "extended": os.path.join(REPO, "extended.webshell_detection.yara"),
}


def list_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.isfile(full) and not os.path.islink(full):
                out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return out


def scan_python(rules_path, compiled, root):
    import yara

    rules = yara.load(rules_path) if compiled else yara.compile(filepath=rules_path)
    hits = {}
    for rel in list_files(root):
        matches = rules.match(os.path.join(root, rel))
        hits[rel] = sorted(m.rule for m in matches)
    return hits


def scan_cli(yara_bin, rules_path, compiled, root):
    cmd = [yara_bin, "-r"]
    if compiled:
        cmd.append("-C")
    cmd += [rules_path, root]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("yara exited with %d" % proc.returncode)
    hits = {rel: [] for rel in list_files(root)}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        rule, _, path = line.partition(" ")
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        hits.setdefault(rel, []).append(rule)
    return {rel: sorted(rules) for rel, rules in hits.items()}


def as_lines(hits):
    return sorted("%s %s" % (rule, rel) for rel, rules in hits.items() for rule in rules)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", choices=sorted(SOURCES), required=True, help="which ruleset's expectations to use")
    ap.add_argument("--rules", help="rules file (default: the .yara source for --set)")
    ap.add_argument("--compiled", action="store_true", help="--rules is a compiled (yarac) file")
    ap.add_argument("--yara", help="path to a yara binary; selects the cli backend")
    ap.add_argument("--tree", help="scan this directory instead of the corpus")
    ap.add_argument("--baseline", help="with --tree: file of expected 'rule path' lines")
    ap.add_argument("--update", action="store_true", help="write results as the new expectation")
    args = ap.parse_args(argv)

    rules_path = args.rules or SOURCES[args.set]
    root = args.tree or CORPUS
    if args.yara:
        hits = scan_cli(args.yara, rules_path, args.compiled, root)
    else:
        hits = scan_python(rules_path, args.compiled, root)

    if args.tree:
        got = as_lines(hits)
        print("%d files scanned, %d rule hits" % (len(hits), len(got)))
        for line in got:
            print("  " + line)
        if args.update and args.baseline:
            with open(args.baseline, "w", newline="\n") as f:
                f.write("".join(line + "\n" for line in got))
            return 0
        if not args.baseline:
            return 0
        with open(args.baseline) as f:
            want = sorted(line.strip() for line in f if line.strip() and not line.startswith("#"))
        new = sorted(set(got) - set(want))
        gone = sorted(set(want) - set(got))
        for line in new:
            print("NEW HIT (not in baseline): " + line)
        for line in gone:
            print("MISSING (in baseline, not hit): " + line)
        return 1 if (new or gone) else 0

    expected = {}
    if os.path.exists(EXPECTED):
        with open(EXPECTED) as f:
            expected = json.load(f)
    if args.update:
        expected[args.set] = hits
        with open(EXPECTED, "w", newline="\n") as f:
            json.dump(expected, f, indent=2, sort_keys=True)
            f.write("\n")
        print("updated %s [%s]" % (EXPECTED, args.set))
        return 0

    want = expected.get(args.set, {})
    failures = 0
    for rel in sorted(set(hits) | set(want)):
        got_rules = hits.get(rel)
        want_rules = want.get(rel)
        if got_rules is None:
            print("FAIL %-40s missing from corpus" % rel)
            failures += 1
        elif want_rules is None:
            print("FAIL %-40s no expectation recorded (got %s)" % (rel, got_rules))
            failures += 1
        elif got_rules != want_rules:
            print("FAIL %-40s expected %s, got %s" % (rel, want_rules, got_rules))
            failures += 1
        else:
            print("ok   %-40s %s" % (rel, ", ".join(got_rules) or "(no hits)"))
    print("%s: %d files, %d failures" % (args.set, len(hits), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
