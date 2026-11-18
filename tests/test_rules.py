import json
import os

import pytest

yara = pytest.importorskip("yara")

import run_corpus  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.mark.parametrize("ruleset", ["core", "extended"])
def test_sources_compile(ruleset):
    rules = yara.compile(filepath=run_corpus.SOURCES[ruleset])
    assert sum(1 for _ in rules) > 0


@pytest.mark.parametrize("ruleset", ["core", "extended"])
def test_corpus_matches_expected(ruleset, capsys):
    rc = run_corpus.main(["--set", ruleset])
    out = capsys.readouterr().out
    assert rc == 0, out


@pytest.mark.parametrize("ruleset", ["core", "extended"])
def test_compiled_rules_roundtrip(ruleset, tmp_path):
    # Rules saved by this YARA version must load back and give the same results as the source.
    compiled = tmp_path / (ruleset + ".yara.bin")
    yara.compile(filepath=run_corpus.SOURCES[ruleset]).save(str(compiled))
    from_source = run_corpus.scan_python(run_corpus.SOURCES[ruleset], False, run_corpus.CORPUS)
    from_bin = run_corpus.scan_python(str(compiled), True, run_corpus.CORPUS)
    assert from_source == from_bin


def test_expectations_are_sane():
    with open(os.path.join(HERE, "expected.json")) as f:
        expected = json.load(f)
    for ruleset, files in expected.items():
        for rel, rules in files.items():
            if rel.startswith("benign/"):
                assert rules == [], "%s: benign file %s expected to hit %s" % (ruleset, rel, rules)
    # every web shell fixture is caught by at least the extended rules
    for rel, rules in expected["extended"].items():
        if rel.startswith("webshell/"):
            assert rules, "webshell fixture %s is not detected by the extended rules" % rel
    # core is a subset of extended for every fixture
    for rel, rules in expected["core"].items():
        assert set(rules) <= set(expected["extended"][rel]), rel
