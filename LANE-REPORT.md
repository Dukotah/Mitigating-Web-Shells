# LANE 3 report: Mitigating-Web-Shells

## 1. Upstream contribution rules (CONTRIBUTING.md)

- The only rule: contributions are released under CC0 1.0 (US-government authors: public domain + CC0
  worldwide). Opening a PR is agreement to that waiver. No CLA, no style guide, no test convention.
- History: 9 merged PRs, last outsider merge #14 (2021-04, same day), last merge 2021-07. #1 "Various
  fixes" shows multi-fix PRs have been accepted, so A is one PR covering #19 + #15 + the .bin names.

## 2. Branches

| Branch | Base | Bound for | Commit |
|---|---|---|---|
| `fix/19-15-readme-logcheck` | upstream/master | upstream PR | `1c31ae2` Fix Sysmon log name, nonexistent .bin names, LogCheck crash |
| `lane/yara-ci-corpus` | `fix/19-15-readme-logcheck` | fork only | `80f20f1` CI + corpus + hardened LogCheck.py, plus this report |

### A: `fix/19-15-readme-logcheck` (4 files, +7/-6)
- README: `Micorosft-Windows-Sysmon` -> `Microsoft-Windows-Sysmon` (#19).
- README: IIS example `base.yara.bin` -> `core.yara.bin` (and "base ruleset" -> "core ruleset"); no
  `base.yara.bin` has ever existed.
- Header comment of both `.yara` files told users to use `limited.yara.bin` (also nonexistent) ->
  `core.yara.bin` / `extended.yara.bin`. Comment-only; CRLF of `extended.webshell_detection.yara` preserved.
- `LogCheck.py`: one condition, `if (row[0][0] != '#')` ->
  `if (len(row) >= len(apachelogsfields) and row[0][:1] != '#')` (#15). Blank lines and lines with fewer
  than 10 fields (e.g. Common Log Format, truncated lines) are skipped instead of raising IndexError.
- Kept out of A on purpose: regenerating `.bin` files (described in the PR body instead), the
  "no 2xx requests" crash and the quadratic list scans (fixed on B).
- Why one PR, not two: four one-line fixes in a dormant repo; one review is cheaper for the maintainer
  and #1 set the precedent. Split is trivial if they ask.

### B: `lane/yara-ci-corpus` (fork only)
- `.github/workflows/yara-ci.yml`:
  - `yara` matrix: builds YARA 3.9.0, 3.10.0, 3.11.0, 4.2.3, 4.3.2, 4.5.8, 4.6.0 from source
    (`ci/build-yara.sh`, cached), `yarac`-compiles both sets, runs the corpus against source and compiled
    rules, uploads `compiled-rules-yara-<ver>` artifacts, and annotates whether the shipped `.bin` loads.
  - `pytest`: rule + LogCheck tests on yara-python 4.5.4.
  - `yara-x`: `ci/yara_x_check.py`; core must compile and match the corpus; extended's 3 known rejected
    regexes are pinned so a new incompatibility (or a fix) fails the job.
  - `false-positives`: core rules on clean WordPress 6.8.3 and Drupal 11.2.5 must equal the baseline
    (currently zero hits); extended hit counts reported.
- `tests/corpus/`: 12 inert synthetic fixtures (rule strings inside comments, `.sample` extension,
  labelled as test fixtures, no real web shell code) + 8 benign files. `tests/expected.json` holds
  the exact rule hits per file per set; `tests/run_corpus.py` checks it via yara-python or any `yara` CLI.
- `LogCheck.py` hardened: regex parser for combined + common format with `\"` inside quoted fields,
  dict/set counting, no crash on empty logs / no 2xx, `.gz` and multiple files, `errors='replace'`,
  exit 2 on usage/missing file; same output and ordering. 13 tests in `tests/test_logcheck.py`.

## 3. Evidence (WSL Ubuntu, uv venv Python 3.12.13, yara-python 4.5.4, yara-x 1.10.0)

#15 before/after with a crafted 5-line log (line 3 blank, line 4 common log format):
```
--- BEFORE (upstream/master LogCheck.py)
  File ".../LogCheck.orig.py", line 35, in analyze_weblog
    if (row[0][0] != '#'):
IndexError: list index out of range                  rc=1
--- BEFORE, blank line removed
    user_agent = row[apachelogsfields.index('user_agent')]
IndexError: list index out of range                  rc=1
--- AFTER (fixed LogCheck.py)
URL with least user agents
--------------------------
/uploads/x.php
URL with least IP address
-------------------------
/uploads/x.php                                       rc=0
```

Shipped `.bin` files vs YARA versions (built from source locally; same result in CI):
```
yara-python 4.5.4: core.webshell_detection.yara OK 22 rules / extended OK 34 rules
                   core.yara.bin FAIL: rules file "core.yara.bin" is incompatible with this version of YARA
yara 3.10.0 -C core.yara.bin -> rc=1 rules were compiled with a different version of YARA
yara 3.11.0 -C core.yara.bin -> rc=1 rules were compiled with a different version of YARA
yara 4.5.8  -C core.yara.bin -> rc=1 rules were compiled with a different version of YARA   (same for extended)
[3.9.0 shipped core.yara.bin] core: 20 files, 0 failures
[3.9.0 shipped extended.yara.bin] extended: 20 files, 0 failures
```
Header bytes: shipped `59415241 b8c00300 2000 1500` = arena version 21 (YARA 3.9.0 `arena.h`:
`(21 << 16)`); 3.10/3.11 write 22. So the shipped bins only load on YARA 3.9.x, while the README links
the 3.11.0 release and recommends the compiled files.

Corpus, all backends (local): source + yarac-compiled on 3.9.0, 3.10.0, 3.11.0, 4.5.8 -> `core: 20 files,
0 failures`, `extended: 20 files, 0 failures`. Example (extended):
```
ok   benign/contact.php                       (no hits)
ok   webshell/fopo_loader.sample              obfuscatedFunctionality, possibleIndicator, suspiciousFunctionality
ok   webshell/regeorg_markers.sample          reGeorg_Variant_Web_shell
```

pytest:
```
tests/test_logcheck.py::test_issue_15_blank_and_short_lines_do_not_crash PASSED
tests/test_rules.py::test_compiled_rules_roundtrip[extended] PASSED
============================= 20 passed in 25.58s ==============================
```

YARA-X:
```
core:      0 rejected line(s), 20 corpus files checked
extended:  rejected line 84:  error[E014]: invalid regular expression   $variable_variable = /\${\$[0-9a-zA-z]+}/
           rejected line 114: error[E014]: invalid regular expression   $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
           rejected line 118: error[E014]: invalid regular expression   $double_var = /\${\s*\${/
```
(Line 84 also has `A-z`, which matches `[\]^_` and backtick as well as letters.)

LogCheck A vs B, 100,000-line combined log, 2,348 unique URLs: outputs byte-identical (2,649 lines);
A 10.48 s, B 0.62 s.

GitHub Actions on the fork, run 44242334766 (lane/yara-ci-corpus @ 80f20f1): **all 10 jobs green**
(pytest, yara 3.9.0/3.10.0/3.11.0/4.2.3/4.3.2/4.5.8/4.6.0, yara-x, false-positives).
```
- extended.yara.bin loads and passes the corpus on YARA 3.9.0
! core.yara.bin does not load on YARA 4.5.8: rules were compiled with a different version of YARA
Core rules against WordPress 6.8.3: 3230 files scanned, 0 rule hits
Core rules against Drupal 11.2.5: 22721 files scanned, 0 rule hits
Extended (informational): wordpress 311 rule hits, drupal-11.2.5 263 rule hits
artifacts: compiled-rules-yara-{3.9.0,3.10.0,3.11.0,4.2.3,4.3.2,4.5.8,4.6.0}
```

## 4. Competing work check

`gh pr list -R nsacyber/Mitigating-Web-Shells --state all -L 50`, at start and before finishing:
- #20 (open) only changes the NSA press-release link (README line 5). No overlap.
- #21 (open, ruppde) adds YARA rules to `core.webshell_detection.yara`; no overlap with A. If merged, the
  `.bin` files would need regenerating anyway, which the PR body for A mentions.
- #11 (closed, maintainer) once proposed "yara-ci testing"; never merged.
- Issues: #19 (no PR), #15 (assigned to iadgovuser41 since 2021, no PR). No issue exists for the `.bin`
  version problem or the nonexistent `.bin` names.
- No PRs from the AI-PR spray accounts.

## 5. Draft upstream text

### Issue (file first, then reference it from the PR)

**Title:** Compiled rules (core.yara.bin, extended.yara.bin) only load on YARA 3.9.x

**Body:**
> The README recommends the compiled rule files and links the YARA v3.11.0 release, but both `.bin`
> files are rejected by every YARA release except 3.9.x:
>
> ```
> yara 3.10.0 -C core.yara.bin <dir>  ->  rules were compiled with a different version of YARA
> yara 3.11.0 -C core.yara.bin <dir>  ->  rules were compiled with a different version of YARA
> yara 4.5.8  -C core.yara.bin <dir>  ->  rules were compiled with a different version of YARA
> yara-python 4.5.4: rules file "core.yara.bin" is incompatible with this version of YARA
> ```
>
> The file header has arena version 21 (`59 41 52 41 b8 c0 03 00 20 00 15 00`), which is what YARA 3.9.0
> writes; 3.10 and 3.11 write 22, and 4.x uses a different format. With YARA 3.9.0 both files load and
> match as expected. Compiled YARA rules are only readable by the same YARA version that produced them, so
> any single `.bin` will go stale. Options: regenerate with a current 4.x release and state the version
> next to the link, or publish per-version compiled files as release assets. The `.yara` sources compile
> cleanly on YARA 3.9 through 4.6.
>
> Separately, `extended.webshell_detection.yara` does not compile on YARA-X (the Rust rewrite).
> Lines 84, 114 and 118 contain an unescaped `{` in a regex (`/\${\$[0-9a-zA-z]+}/`,
> `/\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/`, `/\${\s*\${/`). Line 84 also uses `A-z`, which matches
> `[ \ ] ^ _` and backtick too. `core.webshell_detection.yara` compiles on YARA-X.

### PR (branch `fix/19-15-readme-logcheck`)

**Title:** Fix Sysmon log name, nonexistent .bin names, and LogCheck.py crash on short lines

**Body:**
> - README: the Sysmon query used `Micorosft-Windows-Sysmon/Operational`, so `Get-WinEvent` finds no
>   such log. Fixes #19.
> - README: the IIS example used `base.yara.bin`, and the header comment of both `.yara` files refers to
>   `limited.yara.bin`. Neither file exists; the compiled rules in the repo are `core.yara.bin` and
>   `extended.yara.bin`.
> - LogCheck.py: `row[0][0]` and `row[9]` were read without checking the row, so a blank line, or any
>   line with fewer than 10 space-separated fields (Common Log Format without referer/user-agent, a
>   truncated last line), raised `IndexError`. It depends on log content, not file size. Such lines are
>   now skipped. Fixes #15.
>
> Before/after with a 5-line log containing a blank line and one Common Log Format line:
> ```
> before: IndexError: list index out of range   (line 35, row[0][0])
> before, blank line removed: IndexError: list index out of range   (line 40, user_agent)
> after: prints /uploads/x.php under both headings, exit 0
> ```
>
> Not changed here: `core.yara.bin` / `extended.yara.bin` were compiled with YARA 3.9.x and do not load
> on 3.10, 3.11 or any 4.x (details in #<issue>). They should be regenerated with whichever YARA version
> the README is going to recommend; I left the binaries alone so this PR stays reviewable.
>
> 🤖 Generated with [Claude Code](https://claude.com/claude-code)

## 6. Land probability

**Low.** The fixes are small and verifiable, but nothing has merged in this repo since 2021-07 and #20/#21
have waited since 2023 with no response; historically tiny doc fixes were merged same-day, so it is not zero.

Owner next steps:
1. Review the A diff (`git diff upstream/master fix/19-15-readme-logcheck`, 7+/6-).
2. Open the `.bin` issue above upstream, then the PR from `Dukotah:fix/19-15-readme-logcheck`,
   replacing `#<issue>` with its number.
3. Optional: attach the CI's `compiled-rules-yara-4.5.8` artifact to the issue as ready-made replacements.
