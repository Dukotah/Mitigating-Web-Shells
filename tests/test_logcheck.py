import gzip
import os
import subprocess
import sys
import time

import LogCheck

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "LogCheck.py")


def combined(ip, url, status=200, ua="Mozilla/5.0", method="GET"):
    return '%s - - [16/Apr/2021:10:00:00 +0000] "%s %s HTTP/1.1" %d 512 "-" "%s"\n' % (ip, method, url, status, ua)


def common(ip, url, status=200):
    return '%s - - [16/Apr/2021:10:00:00 +0000] "GET %s HTTP/1.1" %d 128\n' % (ip, url, status)


def run(*paths):
    return subprocess.run([sys.executable, SCRIPT] + [str(p) for p in paths], capture_output=True, text=True)


def sections(stdout):
    lines = stdout.splitlines()
    ua_start = lines.index("URL with least user agents") + 2
    ip_header = lines.index("URL with least IP address")
    return lines[ua_start:ip_header], lines[ip_header + 2:]


def test_parse_combined():
    assert LogCheck.parse_line(combined("10.0.0.1", "/a.php", ua="curl/7.68.0")) == ("10.0.0.1", "/a.php", 200, "curl/7.68.0")


def test_parse_common_log_format_has_dash_user_agent():
    assert LogCheck.parse_line(common("10.0.0.1", "/a.php")) == ("10.0.0.1", "/a.php", 200, "-")


def test_parse_escaped_quotes_in_user_agent():
    line = '10.0.0.1 - - [16/Apr/2021:10:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "Mozilla \\"quoted\\" agent"\n'
    assert LogCheck.parse_line(line) == ("10.0.0.1", "/a", 200, 'Mozilla \\"quoted\\" agent')


def test_parse_skips_blank_comment_and_garbage():
    for line in ["\n", "   \n", "#Fields: ip\n", "garbage\n", "10.0.0.1 - -\n"]:
        assert LogCheck.parse_line(line) is None


def test_issue_15_blank_and_short_lines_do_not_crash(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        combined("10.0.0.1", "/index.php")
        + "\n"
        + "10.0.0.3 - - [16/Apr/2021:10:00:02 +0000]\n"
        + combined("10.0.0.2", "/index.php", ua="curl/7.68.0")
        + combined("10.0.0.4", "/uploads/x.php", ua="python-requests/2.25", method="POST")
    )
    proc = run(log)
    assert proc.returncode == 0, proc.stderr
    ua, ip = sections(proc.stdout)
    assert ua == ["/uploads/x.php"]
    assert ip == ["/uploads/x.php"]
    assert "Skipped 1 line" in proc.stderr


def test_only_2xx_counted(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(combined("10.0.0.1", "/ok") + combined("10.0.0.2", "/missing", status=404)
                   + combined("10.0.0.3", "/redirect", status=302))
    ua, ip = sections(run(log).stdout)
    assert ua == ["/ok"] and ip == ["/ok"]


def test_no_successful_requests_does_not_crash(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(combined("10.0.0.1", "/missing", status=404))
    proc = run(log)
    assert proc.returncode == 0, proc.stderr
    assert sections(proc.stdout) == ([], [])


def test_empty_file_does_not_crash(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    proc = run(log)
    assert proc.returncode == 0, proc.stderr


def test_ranking_and_ties_follow_original_semantics():
    # /rare: 1 ip, 1 ua; /mid: 2 ips, 2 uas; /popular: 3 ips, 3 uas. 5% of 3 URLs rounds up to 1 URL.
    counts = {"/popular": 3, "/rare": 1, "/mid": 2}
    assert LogCheck.least_common(counts) == ["/rare"]
    # ties at the threshold are all included, in first-seen order
    assert LogCheck.least_common({"/b": 1, "/a": 1, "/c": 5}) == ["/b", "/a"]
    assert LogCheck.least_common({}) == []


def test_gzip_and_multiple_files(tmp_path):
    plain = tmp_path / "access.log"
    plain.write_text(combined("10.0.0.1", "/a") + combined("10.0.0.2", "/a"))
    zipped = tmp_path / "access.log.1.gz"
    with gzip.open(zipped, "wt") as f:
        f.write(combined("10.0.0.3", "/a") + combined("10.0.0.9", "/b", ua="odd"))
    proc = run(plain, zipped)
    assert proc.returncode == 0, proc.stderr
    ua, ip = sections(proc.stdout)
    assert ip == ["/b"]


def test_invalid_bytes_do_not_crash(tmp_path):
    log = tmp_path / "access.log"
    log.write_bytes(combined("10.0.0.1", "/a").encode() + b'10.0.0.2 - - [x] "GET /\xff\xfe HTTP/1.1" 200 1 "-" "x"\n')
    assert run(log).returncode == 0


def test_missing_file_and_usage(tmp_path):
    assert run().returncode == 2
    proc = run(tmp_path / "nope.log")
    assert proc.returncode == 2
    assert "valid filename" in proc.stdout


def test_large_log_is_linear(tmp_path):
    # The original implementation used list membership tests (quadratic in unique URLs).
    log = tmp_path / "big.log"
    with open(log, "w") as f:
        for i in range(200000):
            f.write(combined("10.0.%d.%d" % (i % 250, i % 200), "/page/%d" % (i % 20000), ua="agent-%d" % (i % 50)))
    start = time.time()
    proc = run(log)
    elapsed = time.time() - start
    assert proc.returncode == 0, proc.stderr
    assert elapsed < 30, "took %.1fs" % elapsed
