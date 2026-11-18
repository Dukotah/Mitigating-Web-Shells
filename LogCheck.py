import sys
import os.path
import re
import gzip
import math


# Script will generate a list of URL that from Apache web access log that have least unique IP address or unique user-agents
# Written for Python 3
#
# Accepts Apache/nginx "combined" and "common" log format lines. Lines in common log format (no referer and
# user-agent fields) are counted with a user-agent of "-". Blank lines, comment lines (starting with #) and lines
# that do not parse are skipped; the number of skipped lines is reported on stderr. Files ending in .gz are read
# with gzip. Several log files may be given; their entries are combined.

# Ideal Percentage of URL to display
#   Will display more base on matching count
urlpercentage = 0.05

# Hold the filename for Apache web access log
weblogfileName = None

# ip identd user [time] "request" status size ["referer" "user_agent"]
# Quoted fields may contain backslash-escaped quotes (Apache writes " inside a field as \").
LOGLINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]*\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) \S+'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<user_agent>(?:[^"\\]|\\.)*)")?'
)


def parse_line(line):
    """Return (ip, url, status, user_agent) for a log line, or None if the line should be skipped."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    m = LOGLINE.match(line)
    if not m:
        return None
    url = m.group('request').partition(' ')[2].partition(' ')[0]   # extract URL from request field
    user_agent = m.group('user_agent')
    if user_agent is None:
        user_agent = '-'
    return m.group('ip'), url, int(m.group('status')), user_agent


def _open(filename):
    if filename.endswith('.gz'):
        return gzip.open(filename, mode='rt', encoding='utf-8', errors='replace')
    return open(filename, mode='r', encoding='utf-8', errors='replace')


def count_unique(lines):
    """Return ({url: set(ips)}, {url: set(user_agents)}, skipped) for 2xx requests, in first-seen URL order."""
    ips = {}
    agents = {}
    skipped = 0
    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            if line.strip() and not line.lstrip().startswith('#'):
                skipped += 1
            continue
        ip, url, status, user_agent = parsed
        if 200 <= status <= 299:                                   # only request with status of 200 - 299
            ips.setdefault(url, set()).add(ip)
            agents.setdefault(url, set()).add(user_agent)
    return ips, agents, skipped


def least_common(counts, percentage=urlpercentage):
    """Return URLs ordered by ascending count, cut at the count of the URL at the given percentile.

    Matches the original LogCheck.py ordering: by count, then first-seen order; every URL whose count is at or
    below the threshold count is included, so ties can make the list longer than the percentage.
    """
    if not counts:
        return []
    n = max(1, int(math.ceil(percentage * len(counts))))
    threshold = sorted(counts.values())[n - 1]
    return [url for c in range(0, threshold + 1) for url, cnt in counts.items() if cnt == c]


# function output the url based on lower counts unique ip address and lower counts of unique user-agents
def analyze_weblog(*filenames):
    ips = {}
    agents = {}
    skipped = 0
    for filename in filenames:
        print("The weblog file to analyze is %s" % filename)
        with _open(filename) as f:
            file_ips, file_agents, file_skipped = count_unique(f)
        for url, s in file_ips.items():
            ips.setdefault(url, set()).update(s)
        for url, s in file_agents.items():
            agents.setdefault(url, set()).update(s)
        skipped += file_skipped
    if skipped:
        sys.stderr.write("Skipped %d line(s) that are not in combined or common log format\n" % skipped)

    print('URL with least user agents')
    print('--------------------------')
    for url in least_common({u: len(s) for u, s in agents.items()}):
        print(url)

    print('URL with least IP address')
    print('-------------------------')
    for url in least_common({u: len(s) for u, s in ips.items()}):
        print(url)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 %s <weblogfile> [<weblogfile> ...]' % sys.argv[0])         # Print usage statement
        sys.exit(2)
    missing = [name for name in sys.argv[1:] if not os.path.isfile(name)]
    if missing:
        print("You must provide a valid filename (path) of a web logfile: %s" % ", ".join(missing))
        sys.exit(2)
    for weblogfileName in sys.argv[1:]:
        print("Web log file to read is %s" % weblogfileName)
    analyze_weblog(*sys.argv[1:])
