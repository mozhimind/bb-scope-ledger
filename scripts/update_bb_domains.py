#!/usr/bin/env python3
"""
Daily bug-bounty scope aggregator.  Run:  python3 scripts/update_bb_domains.py   (standard library only)

WHAT IT DOES
    Every day (GitHub Actions, see .github/workflows/daily.yml) this script downloads the public scope lists of
    bug bounty programs from 18 sources, understands every entry, merges them, compares the result with the
    previous day and writes text files into data/ so a researcher can see "what is new today" and test it.

THE 18 SOURCES (each returns rows (raw entry, bounty status, program name, program url))
  Mirrors and aggregators (functions src_* below), always on:
    arkadiyt-domains, arkadiyt-wildcard   flat lists of hosts / wildcards from arkadiyt/bounty-targets-data (no bounty flag)
    arkadiyt-hackerone, -bugcrowd, -intigriti, -yeswehack   per-platform JSON files of the same repo (real bounty flag)
    projectdiscovery   ProjectDiscovery public-bugbounty-programs (dist/data.json, fallback src/data.yaml)
    diodb     disclose/diodb program-list.json (only registrable domains of program pages: leads, not scope)
    immunefi-direct   immunefi.com public API (web assets of paying programs + GitHub assets)
  Direct from the platforms (scripts/directsources.py), optional, named "<platform>-direct":
    hackerone-direct (public GraphQL, no login), hackerone-api (official API, needs H1_USERNAME + H1_TOKEN; skipped
    without them), intigriti-direct (official API with INTIGRITI_TOKEN, otherwise the public website endpoints),
    yeswehack-direct (YWH_TOKEN optional), bugcrowd-direct and hackenproof-direct (no login).
    self-hosted-manual   YOUR OWN list in config/self-hosted-programs.tsv: programs a company runs itself (Google, Microsoft ...)
    self-hosted-pages    program pages listed in config/self-hosted-pages.tsv, downloaded and read every day (textscope.py)
    self-hosted-text     page text pasted into config/self-hosted-text/*.txt (for pages drawn by JavaScript)
    Without its token a source is "skipped"; when one breaks it only WARNS (stats.txt, run stays green, last good copy
    kept) unless BB_DIRECT_STRICT=1. Only PUBLIC programs are read unless BB_INCLUDE_PRIVATE=1 (private scope is
    usually under NDA: use that only in a private repository). All sources download in parallel.

THE PIPELINE (see main())
    1. download each source (run_source); a broken source is replaced by its last good copy in state/
    2. scopeparse.parse_entry turns each raw entry into 0..n "hits", each hit belongs to one ASSET TYPE
    3. the Collector merges hits: per asset type, per value: bounty status, sources, programs, raw entries
    4. diffs against the latest earlier snapshot in history/daily  ->  <asset>-new.txt / <asset>-removed.txt
    5. write data/ (current state), history/daily/DATE (small snapshot + diff base), history/monthly/YYYY-MM
       (running unions), state/context-DATE.tsv (so tomorrow's "removed" lines can say where a host came from)

ASSET TYPES (the keys of ASSETS below; one family of files each: <asset>.txt, -paying, -new, -removed)
    apex  subdomains  wildcards  urls  apis  ips  asn  github  repos-other  apps  patterns  internal-hosts  maybe
    Code note: inside the code an asset type also has a short internal "kind" code ("sub", "ip", "app", ...)
    which is what scopeparse.Hit.kind uses. ASSETS maps file name stem -> kind code; STEM is the reverse.

KEY RULES (and why)
    * Failure handling: a source that errors, returns nothing, or shrinks below MIN_RATIO % of its last good copy is
      replaced by that copy (state/<source>.tsv). Otherwise one bad download would show every host as "removed"
      today and "new" tomorrow. The problem is written to data/failed-sources.txt; the workflow commits the data
      first and THEN turns red, so GitHub emails the owner.
    * Diffs compare with the latest EARLIER folder in history/daily (not "yesterday"), so a skipped day, a late run or
      a re-run on the same day all still give a correct diff. The first run, and BB_BASELINE=1, write no diffs
      (a changed PARSER_VERSION does this automatically; BB_BASELINE=1 does it by hand).
    * Apex = registrable domain from the Public Suffix List (ICANN part): www.bbc.co.uk -> bbc.co.uk; bare suffixes
      (co.uk) are rejected. A host that equals its apex goes to apex.txt, anything below it to subdomains.txt, and
      the apex of every listed subdomain is also added to apex.txt ("derived" apexes).
    * Bounty flag per value: "paying" if any source says so, else "non-paying" if any source says so, else
      "unknown". BB_UNKNOWN_PAYING=1 (default) lets "unknown" count as paying in the *-paying files, so hosts that only
      the flat arkadiyt lists know (no flag) are not hidden from the paying lists.
    * Nothing understood is silently dropped: repairs are logged in data/recovered.txt, sentences that contain a host go
      to maybe.txt, and only real junk lands in data/rejected.txt with a reason.
    * NON_SCOPE (below) is only used for diodb and immunefi-direct, whose data contains links that are not scope.
    * master.txt = every distinct value of every asset type once (the host column of review-by-source.txt).

ENVIRONMENT OVERRIDES (all optional)
    BB_ROOT (project folder), BB_DATE (YYYY-MM-DD, for tests), BB_TZ (default Asia/Kolkata), BB_BASELINE=1,
    BB_MIN_RATIO (50), BB_UNKNOWN_PAYING (1), BB_RETAIN_DAYS (30 days of history/daily kept in the working tree), BB_RETAIN_MONTHS (0 = keep history/monthly forever), BB_MIN_FREE_MB (300: no run below this much free disk),
    BB_DIRECT (1; 0 = no direct sources), BB_INCLUDE_PRIVATE, BB_DIRECT_STRICT, BB_DIRECT_BUDGET (600 s per direct
    source), BB_DIRECT_DELAY (0.3 s between requests to one platform). BB_DIRECT_WORKERS (6 requests at once per platform; 1 = one by one). Secrets: H1_USERNAME, H1_TOKEN, INTIGRITI_TOKEN, YWH_TOKEN.

TO ADD A SOURCE: write a src_xxx()  (or a function in directsources.py) returning [(raw, status, program, program_url)], add it to the `sources` list in main(),
    list its download in the README. scopeparse already copes with messy entries.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
import traceback
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# ----------------------------------------------------------------------------- locations and settings
HERE = Path(__file__).resolve().parent          # the scripts/ folder
try:                                              # PROJECT VERSION: the one-line file VERSION in the project root (semantic: MAJOR.MINOR.PATCH).
    VERSION = (HERE.parent / "VERSION").read_text(encoding="utf-8").strip() or "unknown"   # Shown in stats.json, the website and the zip name.
except OSError:
    VERSION = "unknown"
sys.path.insert(0, str(HERE))
import scopeparse  # noqa: E402  (understands one raw scope entry; lives next to this file)
import textscope  # noqa: E402  (finds scope entries inside description / page texts)
import directsources  # noqa: E402  (reads HackerOne, Bugcrowd, Intigriti, YesWeHack, HackenProof directly)
import archive  # noqa: E402  (the all-time database: every value ever in scope, never deleted)
import proghistory  # noqa: E402  (remembers programs day to day: appeared / left / returned / shrank / grew)
from scopeparse import github_project  # noqa: E402

ROOT = Path(os.environ.get("BB_ROOT") or HERE.parent)    # project folder (tests point BB_ROOT at a temp folder)
DATA = ROOT / "data"        # today's results; overwritten every run (git history keeps the old versions)
STATE = ROOT / "state"      # memory between runs: last good copy of each source, context of removed hosts
CONFIG = ROOT / "config"    # denylist.txt (optional hosts to drop) and a vendored Public Suffix List (fallback)
HIST = ROOT / "history"     # daily/ (diff base + changelog) and monthly/ (running unions)

# A source that comes back with fewer than MIN_RATIO % of its last good row count is treated as broken.
MIN_RATIO = int(os.environ.get("BB_MIN_RATIO", "50"))
# Should hosts with bounty status "unknown" appear in the *-paying files? (see KEY RULES in the module docstring)
UNKNOWN_PAYING = os.environ.get("BB_UNKNOWN_PAYING", "1") == "1"
# How many days of history/daily folders stay in the working tree (older ones are deleted; git history has them).
RETAIN_DAYS = int(os.environ.get("BB_RETAIN_DAYS", "30"))
# How many months of history/monthly folders stay. 0 (the default) = keep forever: this project is a database of everything that was ever in scope.
RETAIN_MONTHS = int(os.environ.get("BB_RETAIN_MONTHS", "0"))
# --- direct platform sources (scripts/directsources.py); all optional
# BB_DIRECT=0 switches them all off. BB_INCLUDE_PRIVATE=1 also reads PRIVATE programs of the accounts whose tokens are
# set (their scope is usually under NDA: only do that when the repository is private).
DIRECT = os.environ.get("BB_DIRECT", "1") != "0"
INCLUDE_PRIVATE = os.environ.get("BB_INCLUDE_PRIVATE", "") == "1"
DIRECT_BUDGET = int(os.environ.get("BB_DIRECT_BUDGET", "600"))      # max seconds per direct source
DIRECT_DELAY = float(os.environ.get("BB_DIRECT_DELAY", "0.3"))      # pause between requests to one platform (politeness)
# By default a broken direct source is only a WARNING (shown in stats.txt, last good copy kept, run stays green) because
# these sources are experimental. BB_DIRECT_STRICT=1 treats them like any other source: the run turns red.
DIRECT_STRICT = os.environ.get("BB_DIRECT_STRICT", "") == "1"

# --- keeping going when a publisher goes away
# BB_DISABLE=name1,name2  retires sources by their name (e.g. BB_DISABLE=arkadiyt-domains,arkadiyt-wildcard,arkadiyt-hackerone). A disabled
# source is not downloaded and its stored copy is left alone, so the daily run stops being red because of it.
DISABLED = {x.strip() for x in os.environ.get("BB_DISABLE", "").split(",") if x.strip()}
# A mirror that silently stops publishing does not fail: the files stay downloadable, just frozen. So for sources that
# normally change all the time we remember when their content last changed (state/<source>.meta) and WARN when it has
# not changed for this many days. Sources not listed here (projectdiscovery, diodb, immunefi-direct, the other direct ones) may legitimately stay equal.
STALE_DAYS = {"arkadiyt-domains": 3, "arkadiyt-wildcard": 3, "arkadiyt-hackerone": 7, "arkadiyt-bugcrowd": 7, "arkadiyt-intigriti": 7, "arkadiyt-yeswehack": 7}
# BB_STALE_DAYS=0 switches the check off; BB_STALE_DAYS=N replaces every limit above with N days.
if os.environ.get("BB_STALE_DAYS", "").strip().isdigit():
    STALE_DAYS = {k: int(os.environ["BB_STALE_DAYS"]) for k in STALE_DAYS}

# PARSER_VERSION: bump this string whenever a change to scopeparse.py / the asset rules changes what existing raw entries
# turn into. The next run then notices that state/parser-version.txt differs and automatically writes no diffs for
# that one day (like BB_BASELINE=1), so the one-off change is not reported as hundreds of new / removed hosts.
PARSER_VERSION = "2026-11-10-descriptions-apis"
# BB_BASELINE=1 -> write today's data but no diffs (new/removed). Use after changing parsing rules.
BASELINE = os.environ.get("BB_BASELINE", "") == "1"


def _today() -> str:
    """Today's date (YYYY-MM-DD) in the owner's time zone, so a 03:00 IST run is dated with the IST day."""
    forced = os.environ.get("BB_DATE")
    if forced:
        return forced
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(os.environ.get("BB_TZ", "Asia/Kolkata"))
    except Exception:
        tz = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(tz).strftime("%Y-%m-%d")


DATE = _today()
MONTH = DATE[:7]
HIST_DAILY = HIST / "daily"                 # one folder per day: <asset>.txt lists + review files + stats
HIST_TODAY = HIST_DAILY / DATE
HIST_MONTH = HIST / "monthly" / MONTH       # one folder per month: running unions, files updated in place

RAW = "https://raw.githubusercontent.com"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# Hosts that show up in diodb / immunefi-direct data but are never scope: a program's policy page on a bounty platform
# (hackerone.com/x), a contact form on a SaaS tool (typeform.com), a social page, a block explorer. A link is skipped
# when its host, or its registrable domain, is in this set. The platform JSON files and projectdiscovery do NOT use it (a program
# that really has zendesk.com in scope still gets it from them). If you see noise from diodb/immunefi-direct in
# review-by-source.txt, add its domain here.
NON_SCOPE = {
    "hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com", "hackenproof.com", "immunefi.com",
    "federacy.com", "openbugbounty.org", "bugbounty.jp", "safehub.io", "zerocopter.com", "standoff365.com",
    "responsibledisclosure.com", "disclose.io", "github.com", "githubusercontent.com", "gitlab.com",
    "bitbucket.org", "etherscan.io", "bscscan.com", "polygonscan.com", "arbiscan.io", "snowtrace.io",
    "medium.com", "twitter.com", "x.com", "discord.com", "discord.gg", "t.me", "telegram.org",
    "youtube.com", "linkedin.com", "facebook.com", "docs.google.com", "notion.so", "gitbook.io",
    "notion.site", "freshdesk.com", "typeform.com", "wufoo.com", "jotform.com", "zendesk.com", "zendesk.de",
    "sites.google.com", "drive.google.com", "forms.gle",
}


# Bug bounty PLATFORMS: a program whose page lives on one of these domains is a "platform" program. Every other program
# page (bughunters.google.com, microsoft.com/msrc, zoho.com/security ...) belongs to a SELF-HOSTED program, one the company
# runs itself. Used for the "hosting" column of review-by-source.txt and for data/programs.txt. Add a domain here when a
# platform is missing; matching is by registrable domain or any sub-domain of the entry.
PLATFORM_DOMAINS = {
    "hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com", "hackenproof.com", "immunefi.com",
    "federacy.com", "openbugbounty.org", "bugbounty.jp", "safehub.io", "zerocopter.com", "standoff365.com",
    "synack.com", "yogosha.com", "cobalt.io", "huntr.com", "huntr.dev", "hacktrophy.com", "bugbase.in", "bugbase.ai",
    "responsibledisclosure.com", "disclose.io", "hackrate.com", "hackenproof.com", "code4rena.com", "sherlock.xyz",
    "cantina.xyz", "hats.finance", "bountyfactory.io", "vulnerability-lab.com", "inspectiv.com", "ncsc.nl",
}


def hosting_of_url(url: str) -> str:
    """"platform" if the program page is on a known bounty platform, "self-hosted" if it is anywhere else, "" without url."""
    host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower() if url else ""
    if not host:
        return ""
    return "platform" if any(host == d or host.endswith("." + d) for d in PLATFORM_DOMAINS) else "self-hosted"


def program_key(name: str, url: str) -> str:
    """The IDENTITY of a program, the same whichever source named it. Every source writes the same program differently
    ("Yahoo" / "Yahoo Bug Bounty", hackerone.com/yahoo / https://hackerone.com/yahoo/policy_scopes, www. or not, trailing slash,
    Intigriti's /detail ...). Known platforms are reduced to platform + handle; any other page to host + path; a row without a
    url to its normalised name ("name:..."). Two rows with the same key are ONE program (see ProgramRegistry)."""
    u = (url or "").strip()
    if u:
        pu = urlparse(u if "://" in u else "https://" + u)
        host = re.sub(r"^www\.", "", (pu.hostname or "").lower())
        segs = [x for x in pu.path.split("/") if x]
        low = [x.lower() for x in segs]
        if host == "hackerone.com" and segs:
            return "h1:" + low[0]
        if host == "bugcrowd.com" and segs:
            return "bc:" + (low[1] if low[0] in ("engagements", "programs") and len(segs) > 1 else low[0])
        if host.endswith("intigriti.com") and "programs" in low:
            rest = [x for x in low[low.index("programs") + 1:] if x not in ("detail", "policy", "scope")]
            if rest:
                return "inti:" + "/".join(rest[:2])
        if host == "yeswehack.com" and low[:1] == ["programs"] and len(segs) > 1:
            return "ywh:" + low[1]
        if host == "hackenproof.com":
            rest = [x for x in low if x not in ("programs", "bug-bounty-programs")]
            if rest:
                return "hp:" + rest[-1]
        if host == "immunefi.com" and len(segs) > 1 and low[0] in ("bounty", "bug-bounty"):
            return "imm:" + low[1]
        if host:
            return "url:" + host + "/" + "/".join(low)
    return "name:" + re.sub(r"[^a-z0-9]+", "", (name or "").lower())


class ProgramRegistry:
    """One program, one entry. Before anything is merged, every (name, url) pair of every source is shown to the registry;
    canon(name, url) then answers with the SAME (name, url) for all the spellings of one program, so programs.txt, the program
    pages and the scope lists show it once. The chosen name / url is the one most sources use (ties: the shorter, then
    alphabetical), so the result does not depend on the order the sources finished in. A row that has only a name joins the
    program with that same normalised name when there is exactly one."""

    def __init__(self) -> None:
        self.seen = defaultdict(Counter)           # key -> Counter of (name, url)
        self.final: dict = {}
        self.alias: dict = {}                      # key of a name-only row -> key of the program it joins

    def see(self, name: str, url: str) -> None:
        if name or url:
            self.seen[program_key(name, url)][(name or "", url or "")] += 1

    def finish(self) -> None:
        by_name = defaultdict(set)                 # normalised name -> keys of programs that have a url
        for key, c in self.seen.items():
            if not key.startswith("name:"):
                for (n, _u) in c:
                    by_name[re.sub(r"[^a-z0-9]+", "", n.lower())].add(key)
        for key in list(self.seen):
            if key.startswith("name:") and len(by_name.get(key[5:], ())) == 1:
                self.alias[key] = next(iter(by_name[key[5:]]))
        # Self-hosted programs have no platform handle, so the same company shows up once per mirror with a different page of its
        # site (diodb: /bug-bounty, projectdiscovery: /security). Same normalised name among those "url:" entries = one program.
        # Platform programs are NOT merged with them: the self-hosted page and the platform page are two places (hosting "both").
        selfhosted = defaultdict(list)
        for key, c in self.seen.items():
            if key.startswith("url:"):
                for (n, _u) in c:
                    selfhosted[re.sub(r"[^a-z0-9]+", "", n.lower())].append(key)
        for norm, keys in selfhosted.items():
            keys = sorted(set(keys))
            if norm and len(keys) > 1:
                for k in keys[1:]:
                    self.alias[k] = keys[0]
        merged = defaultdict(Counter)
        for key, c in self.seen.items():
            merged[self.alias.get(key, key)].update(c)
        for key, c in merged.items():
            names, urls = Counter(), Counter()
            for (n, u), k in c.items():
                if n:
                    names[n] += k
                if u:
                    urls[u] += k
            pick = lambda cnt: sorted(cnt, key=lambda v: (-cnt[v], len(v), v))[0] if cnt else ""   # noqa: E731
            self.final[key] = (pick(names), pick(urls))

    def ident(self, name: str, url: str) -> str:
        """The stable identity of the program that (name, url) belongs to: the same key however the program is spelled, and the same
        from one day to the next (proghistory.py remembers programs by it)."""
        key = program_key(name, url)
        return self.alias.get(key, key)

    def canon(self, name: str, url: str):
        if not (name or url):
            return name, url
        key = program_key(name, url)
        return self.final.get(self.alias.get(key, key), (name, url))


def program_id(name: str, url: str) -> str:
    """Stable short id of a program page (10 hex characters of sha1 over name + url). It names the program in
    data/programs.txt, data/program-scope.tsv and in the web UI / API (site/), and does not change when other programs
    are added or removed, so the files stay small in git."""
    return hashlib.sha1(f"{name}\n{url}".encode("utf-8")).hexdigest()[:10]


def hosting_of(urls) -> str:
    """Hosting of one value (host, IP, app ...) from the program pages that list it: all on platforms -> "platform",
    all on the company's own site -> "self-hosted", both kinds -> "both", no program page known -> "unknown"."""
    kinds = {hosting_of_url(u) for u in urls} - {""}
    if kinds == {"platform"}:
        return "platform"
    if kinds == {"self-hosted"}:
        return "self-hosted"
    return "both" if kinds else "unknown"


# ----------------------------------------------------------------------------- helpers
def log(msg: str) -> None:
    """Print immediately (GitHub Actions shows this in the run log)."""
    print(msg, flush=True)


def fetch(url: str, headers: dict | None = None, min_bytes: int = 100, data: bytes | None = None, with_headers: bool = False):
    """Download with retries. Raises on HTTP errors and on suspiciously small bodies. Returns the body (bytes).

    `headers` adds request headers (API tokens: never logged, never in an error message). `min_bytes` is the smallest
    body accepted: 100 for the mirrors (a tiny answer there means an error page), 2 for APIs that may legitimately
    answer "[]". `data` makes it a POST with that body (HackerOne's GraphQL). `with_headers=True` returns
    (body, response headers) instead, to read cookies. Retries (3 tries, growing pause) happen for network errors and
    for HTTP 429/5xx; 401/403/404 and the like fail at once, because asking again cannot fix them.
    """
    last: Exception | None = None
    for attempt in range(3):
        try:
            hdr = {"User-Agent": "bb-domains-aggregator/3.0"}
            hdr.update(headers or {})
            with urlopen(Request(url, data=data, headers=hdr, method="POST" if data is not None else "GET"), timeout=120) as r:
                body, resp_headers = r.read(), r.headers
            if len(body) < min_bytes:
                raise RuntimeError(f"response too small ({len(body)} bytes)")
            return (body, resp_headers) if with_headers else body
        except HTTPError as e:
            last = RuntimeError(f"HTTP {e.code} {e.reason}")
            if e.code not in (429, 500, 502, 503, 504):
                break
            time.sleep(min(30, int(e.headers.get("Retry-After", "") or 0) or 5 * (attempt + 1)))
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{url}: {last}")


def first_working(urls, parse):
    """Try each URL; return parse(bytes) of the first one that yields a non-empty list."""
    errors = []
    for u in urls:
        try:
            rows = parse(fetch(u))
            if rows:
                return rows
            errors.append(f"{u}: no rows")
        except Exception as e:  # noqa: BLE001
            errors.append(str(e))
    raise RuntimeError("; ".join(errors))


def write_list(path: Path, items) -> None:
    """Write a set of strings as a sorted, duplicate-free text file, one per line (atomic: temp file then rename)."""
    items = sorted(set(items))                 # one entry per line, always
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    tmp.replace(path)


def read_set(path: Path):
    """Lines of a text file as a set, or None when the file does not exist (None means "no diff base", not "empty")."""
    if not path.is_file():
        return None
    return {l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()}


# ----------------------------------------------------------------------------- public suffix list
# The Public Suffix List (publicsuffix.org) says which endings are "registrable boundaries": for www.bbc.co.uk the
# suffix is co.uk, so the registrable domain (our "apex") is bbc.co.uk. We use only the ICANN section, so platform
# tenants (foo.github.io, x.s3.amazonaws.com) collapse to github.io / amazonaws.com instead of being separate apexes.
class PSL:
    """Public Suffix List, ICANN section only (so foo.github.io still collapses to github.io)."""

    def __init__(self, text: str):
        self.rules, self.wild, self.exc = set(), set(), set()
        icann = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("// ===BEGIN ICANN"):
                icann = True
                continue
            if s.startswith("// ===END ICANN"):
                icann = False
                continue
            if not icann or not s or s.startswith("//"):
                continue
            s = s.split()[0].lower()
            try:
                s = ".".join(l if l.isascii() else l.encode("idna").decode("ascii") for l in s.split("."))
            except UnicodeError:
                continue
            if s.startswith("!"):
                self.exc.add(s[1:])
            elif s.startswith("*."):
                self.wild.add(s[2:])
            else:
                self.rules.add(s)
        # every TLD, including ones the list only defines through second-level rules (e.g. "za" via co.za)
        self.tlds = {r.rsplit(".", 1)[-1] for r in self.rules | self.wild | self.exc}
        # Registries use com./co./org./... second levels the list does not always include (co.br, co.nl,
        # com.be, com.nz, com.ru, com.de ...). Without this, transunion.co.br would collapse to "co.br".
        self.pseudo = {"com", "co", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "gouv", "mil", "nom", "sch", "ltd"}

    def _suffix_len(self, labels) -> int:
        """Number of trailing labels that form the public suffix of this host (1 for "com", 2 for "co.uk").
        Follows the official algorithm: longest matching rule wins; "*.x" rules match any label under x;
        "!x" exception rules cut one label off. The pseudo-suffix fallback is explained in __init__."""
        n, best = len(labels), 1
        for i in range(n):
            cand = ".".join(labels[i:])
            if cand in self.exc:
                return n - i - 1
            if cand in self.rules:
                best = max(best, n - i)
            if i + 1 < n and ".".join(labels[i + 1:]) in self.wild:
                best = max(best, n - i)
        if best == 1 and n >= 2 and labels[-2] in self.pseudo and len(labels[-1]) == 2:
            best = 2                       # not in the list, but behaves like a public suffix
        return best

    def registrable(self, host: str):
        """Registrable domain of host, or None when host is itself a public suffix."""
        labels = host.split(".")
        sl = self._suffix_len(labels)
        if len(labels) <= sl:
            return None
        return ".".join(labels[-(sl + 1):])


def load_psl() -> PSL:
    """Fresh list from publicsuffix.org; if that fails, the copy committed in config/public_suffix_list.dat."""
    try:
        text = fetch(PSL_URL).decode("utf-8", errors="replace")
        psl = PSL(text)
        if len(psl.rules) < 1000:
            raise RuntimeError("downloaded list looks incomplete")
        log(f"[*] Public Suffix List: fresh download ({len(psl.rules)} rules)")
        return psl
    except Exception as e:  # noqa: BLE001
        vendored = CONFIG / "public_suffix_list.dat"
        log(f"[!] PSL download failed ({e}); using {vendored}")
        return PSL(vendored.read_text(encoding="utf-8"))


# ----------------------------------------------------------------------------- denylist
def load_denylist() -> set:
    """config/denylist.txt: one host/domain per line ("#" starts a comment). Entries remove that host and everything
    below it from all lists. Off by default (the shipped file has every line commented out)."""
    path = CONFIG / "denylist.txt"
    deny = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                deny.add(line)
    return deny


def is_denied(host: str, deny: set) -> bool:
    """True when host or any parent domain of it is in the denylist."""
    if not deny:
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in deny for i in range(len(parts)))


# ----------------------------------------------------------------------------- sources
# A source returns rows: [(raw_host, status, program, program_url)] with status in {"paying", "non-paying", "unknown"}.
# program / program_url say whose scope the entry came from (empty for the flat arkadiyt lists).
def _c(v) -> str:
    return re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else ""


def _prog(p) -> tuple:
    """(program name, program url) of a platform program record; tolerant of missing fields."""
    if not isinstance(p, dict):
        return "", ""
    name = _c(p.get("name") or p.get("program_name") or p.get("project") or p.get("handle") or "")
    return name, _c(p.get("url") or p.get("policy_url") or "")


def _norm(r) -> tuple:
    r = tuple(r)
    return (r + ("",) * (4 - len(r)))[:4]


def src_arkadiyt():
    """arkadiyt/bounty-targets-data data/domains.txt: one in-scope host per line, all platforms, NO bounty flag."""
    def parse(b):
        return [(l.strip(), "unknown", "", "") for l in b.decode("utf-8", "replace").splitlines() if l.strip()]
    return first_working([f"{RAW}/arkadiyt/bounty-targets-data/{br}/data/domains.txt" for br in ("main", "master")], parse)


def src_arkadiyt_wildcards():
    """arkadiyt/bounty-targets-data data/wildcards.txt: wildcard bases without the "*." (we put it back), no flag."""
    def parse(b):
        rows = []
        for l in b.decode("utf-8", "replace").splitlines():
            l = l.strip()
            if l:
                rows.append((l if l.startswith("*.") else "*." + l, "unknown", "", ""))
        return rows
    return first_working([f"{RAW}/arkadiyt/bounty-targets-data/{br}/data/wildcards.txt" for br in ("main", "master")], parse)


# --- per-platform files from arkadiyt/bounty-targets-data: real bounty flags -----------------------
# targets.in_scope gives the targets. targets.out_of_scope (e.g. Intigriti "*.aikido.dev") is NOT a target: it comes along as rows with
# status OOS, which the run keeps apart (data/program-out-of-scope.tsv) so the website can say "excluded" instead of "unknown".
# Raw target text goes to scopeparse unchanged; these parsers only (1) work out the bounty status and
# (2) tell scopeparse when the platform itself says "this is a mobile app" (prefix "app:") or when a
# target is not a network target at all (hardware, smart contract addresses).
H1_APP_TYPES = directsources.H1_APP_TYPES
H1_SKIP_TYPES = directsources.H1_SKIP_TYPES
OOS = directsources.OOS            # status of a row that is an EXCLUSION of its program (never a target; see "out of scope" below)


def _text(v):
    """A non-empty stripped string, else None (platform fields may be missing, null or not strings)."""
    return v.strip() if isinstance(v, str) and v.strip() else None


def _scope(p) -> list:
    """The in-scope asset list of one program record."""
    t = p.get("targets") if isinstance(p, dict) else None
    return (t or {}).get("in_scope") or []


def _excluded(p) -> list:
    """The out-of-scope asset list of one program record (the program's exclusions)."""
    t = p.get("targets") if isinstance(p, dict) else None
    v = (t or {}).get("out_of_scope")
    return [a for a in v if a] if isinstance(v, list) else []


def _platform(name: str, parse):
    """Download arkadiyt's <name>_data.json (branch main, then master) and run `parse` on the decoded JSON."""
    return first_working([f"{RAW}/arkadiyt/bounty-targets-data/{br}/data/{name}_data.json" for br in ("main", "master")],
                         lambda b: parse(json.loads(b)))


def src_hackerone():
    """HackerOne: paying when the program offers bounties AND the asset is eligible_for_bounty."""
    def parse(data):
        rows = set()
        for p in data:
            offers = bool(p.get("offers_bounties"))
            pn, pu = _prog(p)
            for a in _scope(p):
                raw, typ = _text(a.get("asset_identifier")), a.get("asset_type")
                if not raw or typ in H1_SKIP_TYPES:
                    continue
                if typ in H1_APP_TYPES:
                    raw = "app:" + raw
                paying = offers and bool(a.get("eligible_for_bounty", True))
                rows.add((raw, "paying" if paying else "non-paying", pn, pu))
            for a in _excluded(p):
                raw, typ = _text(a.get("asset_identifier")) if isinstance(a, dict) else _text(a), a.get("asset_type") if isinstance(a, dict) else None
                if raw and typ not in H1_SKIP_TYPES:
                    rows.add(((("app:" + raw) if typ in H1_APP_TYPES else raw), OOS, pn, pu))
        return sorted(rows)
    return _platform("hackerone", parse)


def src_bugcrowd():
    """Bugcrowd: paying when the program's max_payout is above 0. The target text may be in target, uri or ipAddress."""
    def parse(data):
        rows = set()
        for p in data:
            paying = (p.get("max_payout") or 0) > 0
            pn, pu = _prog(p)
            for a in _scope(p):
                raw = _text(a.get("target")) or _text(a.get("uri")) or _text(a.get("ipAddress"))
                typ = a.get("type")
                if not raw or typ in {"hardware", "iot"}:
                    continue
                if typ in {"android", "ios"}:
                    raw = "app:" + raw
                rows.add((raw, "paying" if paying else "non-paying", pn, pu))
            for a in _excluded(p):
                raw = (_text(a.get("target")) or _text(a.get("uri")) or _text(a.get("ipAddress"))) if isinstance(a, dict) else _text(a)
                if raw and (a.get("type") if isinstance(a, dict) else None) not in {"hardware", "iot"}:
                    rows.add((raw, OOS, pn, pu))
        return sorted(rows)
    return _platform("bugcrowd", parse)


def src_intigriti():
    """Intigriti: paying when max_bounty > 0 and the asset's impact is not "No Bounty"."""
    def parse(data):
        rows = set()
        for p in data:
            program_pays = ((p.get("max_bounty") or {}).get("value") or 0) > 0
            pn, pu = _prog(p)
            for a in _scope(p):
                raw, typ = _text(a.get("endpoint")), a.get("type")
                if not raw or typ == "device":
                    continue
                if typ in {"android", "ios"}:
                    raw = "app:" + raw
                paying = program_pays and a.get("impact") != "No Bounty"
                rows.add((raw, "paying" if paying else "non-paying", pn, pu))
            for a in _excluded(p):
                raw = _text(a.get("endpoint")) if isinstance(a, dict) else _text(a)
                if raw and (a.get("type") if isinstance(a, dict) else None) != "device":
                    rows.add((raw, OOS, pn, pu))
        return sorted(rows)
    return _platform("intigriti", parse)


def src_yeswehack():
    """YesWeHack: paying when the program's max_bounty is above 0."""
    def parse(data):
        rows = set()
        for p in data:
            paying = (p.get("max_bounty") or 0) > 0
            pn, pu = _prog(p)
            for a in _scope(p):
                raw, typ = _text(a.get("target")), (a.get("type") or "").lower()
                if not raw:
                    continue
                if typ.startswith("mobile"):
                    raw = "app:" + raw
                rows.add((raw, "paying" if paying else "non-paying", pn, pu))
            for a in _excluded(p):
                raw = _text(a.get("target")) if isinstance(a, dict) else _text(a)
                if raw:
                    rows.add((raw, OOS, pn, pu))
        return sorted(rows)
    return _platform("yeswehack", parse)


def _chaos_rows(programs):
    """Chaos program records -> rows. Bounty flag comes from the program's "bounty" field."""
    rows = []
    for p in programs:
        # a file without the flag gives "unknown", never a silent "non-paying"
        status = "unknown" if "bounty" not in p else ("paying" if p["bounty"] else "non-paying")
        pn, pu = _prog(p)
        for d in p.get("domains") or []:
            rows.append((d, status, pn, pu))
    return rows


def _parse_chaos_yaml(text: str):
    """Minimal reader for src/data.yaml (programs: - name / url / bounty / swag / domains), stdlib has no YAML."""
    programs, cur, in_domains = [], None, False
    for line in text.splitlines():
        line = line.split(" #", 1)[0].rstrip()
        s = line.strip()
        if not s or s.startswith("#") or s == "programs:":
            continue
        m = re.match(r"^-\s+name:\s*(.*)$", s)
        if m:                                              # new program
            cur = {"name": m.group(1).strip("'\" "), "domains": []}
            programs.append(cur)
            in_domains = False
            continue
        if cur is None:
            continue
        m = re.match(r"^(bounty|swag):\s*(true|false)\s*$", s, re.I)
        if m:
            cur[m.group(1).lower()] = m.group(2).lower() == "true"
            in_domains = False
            continue
        m = re.match(r"^domains:\s*(.*)$", s)
        if m:
            rest = m.group(1).strip()
            in_domains = rest == ""
            if rest.startswith("["):                       # domains: [] or domains: [a.com, b.com]
                cur["domains"] += [d.strip().strip("'\"") for d in rest.strip("[]").split(",") if d.strip()]
            continue
        m = re.match(r"^url:\s*(.*)$", s)
        if m:
            cur["url"] = m.group(1).strip("'\" ")
            in_domains = False
            continue
        if re.match(r"^[A-Za-z_]+:", s):                   # any other key
            in_domains = False
            continue
        m = re.match(r"^-\s+(.+)$", s)
        if m and in_domains:
            cur["domains"].append(m.group(1).strip().strip("'\""))
    return programs


def src_chaos():
    """dist/data.json is generated from src/data.yaml (the source file); either works, JSON is tried first."""
    def parse(b):
        try:
            data = json.loads(b)
            return _chaos_rows(data.get("programs", []))
        except ValueError:
            return _chaos_rows(_parse_chaos_yaml(b.decode("utf-8", "replace")))
    base = f"{RAW}/projectdiscovery/public-bugbounty-programs/main"
    return first_working([f"{base}/dist/data.json", f"{base}/src/data.yaml"], parse)


def src_diodb(psl: PSL):
    """Registrable domains of the program's own pages. Policy-page hosts themselves are not scope."""
    def parse(b):
        rows = {}
        for p in json.loads(b):
            status = "paying" if p.get("offers_bounty") in ("yes", "partial") else "non-paying"
            pn, pu = _prog(p)
            for field in ("policy_url", "contact_url", "securitytxt_url", "hall_of_fame"):
                url = p.get(field) or ""
                if "://" not in url:
                    continue
                host = urlparse(url).hostname
                apex = psl.registrable(host) if host else None
                if not apex or apex in NON_SCOPE or (host in NON_SCOPE):
                    continue
                if apex not in rows or (rows[apex][0] != "paying" and status == "paying"):
                    rows[apex] = (status, pn, pu)
        return [(a, st, n, u) for a, (st, n, u) in rows.items()]
    return first_working([f"{RAW}/disclose/diodb/{br}/program-list.json" for br in ("master", "main")], parse)


SELF_HOSTED_FILE = ROOT / "config" / "self-hosted-programs.tsv"


def src_selfhosted():
    """Programs the companies run THEMSELVES (Google, Microsoft, Zoho ...), listed by you in config/self-hosted-programs.tsv.
    No platform publishes their scope, so the only way to get it is to write it down once. One line per scope entry,
    4 columns separated by a TAB (2 or more spaces also work):   program <TAB> program_url <TAB> bounty <TAB> scope entry
    bounty = paying | non-paying | unknown. The scope entry is anything scopeparse understands (*.google.com, a URL, an IP
    range, "a.com, b.com", a sentence ...). Lines that start with # and empty lines are ignored. Without the file, or with
    no active line, the source is simply "skipped". The program URL is what makes data/programs.txt call it self-hosted."""
    if not SELF_HOSTED_FILE.is_file():
        raise directsources.Skip("no config/self-hosted-programs.tsv")
    rows = []
    for n, line in enumerate(SELF_HOSTED_FILE.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) < 4:
            # Editors and chat windows often turn the tabs into spaces. Accept that too: the line is read by its shape,
            #   program name ... https://url ... paying|non-paying|unknown ... scope entry
            m = re.match(r"^(.+?)\s+(https?://\S+)\s+(paying|non-paying|unknown)\s+(.+)$", line.strip())
            if m:
                cols = [g.strip() for g in m.groups()]
        if len(cols) < 4 or not cols[0] or not cols[3] or cols[2] not in ("paying", "non-paying", "unknown", OOS):
            raise ValueError(f"config/self-hosted-programs.tsv line {n}: expected program, url, paying|non-paying|unknown, scope entry (separated by a TAB or by 2+ spaces)")
        rows.append((cols[3], cols[2], cols[0], cols[1]))
    if not rows:
        raise directsources.Skip("config/self-hosted-programs.tsv has no active line")
    return rows


SELF_PAGES_FILE = ROOT / "config" / "self-hosted-pages.tsv"
SELF_TEXT_DIR = ROOT / "config" / "self-hosted-text"


def _bounty_word(w: str, where: str) -> str:
    w = (w or "unknown").strip().lower()
    if w not in ("paying", "non-paying", "unknown"):
        raise ValueError(f"{where}: bounty must be paying, non-paying or unknown (got {w!r})")
    return w


def src_selfhosted_pages():
    """AUTOMATIC self-hosted programs: you list the pages once, the run reads them every day.

    config/self-hosted-pages.tsv, one line per program (TAB separated; 2+ spaces also work):
        program <TAB> program_url <TAB> paying|non-paying|unknown <TAB> page_url [<TAB> another_page_url ...]
    The page url may be left out when it is the program url. Several pages can be given (many programs keep the scope on one
    page and the exclusions on another). Each page is downloaded, its text is read by textscope (the same reader that
    reads asset descriptions of the platforms): lists of hosts, wildcards, URLs and IP ranges in an "in scope" section
    become targets, an "out of scope" section becomes exclusions, hosts only mentioned in a sentence become guesses
    (maybe.txt). Pages that are drawn by JavaScript (bughunters.google.com is one) give no text to a plain download:
    the run says so in the Sources table, and you paste that page's text into config/self-hosted-text/ instead.
    Without the file the source is "skipped"."""
    if not SELF_PAGES_FILE.is_file():
        raise directsources.Skip("no config/self-hosted-pages.tsv")
    rows, empty, failed, n_pages = [], [], [], 0
    for n, line in enumerate(SELF_PAGES_FILE.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t") if c.strip()]
        if len(cols) < 3:                                   # tabs turned into spaces
            cols = [c.strip() for c in re.split(r"\s{2,}", line.strip()) if c.strip()]
        if len(cols) < 3:
            m = re.match(r"^(.+?)\s+(https?://\S+)\s+(paying|non-paying|unknown)((?:\s+https?://\S+)*)\s*$", line.strip())
            if m:
                cols = [m.group(1), m.group(2), m.group(3)] + m.group(4).split()
        if len(cols) < 3 or not re.match(r"https?://", cols[1]):
            raise ValueError(f"config/self-hosted-pages.tsv line {n}: expected program, program url, paying|non-paying|unknown, [page url ...]")
        prog, purl, bounty = cols[0], cols[1], _bounty_word(cols[2], f"config/self-hosted-pages.tsv line {n}")
        for page in (cols[3:] or [purl]):
            n_pages += 1
            try:
                html = fetch(page, min_bytes=50).decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                failed.append(f"{page} ({str(e)[:80]})")
                continue
            got = textscope.rows_from_text(textscope.page_text(html), bounty, prog, purl)
            if not any(r[1] != OOS for r in got):
                empty.append(page)
            rows += got
    if n_pages and len(failed) == n_pages:
        raise RuntimeError("none of the self-hosted pages could be downloaded: " + "; ".join(failed[:3]))
    notes = []
    if failed:
        notes.append(f"{len(failed)} page(s) not downloaded today: {failed[0]}")
    if empty:
        notes.append(f"no scope found on {empty[0]}" + (f" (+{len(empty) - 1} more)" if len(empty) > 1 else "")
                     + ": probably drawn by JavaScript; copy the page text into config/self-hosted-text/ (see README)")
    if not n_pages:
        raise directsources.Skip("config/self-hosted-pages.tsv has no active line")
    if not rows and notes:                                          # nothing at all: say WHY in the warning instead of a bare "returned no rows"
        raise RuntimeError("; ".join(notes))
    if notes:
        directsources.NOTES["self-hosted-pages"] = "; ".join(notes)
    return rows


def src_selfhosted_text():
    """PASTED page text: the reliable way for self-hosted pages a script cannot read (JavaScript, logins, PDFs).
    Open the program page in your browser, select all (Ctrl+A), copy, and paste into a new file config/self-hosted-text/<name>.txt.
    Put these lines at the top (they are the only lines the script treats specially; everything else is the page text):
        # program: Google VRP
        # url: https://bughunters.google.com/
        # bounty: paying            (paying | non-paying | unknown; default unknown)
    The text is read by textscope exactly like a platform's asset description. Re-paste only when the page changes."""
    if not SELF_TEXT_DIR.is_dir():
        raise directsources.Skip("no config/self-hosted-text folder")
    rows, files = [], sorted(SELF_TEXT_DIR.glob("*.txt"))
    for f in files:
        meta, body = {}, []
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^#\s*(program|url|bounty)\s*:\s*(.+?)\s*$", line, re.I)
            if m and m.group(1).lower() not in meta and not body:
                meta[m.group(1).lower()] = m.group(2)
            else:
                body.append(line)
        prog = meta.get("program") or f.stem.replace("-", " ").replace("_", " ").title()
        rows += textscope.rows_from_text("\n".join(body), _bounty_word(meta.get("bounty"), f"config/self-hosted-text/{f.name}"), prog, meta.get("url", ""))
    if not files:
        raise directsources.Skip("config/self-hosted-text has no .txt file")
    return rows


def src_immunefi(psl: PSL):
    def parse(b):
        rows = set()
        for prog in json.loads(b):
            if not isinstance(prog, dict):
                continue
            pn = _c(prog.get("project") or prog.get("name") or prog.get("id") or "")
            pu = f"https://immunefi.com/bounty/{_c(prog.get('id'))}/" if prog.get("id") else ""
            for a in (prog.get("assets") or []):
                url = (a.get("url") or "") if isinstance(a, dict) else ""
                if github_project(url):
                    rows.add((url.strip(), "paying", pn, pu))
            urls = [a.get("url") or "" for a in (prog.get("assets") or []) if isinstance(a, dict)]
            n_assets = len(urls)
            urls += [prog.get("websiteUrl") or "", prog.get("githubUrl") or ""]    # githubUrl is NOT treated as scope
            for i, url in enumerate(urls):
                if not url:
                    continue
                u = urlparse(url if "://" in url else "https://" + url)
                host = u.hostname
                if not host:
                    continue
                apex = psl.registrable(host)
                if host in NON_SCOPE or (apex and apex in NON_SCOPE):
                    continue
                # an ASSET url with a real path is a scope in its own right (".../docs-api"): keep the whole address, which
                # becomes an entry of urls.txt (the first version kept only the host and lost the path). Block-explorer style
                # paths (/address/0x...) point at a contract, not a web target, and stay host-only.
                path = u.path.rstrip("/")
                if i < n_assets and path and not re.search(r"/(?:address|token|tx|account|contract)s?/", path, re.I):
                    rows.add((url.strip(), "paying", pn, pu))
                else:
                    rows.add((host, "paying", pn, pu))
        return sorted(rows)
    return first_working(["https://immunefi.com/public-api/bounties.json"], parse)


# ----------------------------------------------------------------------------- state (carry-forward)
# state/<source>.tsv holds the rows of the last GOOD download of each source (tab separated:
# raw entry, bounty status, program, program url). Older copies with only two columns are still read.
# Sources were renamed once (2026-11-06). Their stored copies (state/<old>.tsv / .meta) are renamed on first sight, so the
# carried-forward data, the stale-mirror clock and the day-to-day diffs continue without a "everything is new" day.
RENAMED_SOURCES = {"arkadiyt": "arkadiyt-domains", "hackerone": "arkadiyt-hackerone", "bugcrowd": "arkadiyt-bugcrowd",
                   "intigriti": "arkadiyt-intigriti", "yeswehack": "arkadiyt-yeswehack", "chaos": "projectdiscovery",
                   "immunefi": "immunefi-direct"}


def migrate_source_names() -> None:
    for old, new in RENAMED_SOURCES.items():
        for ext in (".tsv", ".meta"):
            a, b = STATE / f"{old}{ext}", STATE / f"{new}{ext}"
            if a.is_file() and not b.is_file():
                a.rename(b)


def load_state(name: str):
    p = STATE / f"{name}.tsv"
    if not p.is_file():
        return None
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if "\t" in line:
            parts = line.split("\t")
            rows.append(_norm(parts if len(parts) >= 4 else (parts[0], parts[-1])))   # older copies: raw, status
    return rows


CARRY_DAYS = 7                       # a program that cannot be read is kept this many days in a row, then it counts as removed


def load_carry(name: str) -> dict:
    """state/<source>.carry = "program url<TAB>days in a row it could not be read": how long a failing program has been kept."""
    p = STATE / f"{name}.carry"
    out = {}
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            u, _, n = line.partition("\t")
            if u and n.strip().isdigit():
                out[u] = int(n)
    return out


def save_carry(name: str, counts: dict) -> None:
    p = STATE / f"{name}.carry"
    if counts:
        STATE.mkdir(parents=True, exist_ok=True)
        p.write_text("".join(f"{u}\t{n}\n" for u, n in sorted(counts.items())), encoding="utf-8")
    elif p.is_file():
        p.unlink()


def save_state(name: str, rows) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = STATE / f"{name}.tsv.part"
    tmp.write_text("\n".join("\t".join(r) for r in sorted(set(rows))) + "\n", encoding="utf-8")
    tmp.replace(STATE / f"{name}.tsv")


def _staleness(name: str, rows) -> str:
    """Remember when this source's content last changed; return a warning text when it has been frozen too long.

    state/<name>.meta = "<sha1 of the sorted rows>\t<date the content first had this hash>". It is rewritten only when
    the content changes, so a frozen source does not even create a git diff. Returns "" when all is well."""
    digest = hashlib.sha1("\n".join("\t".join(r) for r in sorted(set(rows))).encode("utf-8")).hexdigest()
    meta = STATE / f"{name}.meta"
    old = meta.read_text(encoding="utf-8").split() if meta.is_file() else []
    if len(old) == 2 and old[0] == digest:
        since = old[1]
    else:
        since = DATE
        meta.write_text(f"{digest}\t{DATE}\n", encoding="utf-8")
    limit = STALE_DAYS.get(name)
    days = (date.fromisoformat(DATE) - date.fromisoformat(since)).days
    if limit and days >= limit:
        return f"content unchanged for {days} days (since {since}); the publisher may have stopped updating"
    return ""


def run_source(name: str, fn, failed: list, health: list | None = None, optional: bool = False, warnings: list | None = None):
    """Return rows for this source: fresh ones, or the last good copy when the download is bad.

    A download is "bad" when it raises, returns nothing, or returns fewer than MIN_RATIO % of the rows of the last
    good copy. Problems are appended to `failed` (-> data/failed-sources.txt, turns the run red) - or, for an
    `optional` source (the direct platform sources), to `warnings` (shown in stats.txt, run stays green) unless
    BB_DIRECT_STRICT=1. A source that is not configured (directsources.Skip, e.g. no API token) is neither: it is
    listed as "skipped" and its stored copy is left alone. When `health` is given, one dict per source is appended
    for the "Sources today" table of stats.txt: name, status, rows, seconds, note.
    """
    problems = warnings if (optional and not DIRECT_STRICT and warnings is not None) else failed
    prev = load_state(name)
    reason = None
    rows = []
    started = time.monotonic()
    try:
        rows = [_norm(r) for r in fn()]
        if not rows:
            reason = "returned no rows"
        elif prev and len(rows) * 100 < len(prev) * MIN_RATIO:
            reason = f"shrank to {len(rows)} rows from {len(prev)} (< {MIN_RATIO}%)"
    except directsources.Skip as e:
        log(f"    {name}: skipped ({e})")
        if health is not None:
            health.append({"name": name, "status": "skipped", "rows": 0, "secs": time.monotonic() - started, "note": str(e)[:90]})
        return []
    except Exception as e:  # noqa: BLE001
        reason = str(e)[:300]
    secs = time.monotonic() - started
    if reason is None:
        # PROGRAMS WE COULD NOT READ TODAY keep their rows from the last good run (at most CARRY_DAYS days in a row), so one page that
        # fails (layout change, throttling) is not reported as "removed" for every host of that program.
        keys = directsources.CARRY.pop(name, set())
        if keys and prev:
            counts = load_carry(name)
            keep = {k for k in keys if counts.get(k, 0) < CARRY_DAYS}
            carried = [r for r in prev if r[3] in keep]
            rows = rows + carried
            save_carry(name, {k: counts.get(k, 0) + 1 for k in keys})
            dropped = len(keys) - len(keep)
            if dropped:
                directsources.NOTES[name] = directsources.NOTES.get(name, "") + f"; {dropped} program(s) failed for over {CARRY_DAYS} days in a row, so they now count as removed"
        elif load_carry(name):                                    # everything was readable today: forget the old counters
            save_carry(name, {})
        save_state(name, rows)
        note = _staleness(name, rows)
        partial = directsources.NOTES.pop(name, "")      # direct sources: "3 of 210 programs skipped ..."
        minor = name in directsources.MINOR              # a few skipped programs: shown, but not a warning
        directsources.MINOR.discard(name)
        if partial:
            note = f"{note}; {partial}" if note else partial
        log(f"    {name}: OK ({len(rows)} rows, {secs:.1f}s){'  [!] ' + note if note else ''}")
        if note and warnings is not None and not (minor and note == partial):
            warnings.append(f"{name}: {note}")
        if health is not None:
            health.append({"name": name, "status": "ok", "rows": len(rows), "secs": secs, "note": note})
        return rows
    if prev:
        log(f"    [!] {name}: {reason} -> carried forward {len(prev)} rows from the last good run")
        problems.append(f"{name}: {reason} (carried forward {len(prev)} rows)")
        if health is not None:
            health.append({"name": name, "status": "carried forward", "rows": len(prev), "secs": secs, "note": reason[:80]})
        return prev
    log(f"    [!] {name}: {reason} and no earlier copy exists")
    problems.append(f"{name}: {reason} (no earlier copy, source is empty today)")
    if health is not None:
        health.append({"name": name, "status": "unavailable" if problems is not failed else "FAILED", "rows": 0, "secs": secs, "note": reason[:80]})
    return []


# ----------------------------------------------------------------------------- classification
# ASSETS: output file name stem  ->  internal "kind" code used by scopeparse (Hit.kind) and by Collector.meta.
# Every asset type gets the same family of files in data/:
#     <asset>.txt           everything of this type
#     <asset>-paying.txt    the ones whose bounty status is paying (or unknown while BB_UNKNOWN_PAYING=1)
#     <asset>-new.txt       in today's list but not in the previous snapshot
#     <asset>-removed.txt   in the previous snapshot but not in today's list
# Adding an asset type = add it here, give scopeparse a Hit.kind for it, and add it to the README table.
ASSETS = {"apex": "apex", "subdomains": "sub", "wildcards": "wildcard", "urls": "url", "apis": "api", "ips": "ip", "asn": "asn", "github": "github",
          "repos-other": "repo", "apps": "app", "patterns": "pattern", "internal-hosts": "internal", "maybe": "maybe"}
# OVERLAY lists repeat values that are already in another list (a wildcard base is also apex/subdomain; an API is also a
# subdomain or a url). They get the same four files but are left out of every total, so nothing is counted twice.
OVERLAY = {"wildcards", "apis"}
STEM = {kind: stem for stem, kind in ASSETS.items()}          # kind code -> file name stem
OOS_TEXT_MAX = 200        # longest plain-text exclusion kept ("Denial of service attacks" yes, a whole policy paragraph no)
OOS_TEXT_PER_PROGRAM = 40 # at most this many plain-text exclusions per program are written
# scopeparse hit kinds that are not asset types themselves ("host" becomes apex or subdomains, see asset_of_hit)
QUIET_RULES = {"store-url", "userinfo", "from-description", "declared-api"}       # normal handling, not worth listing in recovered.txt as a repair
# Files written by older versions of this script; deleted automatically so data/ never holds stale copies.
OLD_NAMES = ("new-paying.txt", "new-review.txt") + tuple(
    f"{pre}-{k}.txt" for k in ("apex", "subdomains", "wildcards", "ips", "github", "apps") for pre in ("new", "removed"))


def asset_of_hit(h) -> str:
    """Asset type (file name stem) a scopeparse Hit ends up in. A "host" is apex.txt when it equals its apex."""
    if h.kind == "host":
        return "apex" if h.value == h.apex else "subdomains"
    return STEM[h.kind]


# An address "looks like an API" when a host label says so (api.x.com, x-api.y.com, apis.x.com, yahooapis.com, graphql.x.com)
# or a path segment does (/api/, /apis, /graphql, /rest, /v1/). Deliberately a little generous: apis.txt is a lead list.
_API_HOST_RE = re.compile(r"(?:^|[.-])(?:apis?|graphql|gql|grpc|rest|openapi|swagger)\d*(?=[.-]|$)|[a-z]{3,}apis?(?=\.|$)", re.I)
_API_PATH_RE = re.compile(r"/(?:apis?|graphql|gql|grpc|rest|rpc|v\d+(?:\.\d+)?|openapi|swagger)(?=/|$)", re.I)


def looks_like_api(value: str) -> bool:
    """True for a host / wildcard / URL value that names an API (see the comment above)."""
    host = value.split("://", 1)[-1]
    path = ""
    if "/" in host:
        host, path = host.split("/", 1)
        path = "/" + path
    host = host.split(":")[0].lstrip("*.")
    return bool(_API_HOST_RE.search(host) or (path and _API_PATH_RE.search(path)))


class Collector:
    """Merges every hit of every source into one view: for each asset type and value, which sources listed it,
    with which bounty status, for which programs, and how the source wrote it.

    meta[kind][value] = {"status": set of statuses, "sources": set, "programs": set, "urls": set, "raws": set}
    """

    def __init__(self, deny: set):
        self.deny = deny
        self.listed = set()                # hosts a source lists itself (as opposed to apexes only derived from a subdomain)
        # programs[(name, url)] = {"status": set, "sources": set, "hosts": set}: one entry per program page, for data/programs.txt
        # "items" maps (kind, value) -> bounty statuses given by this program for that value (for data/program-scope.tsv)
        self.programs = defaultdict(lambda: {"status": set(), "sources": set(), "hosts": set(), "items": {}})
        self.meta = {k: defaultdict(lambda: {"status": set(), "sources": set(), "programs": set(), "urls": set(), "raws": set()})
                     for k in ASSETS.values()}
        # what each program EXCLUDES (out of scope): oos[(name, url)] = {(asset stem, value)}; oos_text = plain-language exclusions
        # that are not an asset at all ("all third-party services", "social engineering" ...). Never part of any target file.
        self.oos = defaultdict(set)
        self.oos_text = defaultdict(set)

    def add_exclusion(self, raw: str, prog: str, purl: str, psl) -> None:
        """One out-of-scope entry of a program: understood like any scope entry (host, wildcard, IP range, URL ...); when it is
        free text it is kept as text (short ones only). A crash of the parser here is never fatal."""
        key = (prog, purl)
        try:
            parsed = scopeparse.parse_entry(raw, psl)
        except Exception:  # noqa: BLE001
            parsed = None
        if parsed is not None and parsed.hits:
            for h in parsed.hits:
                self.oos[key].add((asset_of_hit(h), h.value))
        elif parsed is None or not parsed.blank:
            text = _c(raw)
            if 3 <= len(text) <= OOS_TEXT_MAX:
                self.oos_text[key].add(text)

    def put(self, kind: str, value: str, status: str, source: str, prog: str = "", purl: str = "", raw: str = "") -> None:
        if prog or purl:
            pr = self.programs[(prog, purl)]
            pr["status"].add(status)
            pr["sources"].add(source)
            pr["hosts"].add(value)
            pr["items"].setdefault((kind, value), set()).add(status)
        m = self.meta[kind][value]
        m["status"].add(status)
        m["sources"].add(source)
        if prog:
            m["programs"].add(prog)
        if purl:
            m["urls"].add(purl)
        if raw and _c(raw) != value:
            m["raws"].add(_c(raw)[:120])

    def add_hit(self, h, status: str, source: str, prog: str = "", purl: str = "", raw: str = "") -> None:
        """Record one scopeparse Hit. Hosts and wildcards need extra care:
        a "*.example.com" wildcard is stored as a wildcard AND as apex/subdomain; a subdomain also records its apex.
        Denylisted hosts are dropped. Everything else maps one-to-one to an asset type."""
        k = h.kind
        ctx = (status, source, prog, purl, raw)
        if k in ("host", "wildcard"):
            if is_denied(h.value, self.deny):
                return
            self.listed.add(h.value)
            if k == "wildcard":
                self.put("wildcard", h.value, *ctx)
            kind = "apex" if h.value == h.apex else "sub"
            self.put(kind, h.value, *ctx)
            if kind == "sub" and h.apex and not is_denied(h.apex, self.deny):
                self.put("apex", h.apex, *ctx)
        else:                                  # ip, github, app, repo, pattern, internal, maybe
            self.put(k, h.value, *ctx)
        # apis.txt: an overlay of everything that is an API. Either the platform said so (asset type API -> rule "declared-api"),
        # or the address looks like one (see looks_like_api). Exclusions never come through here; maybe/ip/app are not APIs.
        if k in ("host", "wildcard", "url") and not (is_denied(h.value, self.deny)) and ("declared-api" in h.rule or looks_like_api(h.value)):
            self.put("api", h.value, *ctx)

    # --- views
    @staticmethod
    def bounty(m) -> str:
        """Best bounty status over all sources: paying > non-paying > unknown (a definite answer beats "unknown")."""
        if "paying" in m["status"]:
            return "paying"
        if "non-paying" in m["status"]:      # a definite answer beats "unknown"
            return "non-paying"
        return "unknown"

    def is_paying(self, m) -> bool:
        """Does this value belong in the *-paying files? (paying, or unknown when BB_UNKNOWN_PAYING=1)"""
        b = self.bounty(m)
        return b == "paying" or (b == "unknown" and UNKNOWN_PAYING)

    @property
    def master(self) -> set:
        """Every distinct host / IP / URL / pattern, whatever its kind: the host column of review-by-source.txt."""
        return {v for kind in self.meta.values() for v in kind}

    def values(self, kind: str):
        """All values of one kind code (e.g. "sub") as a set."""
        return set(self.meta[kind])

    def paying_values(self, kind: str):
        """The values of one kind code that belong in the <asset>-paying file."""
        return {v for v, m in self.meta[kind].items() if self.is_paying(m)}


# ----------------------------------------------------------------------------- context of removed hosts
def _cap(values, n: int) -> str:
    """Join up to n sorted values with "; " and say how many were left out (keeps review file lines readable)."""
    v = sorted(values)
    return "; ".join(v[:n]) + (f" (+{len(v) - n} more)" if len(v) > n else "")


def save_context(day: str, ctx: dict) -> None:
    """state/context-<day>.tsv: bounty/sources/programs/raw entries of every value of every asset type.

    Why: a host that was REMOVED today is no longer in today's data, so we could not say which program it came
    from. Tomorrow's run reads this file (written for the diff-base day) to fill review-removed.txt.
    Stored as PLAIN text on purpose, not gzip: git compresses and delta-encodes plain text, so a day that changes
    0.3 % of the rows adds a few KB to the repository, while a gzip file changes completely and adds ~2 MB per day
    (measured). Only the newest three days are kept (a skipped day still finds its diff base).
    ctx maps (asset stem, value) -> (bounty, sources, programs, program urls, raw entries)."""
    STATE.mkdir(parents=True, exist_ok=True)
    text = "".join("\t".join((kind, host) + tuple(c)) + "\n" for (kind, host), c in sorted(ctx.items()))
    tmp = STATE / f"context-{day}.tsv.part"
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(STATE / f"context-{day}.tsv")
    for old in sorted(STATE.glob("context-*.tsv"))[:-3]:
        old.unlink()
    for legacy in STATE.glob("context-*.tsv.gz"):              # written by the previous version of this script
        legacy.unlink()


def load_context(day: str) -> dict:
    """Read state/context-<day>.tsv written by save_context; {} when it does not exist (e.g. first run)."""
    f = STATE / f"context-{day}.tsv"
    if not f.is_file():
        return {}
    out = {}
    for line in f.read_text(encoding="utf-8").splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            out[(p[0], p[1])] = tuple((p[2:] + [""] * 5)[:5])
    return out


# ----------------------------------------------------------------------------- history helpers
def previous_day_dir():
    """The diff base: latest history/daily/<date> folder dated BEFORE today that still has the base lists.

    Looking for "the latest earlier folder" (instead of "yesterday") is what makes skipped days, late runs and
    same-day re-runs (today's own folder is ignored) all produce correct diffs."""
    if not HIST_DAILY.is_dir():
        return None
    cands = []
    for d in HIST_DAILY.iterdir():
        if d.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.name) and d.name < DATE and (d / "apex.txt").is_file():
            cands.append(d)
    return max(cands, key=lambda d: d.name) if cands else None


def prune_daily():
    """Delete history/daily folders older than RETAIN_DAYS (git history still has them); always keep the newest two
    so there is a diff base even after a long pause. Returns how many were deleted."""
    if not HIST_DAILY.is_dir() or RETAIN_DAYS <= 0:
        return 0
    cutoff = (datetime.strptime(DATE, "%Y-%m-%d") - timedelta(days=RETAIN_DAYS)).strftime("%Y-%m-%d")
    dirs = sorted(d for d in HIST_DAILY.iterdir() if d.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.name))
    n = 0
    for d in dirs[:-2]:                      # always keep the newest two
        if d.name < cutoff:
            shutil.rmtree(d)
            n += 1
    return n


def prune_monthly():
    """Delete history/monthly folders older than RETAIN_MONTHS months (the disk of a small computer should not fill up slowly over the
    years). The current month and the one before are always kept. Returns how many were deleted."""
    root = HIST / "monthly"
    if not root.is_dir() or RETAIN_MONTHS <= 0:
        return 0
    y, m = int(DATE[:4]), int(DATE[5:7])
    total = y * 12 + (m - 1) - RETAIN_MONTHS
    cutoff = f"{total // 12:04d}-{total % 12 + 1:02d}"
    dirs = sorted(d for d in root.iterdir() if d.is_dir() and re.fullmatch(r"\d{4}-\d{2}", d.name))
    n = 0
    for d in dirs[:-2]:
        if d.name < cutoff:
            shutil.rmtree(d)
            n += 1
    return n


# ----------------------------------------------------------------------------- main
MIN_FREE_MB = int(os.environ.get("BB_MIN_FREE_MB", "300"))   # refuse to start a run with less free disk than this (0 = no check)


def disk_report() -> dict:
    """Disk facts for stats.json and the Sources page: how much the project folder takes and how much room is left on its disk."""
    used = 0
    for dirpath, _dirs, files in os.walk(ROOT):
        for f in files:
            try:
                used += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    free = shutil.disk_usage(ROOT).free
    return {"project_mb": round(used / 1e6), "free_mb": round(free / 1e6)}


def main() -> int:
    """One full run. Returns 0; problems with sources are collected in `failed` and written to
    data/failed-sources.txt (the workflow fails AFTER committing, see daily.yml)."""
    if MIN_FREE_MB > 0:                                       # a full disk would leave half-written files; stop before touching anything
        free_mb = shutil.disk_usage(ROOT).free // 1_000_000
        if free_mb < MIN_FREE_MB:
            print(f"[!] Only {free_mb} MB free on the disk of {ROOT} (BB_MIN_FREE_MB={MIN_FREE_MB}). Nothing was changed. Free some space and run again.")
            return 1
    # state/parser-version.txt = 3 lines: PARSER_VERSION, the day it was first seen, and "baseline" if that day was
    # a version-change day. A re-run on that same day stays a baseline too (otherwise the re-run would diff the
    # new parsing against the old snapshot and report the one-off change after all).
    migrate_source_names()
    version_file = STATE / "parser-version.txt"
    vf = version_file.read_text(encoding="utf-8").split() if version_file.is_file() else []
    old_version = vf[0] if vf else None
    version_changed = old_version is not None and old_version != PARSER_VERSION
    same_day_rerun = len(vf) >= 3 and vf[0] == PARSER_VERSION and vf[1] == DATE and vf[2] == "baseline"
    baseline = BASELINE or version_changed or same_day_rerun    # a baseline run writes the data but no diffs
    log(f"[*] Run for {DATE}  (baseline={'yes' if baseline else 'no'}, min_ratio={MIN_RATIO}%, "
        f"unknown_counts_as_paying={'yes' if UNKNOWN_PAYING else 'no'})")
    for d in (DATA, STATE, HIST_TODAY, HIST_MONTH):
        d.mkdir(parents=True, exist_ok=True)

    # ----- setup: Public Suffix List (what is an apex?) and the optional denylist
    psl = load_psl()
    deny = load_denylist()
    log(f"[*] Denylist: {len(deny)} entries" + (" (disabled)" if not deny else ""))

    # ----- 1. download all sources. Each is (name used in files and state, function returning rows).
    failed: list[str] = []          # human-readable problems of this run -> data/failed-sources.txt
    health: list[dict] = []         # one entry per source, shown as "Sources today" in stats.txt
    log("[*] Sources")
    # (name, function, optional). "optional" sources only warn when they break (see run_source).
    sources = [
        ("arkadiyt-domains", src_arkadiyt, False),
        ("arkadiyt-wildcard", src_arkadiyt_wildcards, False),
        ("arkadiyt-hackerone", src_hackerone, False),
        ("arkadiyt-bugcrowd", src_bugcrowd, False),
        ("arkadiyt-intigriti", src_intigriti, False),
        ("arkadiyt-yeswehack", src_yeswehack, False),
        ("projectdiscovery", src_chaos, False),
        ("diodb", lambda: src_diodb(psl), False),
        ("immunefi-direct", lambda: src_immunefi(psl), False),
        ("self-hosted-manual", src_selfhosted, True),
        ("self-hosted-pages", src_selfhosted_pages, True),
        ("self-hosted-text", src_selfhosted_text, True),
    ]
    if DIRECT:
        env = lambda k: os.environ.get(k, "").strip()                 # noqa: E731  (unset secrets arrive as "")
        budget = lambda name: directsources.Budget(DIRECT_BUDGET, name)   # noqa: E731  (a fresh clock per source)
        sources += [
            # HackerOne twice: the website's public GraphQL (no login), and the official API (token; the only way to see
            # programs you were invited to). Both are optional; "paying" wins when they disagree.
            ("hackerone-direct", lambda: directsources.hackerone(fetch, budget("hackerone-direct"), DIRECT_DELAY), True),
            ("hackerone-api", lambda: directsources.hackerone_api(fetch, env("H1_USERNAME"), env("H1_TOKEN"), INCLUDE_PRIVATE, budget("hackerone-api"), DIRECT_DELAY), True),
            ("bugcrowd-direct", lambda: directsources.bugcrowd(fetch, budget("bugcrowd-direct"), DIRECT_DELAY), True),
            # Intigriti: the official API when INTIGRITI_TOKEN is set, otherwise the public website endpoints.
            ("intigriti-direct", lambda: (directsources.intigriti(fetch, env("INTIGRITI_TOKEN"), INCLUDE_PRIVATE, budget("intigriti-direct"), DIRECT_DELAY)
                                          if env("INTIGRITI_TOKEN") else directsources.intigriti_public(fetch, budget("intigriti-direct"), DIRECT_DELAY)), True),
            ("yeswehack-direct", lambda: directsources.yeswehack(fetch, env("YWH_TOKEN"), INCLUDE_PRIVATE, budget("yeswehack-direct"), DIRECT_DELAY), True),
            ("hackenproof-direct", lambda: directsources.hackenproof(fetch, budget("hackenproof-direct"), DIRECT_DELAY), True),
        ]
    disabled = [src for src in sources if src[0] in DISABLED]
    sources = [src for src in sources if src[0] not in DISABLED]
    for src in disabled:
        health.append({"name": src[0], "status": "disabled", "rows": 0, "secs": 0.0, "note": "retired with BB_DISABLE"})
    # Download all sources at the same time (they are different servers; each one is polite on its own). Results come
    # back in list order, so the later steps do not depend on which download finished first.
    warnings: list[str] = []        # problems of optional sources: shown in stats.txt, do not turn the run red
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        fetched = list(pool.map(lambda src: run_source(src[0], src[1], failed, health, src[2], warnings), sources))
    order = {src[0]: i for i, src in enumerate(sources + disabled)}
    health.sort(key=lambda h: order[h["name"]])
    failed.sort()
    warnings.sort()

    # ----- 2. understand every raw entry (scopeparse) and merge the hits
    col = Collector(deny)
    registry = ProgramRegistry()    # one program = one entry, however many sources name it and however they spell it
    for rows in fetched:
        for _raw, _st, _prog, _purl in rows:
            registry.see(_prog, _purl)
    registry.finish()
    rejects: list = []              # (source, reason, raw) for entries nothing could be understood from
    recovered: list = []            # (rules, source, raw, asset, result) for repaired / guessed entries
    parser_errors: dict = {}        # exception name -> first message; a parser that CRASHES (a bug or an unsupported Python) is not the same as "entry not understood"
    for (name, _fn, _opt), rows in zip(sources, fetched):
        for raw, status, prog, purl in rows:
            prog, purl = registry.canon(prog, purl)
            if status == OOS:                       # the program EXCLUDES this: understood, but kept apart from every target list
                col.add_exclusion(raw, prog, purl, psl)
                continue
            try:
                parsed = scopeparse.parse_entry(raw, psl)
            except Exception as e:  # noqa: BLE001  (one odd line must never stop the daily run)
                rejects.append((name, f"parser-error:{type(e).__name__}", raw))
                parser_errors.setdefault(type(e).__name__, f"{e}  (entry: {raw[:80]!r})")
                continue
            if parsed.blank:
                continue
            if not parsed.hits:
                rejects.append((name, parsed.reject or "unknown", raw))
                continue
            for h in parsed.hits:
                col.add_hit(h, status, name, prog, purl, raw)

                rules = [r for r in h.rule.split(";") if r and r not in QUIET_RULES]
                if rules:                                   # repaired or guessed: keep an audit trail
                    recovered.append((";".join(rules), name, raw, asset_of_hit(h), h.value))

    # A crashing parser must never be saved as a normal day: every entry would be "rejected" and tomorrow's diff would be wrong.
    # A handful of crashes is a warning; more than 1% of all entries (or a crash on a whole source) stops the run BEFORE anything is written.
    n_perr = sum(1 for r in rejects if r[1].startswith("parser-error"))
    n_rows = sum(len(r) for r in fetched)
    if n_perr:
        detail = "; ".join(f"{k}: {v}" for k, v in list(parser_errors.items())[:3])
        if n_perr * 100 > max(n_rows, 1):
            print(f"[!] STOPPED: the parser crashed on {n_perr} of {n_rows} entries, nothing was written. First problems: {detail}")
            print(f"    Python here is {sys.version.split()[0]}; the scripts need 3.8 or newer. Fix the cause (see the message above) and run again.")
            for d in (HIST_TODAY, HIST_MONTH):              # created at the start; remove again when still empty so no half-day is left behind
                try:
                    d.rmdir()
                except OSError:
                    pass
            return 1
        warnings.append(f"parser crashed on {n_perr} entries (listed in rejected.txt as parser-error:*): {detail}")
        warnings.sort()

    # ----- 3. today's state per asset type: cur[asset] = all values, pay[asset] = the paying (or unknown) ones
    cur = {stem: col.values(kind) for stem, kind in ASSETS.items()}
    master = col.master
    if cur["apex"] & cur["subdomains"]:
        failed.append("consistency: a host is in both apex and subdomains")
    pay = {stem: col.paying_values(kind) for stem, kind in ASSETS.items()}

    # ----- 4. diffs against the latest earlier daily folder (diffs[asset] = (new values, removed values))
    prev_dir = previous_day_dir()
    diffs = {k: (set(), set()) for k in ASSETS}
    diff_note = ""
    if baseline:
        diff_note = ("baseline run requested (BB_BASELINE=1): no diffs today" if BASELINE
                     else f"parser version changed earlier today (now {PARSER_VERSION}): no diffs today" if same_day_rerun and not version_changed
                     else f"parser version changed ({old_version or 'earlier run'} -> {PARSER_VERSION}): no diffs today")
    elif prev_dir is None:
        diff_note = "first run: no earlier snapshot, no diffs today"
    else:
        prev = {k: read_set(prev_dir / f"{k}.txt") for k in diffs}
        suspicious = [k for k in ("apex", "subdomains") if prev[k] and len(cur[k]) * 100 < len(prev[k]) * MIN_RATIO]
        if suspicious:
            diff_note = f"merged list collapsed ({', '.join(suspicious)}): diffs skipped"
            failed.append(diff_note)
        else:
            for k in diffs:
                if prev[k] is not None:                     # a list the old snapshot did not have: no diff on its first day
                    diffs[k] = (cur[k] - prev[k], prev[k] - cur[k])
            diff_note = f"diffs against {prev_dir.name}"
    log(f"[*] {diff_note}")

    # ----- 5. write data/: master + the four files of every asset type
    write_list(DATA / "master.txt", master)
    for k in cur:
        write_list(DATA / f"{k}.txt", cur[k])
        write_list(DATA / f"{k}-paying.txt", pay[k])
        write_list(DATA / f"{k}-new.txt", diffs[k][0])
        write_list(DATA / f"{k}-removed.txt", diffs[k][1])
    for old in OLD_NAMES:                       # files from the previous naming scheme (new-apex.txt ...)
        (DATA / old).unlink(missing_ok=True)

    # ----- review files (for a human to read; tab separated with a header line)
    def ctx(kind: str, host: str):
        """(bounty, sources, programs, program urls, raw entries) for one value of one kind code, as text."""
        m = col.meta[kind][host]
        return (col.bounty(m), ",".join(sorted(m["sources"])), _cap(m["programs"], 5), _cap(m["urls"], 3), _cap(m["raws"], 2))

    def row(kind: str, host: str):
        """Line of review-by-source.txt: bounty, asset type, value, sources, hosting (platform / self-hosted / both / unknown)."""
        m = col.meta[kind][host]
        return (col.bounty(m), STEM[kind], host, ",".join(sorted(m["sources"])), hosting_of(m["urls"]))

    order = {"paying": 0, "unknown": 1, "non-paying": 2, "": 3}
    REVIEW_HEAD = "bounty\tassets\thost\tsources\tprograms\tprogram_urls\traw_entries"

    def write_review(path, rows, extra_head=""):
        rows = sorted(rows, key=lambda r: (order.get(r[0], 3), r[1], r[2]))
        path.write_text(REVIEW_HEAD + extra_head + "\n" + "".join("\t".join(r) + "\n" for r in rows), encoding="utf-8")
        return rows

    # New values exist in today's data, so their context (programs, raw text, ...) is read straight from the Collector.
    new_rows = [(ctx(ASSETS[k], h)[0], k, h, *ctx(ASSETS[k], h)[1:]) for k, (new, _) in diffs.items() for h in new]
    new_rows = write_review(DATA / "review-new.txt", new_rows)
    pay_rows = [r for r in new_rows if r[0] == "paying" or (r[0] == "unknown" and UNKNOWN_PAYING)]
    write_review(DATA / "review-new-paying.txt", pay_rows)

    # removed hosts are no longer in today's data: their context comes from the stored copy of the diff base day
    old_ctx = load_context(prev_dir.name) if (prev_dir is not None and diff_note.startswith("diffs against")) else {}
    removed_rows = []
    for k, (_, removed) in diffs.items():
        for h in removed:
            c = old_ctx.get((k, h), ("", "", "", "", ""))
            removed_rows.append((c[0], k, h, *c[1:]))
    # WHY was it removed? A removed value is either "its whole program has disappeared from every source" (made private, paused, closed,
    # or a source lost it) or "the program is still listed but this value is gone from its scope" (the scope was edited, or the
    # source reads the page differently today). The two need different follow-ups, so say which one it is (column why_removed).
    today_programs = defaultdict(lambda: [set(), 0])                # program name -> [sources listing it today, values it has today]
    for (pn, _pu), pv in col.programs.items():
        today_programs[pn][0] |= pv["sources"]
        today_programs[pn][1] += len(pv["hosts"])

    def why_removed(programs_text: str) -> str:
        names = [n.strip() for n in re.sub(r"\s*\(\+\d+ more\)\s*$", "", programs_text or "").split(";") if n.strip()]
        if not names:
            return "no program is known for this value"
        still = [n for n in names if n in today_programs]
        if not still:
            return "program no longer listed by any source today (made private, paused or closed, or every source lost it)"
        n = still[0]
        return f"program still listed by {','.join(sorted(today_programs[n][0]))} ({today_programs[n][1]} values today) but this value is no longer in its scope"

    removed_rows = [r + (prev_dir.name if prev_dir is not None else "", why_removed(r[4])) for r in removed_rows]
    removed_rows = sorted(removed_rows, key=lambda r: (order.get(r[0], 3), r[1], r[2]))
    (DATA / "review-removed.txt").write_text(
        REVIEW_HEAD + "\tlast_seen_in\twhy_removed\n" + "".join("\t".join(r) + "\n" for r in removed_rows), encoding="utf-8")
    save_context(DATE, {(stem, h): ctx(kind, h) for stem, kind in ASSETS.items() for h in col.meta[kind]})
    # The ALL-TIME database (history/all-time.tsv, see archive.py): every value ever in scope, never deleted. A day on which a source had
    # no data at all (not even an older copy) or the parser changed does not mark anything as gone, so a hiccup cannot "remove" values.
    try:
        blind = any(h["status"] in ("unavailable", "FAILED") for h in health)
        info = archive.update(HIST / "all-time.tsv", {(stem, h): (ctx(kind, h)[0], ctx(kind, h)[2]) for stem, kind in ASSETS.items() if stem != "apis"
                                                       for h in col.meta[kind]}, DATE, baseline or blind)
        log(f"[*] All-time database: {info['total']} values ever seen, {info['gone']} no longer listed (+{info['added']} new, {info['went']} gone today)")
    except Exception as e:  # noqa: BLE001  (never lose the day's data because of the archive)
        log(f"[!] all-time database not updated: {type(e).__name__}: {e}")

    review = sorted((row(kind, h) for kind in col.meta for h in col.meta[kind]), key=lambda r: (r[2], r[1]))
    (DATA / "review-by-source.txt").write_text(
        "bounty\tassets\thost\tsources\thosting\n" + "".join("\t".join(r) + "\n" for r in review), encoding="utf-8")

    # programs.txt: one line per program page. hosting = platform (page on HackerOne, Bugcrowd ...), self-hosted (the company's
    # own page, e.g. Google, Microsoft, Zoho) or both (a self-hosted program whose domains also appear in a platform program;
    # `also_on` names those platform programs). Only registrable domains of the program's own pages come from diodb, so
    # for self-hosted programs `hosts` is often small unless config/self-hosted-programs.tsv lists their scope.
    plat_hosts = defaultdict(set)                           # host -> names of platform programs that list it
    for (pname, purl), pr in col.programs.items():
        if hosting_of_url(purl) == "platform" and pname:
            for h in pr["hosts"]:
                plat_hosts[h].add(pname)
    prog_rows = []
    for (pname, purl), pr in col.programs.items():
        hosting = hosting_of_url(purl) or "unknown"
        also = set()
        if hosting == "self-hosted":
            for h in pr["hosts"]:
                also |= plat_hosts.get(h, set())
            if also:
                hosting = "both"
        st = "paying" if "paying" in pr["status"] else "non-paying" if "non-paying" in pr["status"] else "unknown"
        prog_rows.append((hosting, st, pname, purl, str(len(pr["hosts"])), ",".join(sorted(pr["sources"])), _cap(also, 3), program_id(pname, purl)))
    # Program history: appeared / left / returned / shrank / grew (see proghistory.py). A source that did not deliver fresh data today
    # is named in the "left" event, so a source problem is not mistaken for a program that really left.
    unhealthy = [h["name"] for h in health if h["status"] not in ("ok", "disabled") or "could not be read today" in (h.get("note") or "")]
    try:
        events = proghistory.update(
            STATE / "programs-seen.tsv", HIST / "program-events.tsv",
            [{"key": registry.ident(r[2], r[3]), "id": r[7], "name": r[2], "url": r[3], "count": int(r[4]), "sources": [x for x in r[5].split(",") if x]} for r in prog_rows],
            DATE, baseline, unhealthy)
        if events:
            log("[*] Program events: " + ", ".join(f"{n} {k}" for k, n in sorted(Counter(e["event"] for e in events).items())))
    except Exception as e:  # noqa: BLE001  (the history is a nice-to-have: never lose the day's data because of it)
        log(f"[!] program history not updated: {type(e).__name__}: {e}")
    # program-scope.tsv: which program lists which value (one line per program, asset type and value). The web UI and the
    # API (site/) use it for the program pages and for "is this host in scope, and where?". `id` = program_id() of programs.txt.
    ps_rows = []
    for (pname, purl), pr in col.programs.items():
        pid = program_id(pname, purl)
        for (kind, value), sts in pr["items"].items():
            ps_rows.append((pid, STEM[kind], value, "paying" if "paying" in sts else "non-paying" if "non-paying" in sts else "unknown"))
    ps_rows.sort()
    # program-out-of-scope.tsv: what each program EXCLUDES (id asset value). asset is an asset type, or "text" for a plain-language
    # exclusion ("social engineering"). Only for programs that also have in-scope targets (they have an id in programs.txt).
    oos_rows = []
    for (pname, purl) in col.programs:
        pid = program_id(pname, purl)
        for asset, value in col.oos.get((pname, purl), ()):
            oos_rows.append((pid, asset, value))
        for text in sorted(col.oos_text.get((pname, purl), ()))[:OOS_TEXT_PER_PROGRAM]:
            oos_rows.append((pid, "text", text))
    oos_rows.sort()
    (DATA / "program-out-of-scope.tsv").write_text("id\tasset\tvalue\n" + "".join("\t".join(r) + "\n" for r in oos_rows), encoding="utf-8")
    (DATA / "program-scope.tsv").write_text("id\tasset\tvalue\tbounty\n" + "".join("\t".join(r) + "\n" for r in ps_rows), encoding="utf-8")
    hosting_order = {"self-hosted": 0, "both": 1, "platform": 2, "unknown": 3}
    prog_rows.sort(key=lambda r: (hosting_order.get(r[0], 4), order.get(r[1], 3), r[2].lower(), r[3]))
    (DATA / "programs.txt").write_text(
        "hosting\tbounty\tprogram\tprogram_url\thosts\tsources\talso_on\tid\n" + "".join("\t".join(r) + "\n" for r in prog_rows), encoding="utf-8")

    rej = sorted(set(rejects))
    (DATA / "rejected.txt").write_text(
        "source\treason\traw\n" + "".join("\t".join(r) + "\n" for r in rej), encoding="utf-8")
    rec = sorted(set(recovered))
    (DATA / "recovered.txt").write_text(
        "rule\tsource\traw\tassets\tresult\n" + "".join("\t".join(r) + "\n" for r in rec), encoding="utf-8")
    (DATA / "failed-sources.txt").write_text("".join(f + "\n" for f in failed), encoding="utf-8")

    # ----- stats.txt
    reasons = Counter(r[1] for r in rej)
    rules_seen = Counter(r[0] for r in rec)
    have_diffs = diff_note.startswith("diffs against")
    kinds_sum = sum(len(cur[k]) for k in cur if k not in OVERLAY)
    overlap = kinds_sum - len(master)
    n_new = {k: len(diffs[k][0]) for k in cur}
    n_rem = {k: len(diffs[k][1]) for k in cur}

    def banner(text: str):
        inner = f"===  {text}  ==="
        return ["=" * len(inner), inner, "=" * len(inner)]

    def table(rows, widths, head):
        line = "-" * (sum(widths) + 2)
        out = [line, head, line] + rows
        return out, line

    # Line 1 is a one-line headline (greppable, also good as a notification text), then the full tables.
    if have_diffs:
        headline = (f"{DATE} | new: {sum(n_new.values())} (+{n_new['apex']} apex, +{n_new['subdomains']} subdomains) | "
                    f"removed: {sum(n_rem.values())} | failed sources: {len(failed)} | warnings: {len(warnings)}")
    else:
        headline = f"{DATE} | {diff_note} | failed sources: {len(failed)} | warnings: {len(warnings)}"
    L = [headline, ""] + banner(f"Bug bounty domains - {DATE}")
    files_head = f"{'filename':<26}{'count':>8}"
    file_rows = [f"{'master.txt':<26}{len(master):>8}",
                 f"{'review-new-paying.txt':<26}{len(pay_rows):>8}",
                 f"{'review-new.txt':<26}{len(new_rows):>8}",
                 f"{'review-removed.txt':<26}{len(removed_rows):>8}",
                 f"{'recovered.txt':<26}{len(rec):>8}",
                 f"{'rejected.txt':<26}{len(rej):>8}",
                 f"{'review-by-source.txt':<26}{len(review):>8}",
                 f"{'programs.txt':<26}{len(prog_rows):>8}",
                 f"{'program-out-of-scope.tsv':<26}{len(oos_rows):>8}",
                 f"{'failed-sources.txt':<26}{len(failed):>8}"]
    t, line = table(file_rows, [26, 8], files_head)
    L += [""] + t + [line, ""]

    # "Sources today": one line per source, so "why did the counts move?" is answered without reading the log.
    rej_by_src = Counter(r[0] for r in rej)
    L += banner("Sources today")
    sh = f"{'source':<20}{'status':<17}{'rows':>8}{'rejected':>10}{'seconds':>9}"
    src_rows = [f"{h['name']:<20}{h['status']:<17}{h['rows']:>8}{rej_by_src.get(h['name'], 0):>10}{h['secs']:>9.1f}"
                + (f"   {h['note']}" if h["note"] else "") for h in health]
    t, line = table(src_rows, [20, 17, 8, 10, 9], sh)
    L += [""] + t + [line, ""]

    L += banner(f"Diffs: {diff_note}")
    w = 22
    head = f"{'assets':<{w}}{'count':>8}{'paying':>8}{'new':>7}{'removed':>9}"
    rows_ = []
    for k in cur:
        n, r_ = (str(n_new[k]), str(n_rem[k])) if have_diffs else ("-", "-")
        rows_.append(f"{k:<{w}}{len(cur[k]):>8}{len(pay[k]):>8}{n:>7}{r_:>9}")
    nd = [k for k in cur if k not in OVERLAY]
    tot = lambda f: sum(f(k) for k in cur)
    totnd = lambda f: sum(f(k) for k in nd)
    dash = "-" * (w + 32)
    fmt = lambda label, a, b, c, d: f"{label:<{w}}{a:>8}{b:>8}{c:>7}{d:>9}"
    rows_ += [dash,
              fmt("total (no duplicates)", totnd(lambda k: len(cur[k])), totnd(lambda k: len(pay[k])),
                  totnd(lambda k: n_new[k]) if have_diffs else "-", totnd(lambda k: n_rem[k]) if have_diffs else "-"),
              dash,
              fmt("total", tot(lambda k: len(cur[k])), tot(lambda k: len(pay[k])),
                  tot(lambda k: n_new[k]) if have_diffs else "-", tot(lambda k: n_rem[k]) if have_diffs else "-")]
    t, line = table(rows_, [w, 32], head)
    L += [""] + t + [dash, ""]

    L += banner("Explanation / logic for the above results")
    L += ["", f"Recovered (repaired or guessed): {len(rec)}"]
    L += [f"  {v:>6}  {k}" for k, v in rules_seen.most_common()] or ["  none"]
    L += [f"Rejected: {len(rej)}"]
    L += [f"  {v:>6}  {k}" for k, v in reasons.most_common()] or ["  none"]
    L += [f"Failed sources: {len(failed)}"] + [f"  - {f}" for f in failed]
    L += [f"Warnings (optional direct sources that did not work; the run stays green): {len(warnings)}"] + [f"  - {w}" for w in warnings]
    L += ["", "How the numbers are counted",
          "- count: lines in data/<asset>.txt. paying: lines in data/<asset>-paying.txt (bounty status paying, or unknown while BB_UNKNOWN_PAYING=1).",
          "- new / removed: lines in data/<asset>-new.txt and <asset>-removed.txt, compared with the latest earlier folder in history/daily ('-' = no diff today).",
          "- sources today: status ok = downloaded fine (a note says when the content has been frozen for days); disabled = retired with BB_DISABLE; carried forward = the download failed or shrank below BB_MIN_RATIO % and the last good copy was used; FAILED / unavailable = failed and no earlier copy exists; skipped = not configured (e.g. no API token), not an error. rows = entries the source delivered, rejected = how many of them fit no asset type. Sources ending in -direct are read straight from the platform and only warn when they break.",
          "- total: the sum of all asset types = one line per (host, kind) in review-by-source.txt.",
          "- total (no duplicates): total minus the overlay lists (wildcards and apis), because those only repeat values that are also listed under apex, subdomains or urls.",
          f"- master.txt: every distinct host, IP, URL or pattern of every asset type, once. {len(master)} = "
          + " + ".join(f"{len(cur[k])} {k}" for k in nd)
          + (f" - {overlap} value(s) that appear under two asset types (so master is {overlap} less than total (no duplicates))" if overlap
             else " (no value appears under two kinds)"),
          f"- apex: registrable domains. {len(cur['apex'])} = {len(cur['apex'] & col.listed)} listed by a source + {len(cur['apex'] - col.listed)} derived from a listed subdomain.",
          "- subdomains: hosts below an apex, including wildcard bases that are not apexes. A host is never in both apex and subdomains.",
          "- wildcards: wildcard bases (*.example.com stored as example.com). They are also in apex or subdomains.",
          "- apis: an overlay: every host / wildcard / url that the platform calls an API (rule declared-api) or whose address says so (api.x.com, yahooapis.com, /api/, /graphql, /v1/). Also listed in subdomains or urls, never counted twice.",
          "- urls: scope entries that carry a PATH (https://storage.googleapis.com/kubernetes-release): the path is the scope, so the host of such an entry is NOT also added to apex/subdomains. A bare host or 'host/*' stays a host.",
          "- review-new.txt / review-new-paying.txt / review-removed.txt: one line per new or removed (host, kind) with bounty, sources, programs, program links and the raw entry; the paying file keeps paying and unknown-bounty lines.",
          "- program-out-of-scope.tsv: what each program EXCLUDES (id, asset type or 'text', value). Never part of any target list; the website uses it to say 'excluded' in the scope check.",
          "- programs.txt: one line per program page (hosting = platform, self-hosted or both; see README, 'Self-hosted programs'). review-by-source.txt has the same hosting word per host in its last column.",
          "- recovered: entries repaired or guessed by scopeparse (details in recovered.txt). rejected: entries that fit no kind (details in rejected.txt)."]
    stats = "\n".join(L) + "\n"
    (DATA / "stats.txt").write_text(stats, encoding="utf-8")
    log(stats)
    # stats.json: the same numbers in a machine-readable form for the web UI and the API (site/build_site.py)
    (DATA / "stats.json").write_text(json.dumps({
        "date": DATE, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": VERSION, "disk": disk_report(), "parser_version": PARSER_VERSION, "diff_note": diff_note, "have_diffs": have_diffs, "headline": L[0],
        "master": len(master), "overlap": overlap,
        "files": {"review_new_paying": len(pay_rows), "review_new": len(new_rows), "review_removed": len(removed_rows),
                  "recovered": len(rec), "rejected": len(rej), "review_by_source": len(review), "programs": len(prog_rows),
                  "program_scope": len(ps_rows), "program_out_of_scope": len(oos_rows), "failed_sources": len(failed)},
        "assets": [{"asset": k, "count": len(cur[k]), "paying": len(pay[k]), "new": n_new[k] if have_diffs else None,
                    "removed": n_rem[k] if have_diffs else None} for k in cur],
        "sources": [{"name": h["name"], "status": h["status"], "rows": h["rows"], "rejected": rej_by_src.get(h["name"], 0),
                     "seconds": round(h["secs"], 1), "note": h["note"]} for h in health],
        "failed": failed, "warnings": list(warnings),
        "recovered": dict(rules_seen.most_common()), "rejected": dict(reasons.most_common()),
    }, indent=1) + "\n", encoding="utf-8")

    # ----- 6. history/daily/DATE: a SMALL snapshot, kept for RETAIN_DAYS days.
    # What it is for:
    #   * <asset>.txt (11 files): the DIFF BASE. Tomorrow's run reads these to work out new / removed values.
    #   * review-new / review-new-paying / review-removed: that day's changelog with full context (programs, raw text).
    #     They contain everything the per-asset -new / -removed files contain, so those are not copied.
    #   * failed-sources, stats: what went wrong / the numbers of that day.
    # Deliberately NOT copied: <asset>-paying.txt (a filter of <asset>.txt, rebuilt any time from review-by-source),
    # <asset>-new/-removed.txt (duplicated by the review files), master.txt (union of the asset lists).
    # Git history of data/ keeps every full day anyway; this folder is the quick, browsable window.
    for name in [*cur, "review-new", "review-new-paying", "review-removed", "failed-sources", "stats"]:
        shutil.copy2(DATA / f"{name}.txt", HIST_TODAY / f"{name}.txt")
    shutil.copy2(DATA / "stats.json", HIST_TODAY / "stats.json")       # small; the web UI draws its history charts from these

    # ----- 7. history/monthly/YYYY-MM: running unions ("everything seen at any point this month").
    # data/ only shows today, so this is the one place that remembers values which appeared and later vanished.
    # Files are updated IN PLACE every day (the folder never grows by more than a few KB): for every asset type
    # <asset>.txt and <asset>-paying.txt, plus master.txt. Paying here = "was paying on at least one day this month".
    def union(name: str):
        target = HIST_MONTH / name
        merged = (read_set(target) or set()) | (read_set(DATA / name) or set())
        legacy = HIST_MONTH / ("all-" + name)                  # old scheme (all-apex.txt): fold into the new file, then delete
        if legacy.is_file():
            merged |= read_set(legacy) or set()
            legacy.unlink()
        write_list(target, merged)

    for name in [f"{k}{suf}.txt" for k in cur for suf in ("", "-paying")] + ["master.txt"]:
        union(name)
    # ----- 8. remember the parser version (see the top of main), housekeeping and the Actions step summary
    if version_changed or same_day_rerun:
        version_file.write_text(f"{PARSER_VERSION}\n{DATE if version_changed else vf[1]}\nbaseline\n", encoding="utf-8")
    elif not vf or vf[0] != PARSER_VERSION:
        version_file.write_text(f"{PARSER_VERSION}\n{DATE}\n", encoding="utf-8")
    pruned_m = prune_monthly()
    if pruned_m:
        log(f"[*] pruned {pruned_m} monthly folder(s) older than {RETAIN_MONTHS} months")
    pruned = prune_daily()
    if pruned:
        log(f"[*] pruned {pruned} daily folder(s) older than {RETAIN_DAYS} days (git history keeps them)")

    write_summary(cur, pay, diffs, [r[2] for r in pay_rows], failed, diff_note, warnings)
    log(f"[+] Finished {DATE}" + (f" with {len(failed)} problem(s)" if failed else ""))
    return 0


def write_summary(cur, pay, diffs, new_paying, failed, diff_note, warnings=()) -> None:
    """Markdown table on the GitHub Actions run page ($GITHUB_STEP_SUMMARY; skipped when running locally)."""
    new_paying = sorted(set(new_paying))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    L = [f"### Bug bounty domains - {DATE}", "", "| Assets | Total | Paying | New | Removed |", "| --- | ---: | ---: | ---: | ---: |"]
    for k in ASSETS:
        new, removed = diffs[k]
        L.append(f"| {k} | {len(cur[k])} | {len(pay[k])} | {len(new)} | {len(removed)} |")
    L += ["", f"_{diff_note}_", ""]
    if failed:
        L += ["**Problems (workflow is marked failed on purpose so you notice):**", ""] + [f"- {f}" for f in failed] + [""]
    if warnings:
        L += ["**Warnings (optional direct sources, run stays green):**", ""] + [f"- {w}" for w in warnings] + [""]
    if new_paying:
        L += [f"**New paying / unknown-bounty hosts ({len(new_paying)}), first 30:**", "", "```"] + new_paying[:30] + ["```"]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: {exc}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
