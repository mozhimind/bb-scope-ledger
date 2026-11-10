#!/usr/bin/env python3
"""scopeparse - understand ONE raw scope entry the way a person reading it would (standard library only).

WHY THIS FILE EXISTS
    Bug bounty programs write their scope by hand, so a single "entry" can be a clean hostname, a URL, a
    wildcard, an IP range, an app-store link, a sentence, a list of five domains, or garbage. The platforms'
    JSON files give us those strings untouched. This module decides what each string means and which
    asset type (= which output file in data/) it belongs to. It never touches the network or the disk, so
    it is fully testable: tests/test_parse.py holds a table of ~100 raw entries and what each must become.

HOW TO USE IT
    parse_entry(raw, psl) returns a Parsed object:
        .hits    list of Hit(kind, value, rule, apex)   - everything that could be understood (may be several)
        .reject  reason string when nothing could be understood (then .hits is empty)
        .blank   True for empty lines and comments
    `psl` is the Public Suffix List object from update_bb_domains.py (it knows which TLDs exist and what the
    "registrable domain" / apex of a host is, e.g. www.bbc.co.uk -> bbc.co.uk).

Hit.kind (the internal code of an asset type; update_bb_domains.py maps it to the output file name)
    host      a hostname below a registrable domain      (value = host, apex = registrable domain)
              -> data/apex.txt if value == apex, else data/subdomains.txt
    wildcard  base of a "*.example.com" style scope     (value = base host, apex = registrable domain)
              -> data/wildcards.txt, AND the base is also stored as apex/subdomain
    ip        public IPv4/IPv6 address or CIDR range                         -> data/ips.txt
    asn       autonomous system number, always written "AS<number>"          -> data/asn.txt
    url       an address WITH A PATH ("https://storage.googleapis.com/kubernetes-release/"): the scope is that path, not the whole
              host, so the host is NOT also stored as apex/subdomain         (value = scheme://host[:port]/path)  -> data/url.txt
    github    in-scope GitHub project or org            (https://github.com/org[/repo])   -> data/github.txt
    repo      in-scope repo on another code host        (GitLab, Bitbucket, Codeberg, ...) -> data/repos-other.txt
    app       mobile / desktop app: store URL or package id                  -> data/apps.txt
    pattern   wildcard or template that cannot become a plain host ("api-*.example.com", "{tenant}.example.com")
                                                                             -> data/patterns.txt
    internal  well-formed host or IP that is not on the public internet (".internal", ".local", 10.0.0.0/8, ...)
                                                                             -> data/internal-hosts.txt
    maybe     host / IP / ASN found inside free text; a guess that needs a human look -> data/maybe.txt

Hit.rule is "" when the entry was clean as given. A non-empty rule says what was repaired or guessed
("defang", "markdown", "punctuation", "multi-entry", "comment-stripped", "email", "ip-star", "ip-range",
"leading-dot", "pattern-tail", "package-id", "text-extract", "alternatives", "ellipsis-wildcard", ...). Those go to data/recovered.txt so a human
can audit every guess.

Rejects (nothing understood): placeholder, free-text, single-label, public-suffix, file-ext, numeric-tld,
bad-chars, bad-label, bad-idn, bad-ip, ip-too-broad, ip-range-too-large, too-long, empty, not-a-project,
store-host. They go to data/rejected.txt together with the source and the raw text.

ORDER OF DECISIONS (first match wins; see parse_entry and parse_token)
    1. blank / comment            -> ignored
    2. "app:..." prefix           -> app (the platform itself said it is a mobile app)
    2b. alternatives "{com,co.uk}", "(se|fi).x.com", "[it | fr | ...].x.com" -> expanded into several entries, each
                                  parsed again by this same list (see expand_alternatives)
    3. placeholder ("N/A", "-")   -> reject
    4. ASN ("AS16314")            -> asn
    5. IP / CIDR / range          -> ip (or internal for private ranges)
    6. one token (no spaces):     GitHub, app store, other repo host, then URL clean-up and host validation;
                                  a URL with a real path becomes kind "url" (see url_of below), a bare host stays a host
    7. text with spaces/commas    -> list of entries, "host (comment)", or hosts hidden in a sentence (maybe)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import bbclean

# --- constants shared with / borrowed from bbclean.py (the older, simpler cleaner)
LABEL_RE = bbclean.LABEL_RE            # one DNS label: letters, digits, "-" and "_", max 63 characters
# Endings that make a "host" really a file name ("index.html", "app.js"): rejected as file-ext.
FILE_EXT = bbclean.FILE_EXT | {"ico", "woff", "woff2", "map", "yml", "yaml", "exe", "apk", "ipa", "dll", "jar", "gradle", "lock"}
# First labels of reverse-DNS package ids ("com.example.app", "org.foo.bar", "io.x.y"): such a string looks like a
# host with a real TLD at the END of the string being the app name, so it is treated as an app when it starts with
# one of these or with a real TLD.
REVERSE_DNS_FIRST = bbclean.REVERSE_DNS_FIRST

# Invisible characters that sneak into scope text copied from web pages; removed before parsing.
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
# Whole-entry values that mean "nothing here" (programs fill empty scope fields with these).
PLACEHOLDERS = {"all", "any", "n/a", "na", "none", "tbd", "tba", "various", "other", "unknown", "-", "--", "*", "**",
                "todo", "null", "nil", "see below", "see description", "see scope"}
# Words allowed BETWEEN hosts in a list ("a.com and b.org", "a.com / b.com"); any other word makes it a sentence.
CONNECTORS = {"and", "or", "&", "+", "also", "plus", "incl", "including", "e.g", "eg", "i.e", "ie", "etc", "-", "–", "—", "/", "|"}

# Characters that mean "this label is a template, not a real name" (api-*.example.com, {tenant}.example.com).
PATTERN_CHARS = set("*{}<>[]$%")

# Autonomous System numbers are 32-bit; 0 is reserved.
ASN_MAX = 4294967295

# App stores / marketplaces: a URL on these is an app (data/apps.txt); the bare host alone is not a target.
STORE_HOSTS = {
    "apps.apple.com", "itunes.apple.com", "testflight.apple.com", "play.google.com", "chrome.google.com",
    "chromewebstore.google.com", "addons.mozilla.org", "marketplace.atlassian.com", "appgallery.huawei.com",
    "apps.microsoft.com", "microsoftedge.microsoft.com", "marketplace.visualstudio.com", "apps.shopify.com",
    "galaxystore.samsung.com", "apkpure.com", "f-droid.org",
}
# Code hosts other than GitHub (GitHub has its own asset type, github.txt).
REPO_HOSTS = {"gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "sourceforge.net"}
# Path segments that end the "project" part of a repo URL (".../group/proj/-/tree/main" -> group/proj).
REPO_STOP = {"-", "tree", "blob", "issues", "pulls", "merge_requests", "wiki", "releases", "tags", "commits", "src", "raw", "actions"}
# github.com/<word> pages that are GitHub site pages, not an organisation (github.com/about, /features, ...).
GH_RESERVED = {"orgs", "sponsors", "settings", "marketplace", "features", "about", "topics", "collections", "pricing",
               "login", "join", "enterprise", "security", "apps", "search", "explore", "notifications", "pulls",
               "issues", "new", "site", "customer-stories", "readme", "contact", "trending", "events"}

# "https://", "ftp://", "mailto:" and typo forms such as "http//" or "https:" that people really write.
SCHEME_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|(?:https?|ftp|ftps|wss?|sftp|ssh|tcp|udp)(?::/{0,2}|//)|mailto:)", re.I)
# IPv4 address text, used inside other regexes.
V4 = r"\d{1,3}(?:\.\d{1,3}){3}"


@dataclass(frozen=True)
class Hit:
    """One thing understood in an entry. An entry can give several hits (a list of hosts, a pattern + its domain)."""
    kind: str                  # asset type code, see the module docstring
    value: str                 # normalised value: lowercase host, canonical CIDR, "AS123", store URL, ...
    rule: str = ""             # what was repaired/guessed ("" = entry was clean); ";"-separated
    apex: str | None = None    # registrable domain, only for host / wildcard / maybe hosts


@dataclass
class Parsed:
    """Result of parse_entry. Exactly one of: hits (understood), reject (a reason), blank (nothing to do)."""
    hits: list = field(default_factory=list)
    reject: str | None = None
    blank: bool = False


# ----------------------------------------------------------------------------- ASN
def parse_asn(s: str):
    """"AS16314", "ASN 16314", "AS6720 IPv6 1/2", "AS123 (Example Corp)" -> ("AS16314", had_comment); else None.

    Strict on purpose, because words like "as" or "AS400 system guide" appear in prose:
      * "AS" / "ASN" must be upper case when a space or ":" separates it from the number ("as16314" without a
        separator is also accepted);
      * the number must be 1..4294967295;
      * whatever follows the number must be empty or an obvious comment: "(...)", "- ...", ": ...",
        or a part marker such as "1/2" / "IPv6 1/2" (Bugcrowd splits big AS scopes that way).
    """
    m = re.match(r"^(?:AS|ASN)[ :#-]?(\d{1,10})(?![\w.-])(.*)$", s) or re.match(r"(?i)^(?:as|asn)(\d{1,10})(?![\w.-])(.*)$", s)
    if not m:
        return None
    n = int(m.group(1))
    if not 0 < n <= ASN_MAX:
        return None
    rest = m.group(2).strip()
    if rest and not re.fullmatch(r"(?:(?:IPv[46]\s+)?\d+\s*/\s*\d+|[(\[–—:-].*)", rest):
        return None
    return f"AS{n}", bool(rest)


# ----------------------------------------------------------------------------- text clean-up
def defang(s: str):
    """hxxp, [.] (.) [dot], [:] [://] [@], '(*.)' -> normal text. Returns (text, changed)."""
    t = re.sub(r"hxxp", "http", s, flags=re.I)
    t = re.sub(r"\[\s*://\s*\]", "://", t)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\[\s*@\s*\]|\(\s*at\s*\)", "@", t, flags=re.I)
    t = re.sub(r"\(\s*\*\s*\.\s*\)|\[\s*\*\s*\.\s*\]", "*.", t)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)", ".", t, flags=re.I)
    return t, t != s


def strip_wrap(t: str):
    """Remove wrapping or dangling punctuation: '(host)', 'host)', '"host",', '<host>', 'host.' ... Returns (text, changed)."""
    orig = t
    pairs = {"(": ")", "[": "]", "<": ">", "{": "}", '"': '"', "'": "'", "`": "`"}
    for _ in range(4):
        t = t.strip()
        if len(t) > 1 and t[0] in pairs and t[-1] == pairs[t[0]]:
            t = t[1:-1]
            continue
        # dangling closers / opener without partner:  "gov)"  "(host"
        if t and t[-1] in ")]>}" and t.count(t[-1]) > t.count({")": "(", "]": "[", ">": "<", "}": "{"}[t[-1]]):
            t = t[:-1]
            continue
        if t and t[0] in "([<{" and t.count(t[0]) > t.count(pairs[t[0]]):
            t = t[1:]
            continue
        if t and t[-1] in ",;:!?\"'`":
            t = t[:-1]
            continue
        if t and t[0] in "\"'`":
            t = t[1:]
            continue
        break
    return t, t.strip() != orig.strip()


# ----------------------------------------------------------------------------- IPs
def _classify_net(net, rule: str):
    """ipaddress network -> Hit ("ip" when public, "internal" when private/loopback/link-local) or "ip-too-broad".

    Networks bigger than a /8 (IPv4) or /16 (IPv6) are rejected: they are never a real scope, usually a typo
    such as 0.0.0.0/0.
    """
    ver = net.version
    if net.prefixlen < (8 if ver == 4 else 16):
        return "ip-too-broad"
    kind = "ip" if net.is_global else "internal"
    value = str(net.network_address) if net.num_addresses == 1 else str(net)
    return Hit(kind, value, rule)


def parse_ip(s: str):
    """Understand an IP-ish string. Returns list[Hit] (understood), a reject reason (IP-like but unusable) or None (not an IP).

    Understood forms: 1.2.3.4, 1.2.3.4:8443, CIDR (non-canonical ones such as 203.79.37.2/29 are rewritten to the
    network address, rule "cidr-normalised"), ranges "1.2.3.0-255" and "1.2.3.4 - 1.2.3.20" (turned into the
    smallest list of CIDR blocks, rule "ip-range"), stars "1.2.*.*" (rule "ip-star"), IPv6 with optional
    brackets/port/prefix. Private ranges become kind "internal".
    """
    t = s.strip().lower()
    # IPv6 (optionally [addr]:port, optional /prefix)
    m6 = re.fullmatch(r"\[?([0-9a-f:.]*:[0-9a-f:.]*)\]?(?::\d{1,5})?(?:/(\d{1,3}))?", t)
    if m6 and t.count(":") >= 2:
        txt = m6.group(1) + (f"/{m6.group(2)}" if m6.group(2) else "")
        try:
            net = ipaddress.ip_network(txt, strict=False)
        except ValueError:
            return None
        r = _classify_net(net, "" if "[" not in t else "ip-brackets")
        return [r] if isinstance(r, Hit) else r
    nets, rule = None, ""
    try:
        m = re.fullmatch(rf"({V4})/(\d{{1,2}})", t)
        if m:
            nets = [ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)]
            rule = "" if str(nets[0]) == t else "cidr-normalised"
        if nets is None:
            m = re.fullmatch(rf"({V4}):(\d{{1,5}})", t)
            if m:
                nets = [ipaddress.ip_network(m.group(1))]
        if nets is None:
            m = re.fullmatch(rf"({V4})\s*(?:-|–|to)\s*({V4})", t)
            if m:
                a, b = ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
                nets, rule = _range(a, b), "ip-range"
        if nets is None:
            m = re.fullmatch(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*(?:-|–)\s*(\d{1,3})", t)
            if m:
                a = ipaddress.ip_address(f"{m.group(1)}.{m.group(2)}")
                b = ipaddress.ip_address(f"{m.group(1)}.{m.group(3)}")
                nets, rule = _range(a, b), "ip-range"
        if nets is None:
            m = re.fullmatch(r"((?:\d{1,3}\.){1,3})((?:\*\.?)+)", t)
            if m:
                fixed = [x for x in m.group(1).split(".") if x]
                if len(fixed) + m.group(2).count("*") == 4:
                    ip = ".".join(fixed + ["0"] * (4 - len(fixed)))
                    nets, rule = [ipaddress.ip_network(f"{ip}/{8 * len(fixed)}", strict=False)], "ip-star"
        if nets is None:
            m = re.fullmatch(V4, t)
            if m:
                nets = [ipaddress.ip_network(t)]
    except ValueError:
        return "bad-ip"
    except _TooBig:
        return "ip-range-too-large"
    if nets is None:
        return None
    hits = []
    for n in nets:
        r = _classify_net(n, rule)
        if not isinstance(r, Hit):
            return r
        hits.append(r)
    return hits


class _TooBig(Exception):
    """Raised when an IP range would need more than 256 CIDR blocks (not a sensible scope entry)."""


def _range(a, b):
    """Smallest list of CIDR networks covering addresses a..b (raises ValueError if reversed, _TooBig if huge)."""
    if a > b:
        raise ValueError("reversed")
    nets = list(ipaddress.summarize_address_range(a, b))
    if len(nets) > 256:
        raise _TooBig()
    return nets


# ----------------------------------------------------------------------------- stores, repos, GitHub
def github_project(raw: str):
    """GitHub URL -> canonical lowercase project/org URL ("https://github.com/org/repo"), or None.

    Branches, file paths and ".git" are cut off, so a link to a file inside a repo still gives the repo.
    github.com/<reserved word> (about, features, ...) is not a project, see GH_RESERVED.
    """
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([a-z0-9][a-z0-9_.-]*)(?:/([a-z0-9_.-]+))?", (raw or "").strip(), re.I)
    if not m or m.group(1).lower() in GH_RESERVED:
        return None
    org, repo = m.group(1).lower(), (m.group(2) or "").lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{org}/{repo}" if repo else f"https://github.com/{org}"


def store_app(token: str):
    """Normalised store / marketplace URL, or None. Package ids keep their case."""
    try:
        u = urlsplit(token if "://" in token else "https://" + token)
        host = (u.hostname or "").lower()
    except ValueError:
        return None
    if host not in STORE_HOSTS:
        return None
    path = u.path.rstrip("/")
    if host in ("apps.apple.com", "itunes.apple.com"):
        m = re.search(r"/id(\d+)", path)
        if m:
            return f"https://apps.apple.com/app/id{m.group(1)}"
        return f"https://apps.apple.com{path}" if path else None
    if host == "play.google.com":
        pid = re.search(r"(?:^|&)id=([A-Za-z0-9._]+)", u.query)
        if pid:
            return f"https://play.google.com/store/apps/details?id={pid.group(1)}"
    return f"https://{host}{path}" if path else None


# first label of a reverse-DNS package / bundle id (com.klarna.app, org.signal.messenger, de.bund.app): what tells "com.oyo.consumer" from a host name
_PKG_PREFIX = {"com", "org", "net", "io", "co", "me", "app", "edu", "gov", "de", "fr", "nl", "uk", "jp", "kr", "in", "br", "ru", "us", "se", "fi", "no", "dk",
               "ca", "au", "it", "es", "ch", "at", "be", "pl", "cz", "tr", "il", "sg", "hk", "tw", "cn", "mx", "ar", "id", "vn", "th", "ae", "za", "eu", "ai"}
_PKG_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+){2,}$")


def extract_app_ids(text: str) -> list:
    """The app identifiers inside a free-text app name: store links (Google Play / App Store, with or without https://) and reverse-DNS
    package or bundle ids. "Klarna iOS App (com.klarna.app)" -> ["com.klarna.app"]; a name with neither gives []. Order kept, no repeats."""
    out = []
    for tok in re.split(r"[\s,;()\[\]<>\"']+", text):
        tok = tok.strip(".:-> ")
        if not tok:
            continue
        got = store_app(tok) if re.search(r"(play\.google\.com|apps\.apple\.com|itunes\.apple\.com)", tok, re.I) else None
        if not got and _PKG_RE.match(tok) and tok.split(".")[0] in _PKG_PREFIX:
            got = tok
        if got and got not in out:
            out.append(got)
    return out


def repo_url(token: str):
    """Canonical URL of a repo on GitLab/Bitbucket/Codeberg/..., cut at tree/blob/issues/... segments, or None."""
    try:
        u = urlsplit(token if "://" in token else "https://" + token)
        host = (u.hostname or "").lower()
        if host.startswith("www."):      # str.removeprefix needs Python 3.9; the Pi may have 3.8
            host = host[4:]
    except ValueError:
        return None
    if host not in REPO_HOSTS:
        return None
    segs = []
    for seg in [x for x in u.path.split("/") if x]:
        if seg in REPO_STOP:
            break
        segs.append(seg.lower())
    if host == "sourceforge.net":
        segs = segs[:2]
    if not segs:
        return None
    if segs[-1].endswith(".git"):
        segs[-1] = segs[-1][:-4]
    return f"https://{host}/" + "/".join(segs[:4])


# ----------------------------------------------------------------------------- hosts
def _validate(labels, psl, rule: str, wildcard: bool):
    """Check a list of DNS labels (no template characters) and classify the host.

    Returns a Hit or a reject reason. Decision on the last label (the TLD):
      * it exists in the Public Suffix List       -> "host" (or "wildcard"), with its registrable domain (apex)
      * it does not exist but the FIRST label is a TLD / reverse-DNS word ("com.example.app") -> "app" (package id)
      * otherwise (".internal", ".local", typos)  -> "internal"
    """
    for l in labels:
        if not l:
            return "bad-label"
        if not LABEL_RE.match(l):
            return "bad-chars" if not (l.startswith("-") or l.endswith("-")) else "bad-label"
    tld = labels[-1]
    if tld.isdigit():
        return "numeric-tld"
    if tld in FILE_EXT:
        return "file-ext"
    host = ".".join(labels)
    if len(host) > 253:
        return "too-long"
    if tld in psl.tlds:
        apex = psl.registrable(host)
        if apex is None:
            return "public-suffix"
        return Hit("wildcard" if wildcard else "host", host, rule, apex)
    if labels[0] in psl.tlds or labels[0] in REVERSE_DNS_FIRST:
        return Hit("app", host, "package-id" if not rule else rule + "+package-id")    # com.example.myapp
    return Hit("internal", host, rule)


def _idna(host: str):
    """Unicode host -> punycode ("bücher.de" -> "xn--bcher-kva.de"); None when it cannot be encoded."""
    if host.isascii():
        return host
    try:
        return ".".join(l if l.isascii() else l.encode("idna").decode("ascii") for l in host.split("."))
    except UnicodeError:
        return None


def parse_host(h: str, psl, rules: list):
    """Classify host text that is already lowercase and has no scheme / port / path. -> list[Hit] | reject reason.

    Handles: plain hosts, leading-dot wildcards (".example.com"), "*.example.com" wildcards, and templates
    ("api-*.example.com", "{tenant}.example.com") which become a "pattern" hit plus, when the part after the
    template is a real domain, a normal host hit for that domain (rule "pattern-tail").
    `rules` is the list of repairs already applied, copied into each Hit.rule.
    """
    h = h.strip().rstrip(".")
    if ".." in h:
        h = re.sub(r"\.{2,}", ".", h)
        rules.append("double-dot")
    leading_dot = h.startswith(".")
    h = h.lstrip(".")
    if not h:
        return "empty"
    h = _idna(h)
    if h is None:
        return "bad-idn"
    labels = h.split(".")
    if len(labels) < 2:
        return "single-label"
    rule = ";".join(dict.fromkeys(rules))
    pat = [i for i, l in enumerate(labels) if any(c in PATTERN_CHARS for c in l)]
    if not pat:
        if leading_dot:
            r = _validate(labels, psl, "leading-dot", True)
        else:
            r = _validate(labels, psl, rule, False)
        return [r] if isinstance(r, Hit) else r
    if pat == [0] and labels[0] == "*":
        r = _validate(labels[1:], psl, rule, True) if len(labels) >= 3 or len(labels[1:]) >= 2 else "single-label"
        return [r] if isinstance(r, Hit) else r
    # patterns / templates
    norm = []
    for l in labels:
        if any(c in l for c in "{}<>[]$%"):
            norm.append("*")
        else:
            norm.append(l)
    if any(not re.fullmatch(r"[a-z0-9_*-]+", l) for l in norm):
        return "bad-chars"
    hits = [Hit("pattern", ".".join(norm), "pattern")]
    tail = labels[max(pat) + 1:]
    if len(tail) >= 2:
        r = _validate(tail, psl, "pattern-tail", False)
        if isinstance(r, Hit) and r.kind == "host":
            hits.append(r)
    return hits


# ----------------------------------------------------------------------------- one token (no spaces)
def parse_token(tok: str, psl, orig: str = ""):
    """Parse ONE token (text without spaces). -> (list[Hit], reject reason or None).

    `tok` keeps its original upper/lower case because package ids and store ids are case sensitive; it is only
    lowercased once we know it is a host. Steps: strip wrapping punctuation, ASN, GitHub, app store, other repo
    hosts, IPs (before the "/" of a CIDR gets treated as a path), scheme/userinfo/port/path removal, then host
    validation in parse_host. `orig` is unused and kept for call compatibility.
    """
    rules: list = []
    t, changed = strip_wrap(tok)
    if changed:
        rules.append("punctuation")
    if not t:
        return [], "empty"
    # --- ASN written alone ("AS16314"); also reached for each word of a list such as "AS1, AS2"
    asn = parse_asn(t)
    if asn and not asn[1]:
        return [Hit("asn", asn[0], ";".join(rules))], None
    # --- GitHub / other code hosts / stores (before any lowercase-and-split)
    gh = github_project(t)
    if gh:
        return [Hit("github", gh, ";".join(rules))], None
    if re.match(r"^(?:https?://)?(?:www\.)?github\.com/+[^/?#\s]", t, re.I):
        return [], "not-a-project"                                  # github.com/about, /features, ... (plain github.com stays a host)
    app = store_app(t)
    if app:
        return [Hit("app", app, ";".join(rules + ["store-url"]))], None
    rp = repo_url(t)
    if rp:
        return [Hit("repo", rp, ";".join(rules))], None
    tl = t.lower()
    # --- IPs (CIDR, ranges, wildcards, IPv6) before the scheme / path split eats the '/24'
    body = SCHEME_RE.sub("", tl)
    ipr = parse_ip(body.rstrip("/"))
    if isinstance(ipr, list):
        return [Hit(h.kind, h.value, ";".join(x for x in [h.rule, *rules] if x)) for h in ipr], None
    if isinstance(ipr, str):
        return [], ipr
    # --- scheme, userinfo, path, port
    m = SCHEME_RE.match(tl)
    if m:
        s = m.group(0)
        if not re.fullmatch(r"[a-z][a-z0-9+.-]*://", s, re.I) and not s.lower().startswith("mailto"):
            rules.append("scheme-typo")                              # "http//host", "https:host"
        tl = tl[m.end():]
    auth = re.split(r"[/?#\\]", tl, maxsplit=1)[0]
    # What follows the host, with the ORIGINAL letter case (paths are case sensitive). Lowercasing never changes the length of
    # ASCII text; if it did (rare Unicode letters) we simply take no path.
    body = t[m.end():] if m else t
    path = url_path(body[len(auth):]) if len(body) == len(tl) else ""
    scheme = m.group(0).lower() if m else ""
    if "@" in auth:
        rules.append("email" if "://" not in t and not m else "userinfo")
        auth = auth.rsplit("@", 1)[1]
    port = re.search(r":(\d{1,5})$", auth)
    auth = re.sub(r":(?:\d{1,5}|\*)$", "", auth)
    if not auth:
        return [], "empty"
    # A URL is written scheme://host[:port]/path. Only http(s) schemes are kept as written; no scheme means https.
    # (We never invent "http": a missing scheme is far more often a web address than plain text.)
    if scheme in ("http://", "https://") or not scheme:
        scheme_out = scheme or "https://"
    elif scheme.endswith("://"):
        scheme_out = scheme                                          # ftp://, wss:// ... kept as given
    else:
        scheme_out = "https://"                                      # typo forms such as "http//" or "https:"; rule "scheme-typo" is already set
    host_port = auth + (":" + port.group(1) if port else "")

    def as_url(hits):
        """The same hits as a single url hit, when the entry has a path and the host is a normal public one."""
        if not path or not hits or any(h.kind not in ("host", "wildcard", "ip") or "/" in h.value for h in hits):
            return None
        value = f"{scheme_out}{host_port}{path}"
        if len(value) > 300:
            return None
        return [Hit("url", value, ";".join(rules))]
    # IPv6 literal with brackets after the port strip, or plain IPv4 after userinfo/port strip
    ipr = parse_ip(auth)
    if isinstance(ipr, list):
        u = as_url(ipr)                                             # http://203.0.113.5/admin is a URL, not "the IP 203.0.113.5"
        if u:
            return u, None
        return [Hit(h.kind, h.value, ";".join(x for x in [h.rule, *rules] if x)) for h in ipr], None
    if isinstance(ipr, str):
        return [], ipr
    if re.search(r"[^a-z0-9._*{}<>\[\]$%\-\u0080-￿]", auth):
        return [], "bad-chars"
    if auth in STORE_HOSTS:
        return [], "store-host"                      # a bare app-store / marketplace host is not a target
    r = parse_host(auth, psl, rules)
    if isinstance(r, str):
        return [], r
    u = as_url(r)                                                   # host + real path: the PATH is the scope, so no apex/subdomain is stored
    if u:
        return u, None
    out = []
    for h in r:                                    # package ids are case sensitive: give back the original spelling
        if h.kind == "app":
            m2 = re.search(re.escape(h.value), t, re.I)
            if m2:
                h = Hit(h.kind, t[m2.start():m2.end()], h.rule, h.apex)
        out.append(h)
    return out, None


# ----------------------------------------------------------------------------- URLs with a path
def url_path(rest: str) -> str:
    """Normalise what follows the host of a URL into the path that matters for scope; "" when there is none.

    "/kubernetes-release/" -> "/kubernetes-release"      trailing slashes are not part of the meaning
    "/api/*", "/api/**"    -> "/api"                     a trailing wildcard only says "and everything below", which a URL entry
                                                         already means (the scope check treats a url as a prefix)
    "/", "/*", "?x=1", "#a" -> ""                        no path: the entry is really about the whole host
    Query string and fragment are dropped (they are not part of a scope). Case is kept: paths are case sensitive.
    """
    path = re.split(r"[?#]", rest, maxsplit=1)[0].replace("\\", "/")
    path = re.sub(r"/{2,}", "/", path).rstrip("/*")
    return path if path.strip("/") else ""


# ----------------------------------------------------------------------------- one raw entry
def clean_text(raw: str):
    """First-pass text clean-up of a raw entry. Returns (text, rules applied).

    Removes invisible characters, un-defangs ("hxxps://evil[.]com"), unwraps markdown links/bold/backticks.
    """
    s = (raw or "").translate(ZERO_WIDTH).replace(" ", " ").strip()
    rules = []
    s2, ch = defang(s)
    if ch:
        rules.append("defang")
    s = s2
    m = re.fullmatch(r"\[([^\]]+)\]\((\S+?)\)", s)               # markdown link [text](url)
    if m:
        s, rules = m.group(2), rules + ["markdown"]
    elif re.fullmatch(r"\*\*(?!\.)(.+?)\*\*", s) or re.fullmatch(r"__(.+?)__", s):
        s, rules = s.strip("*_"), rules + ["markdown"]
    if "`" in s:
        s, rules = s.replace("`", ""), rules + ["markdown"]
    return s.strip(), rules


# ----------------------------------------------------------------------------- alternatives: {com,co.uk} (se|fi).x.com
# Programs shorten lists of near-identical hosts with a group of choices. Examples and what they mean:
#   *.nymhair.{com,co.uk,uk,}        -> *.nymhair.com  *.nymhair.co.uk  *.nymhair.uk      (the empty choice is dropped)
#   (se|fi|uk).bingo.com             -> se.bingo.com  fi.bingo.com  uk.bingo.com
#   https://www.decathlon.(hu|ro|com.tr) -> https://www.decathlon.hu  ...ro  ...com.tr
#   [it | fr | us | sg | …].louisvuitton.com -> *.louisvuitton.com   (the dots mean "and so on" = every country)
# A group counts as a list of choices only when ALL of this is true (so ordinary brackets and comments stay as they are):
#   * it is written with (), [] or {} and contains a separator "," or "|" (so a single "{tenant}" stays a template);
#   * it touches a dot ("x.(a|b)" or "(a|b).x"), i.e. it is a piece of a host name, not a remark after a space;
#   * every choice is a valid piece of a name (letters, digits, "-", "_", "."), spaces around "|" or "," allowed;
#   * the product of all groups stays small (MAX_EXPANSION), so a typo cannot produce thousands of hosts.
GROUP_RE = re.compile(r"[\[({]([^\[\](){}]{1,200})[\])}]")
CHOICE_RE = re.compile(r"[a-z0-9_-][a-z0-9_.-]*", re.I)
ELLIPSIS = {"…", "...", "..", "etc", "etc.", "others", "other"}
MAX_EXPANSION = 64


def expand_alternatives(s: str):
    """-> (list of expanded entries, rule) or None when the entry has no group of choices.

    rule is "alternatives", or "ellipsis-wildcard" when a group ended in "…" / "..." / "etc" and was replaced by "*".
    Several groups in one entry are multiplied out ("{a,b}.x.{com,net}" -> 4 entries).
    """
    results, rule = [s], ""
    while True:
        target = None
        for text in results:
            for m in GROUP_RE.finditer(text):
                before, after = text[:m.start()][-1:], text[m.end():][:1]
                inner = m.group(1)
                if "," not in inner and "|" not in inner:
                    continue
                if before != "." and after != ".":
                    continue
                parts = [x.strip() for x in re.split(r"[,|]", inner)]
                dots = [x for x in parts if x.lower() in ELLIPSIS]
                names = [x for x in parts if x and x.lower() not in ELLIPSIS]
                if not all(CHOICE_RE.fullmatch(x) for x in names) or not (names or dots):
                    continue
                target = (text, m, names, bool(dots))
                break
            if target:
                break
        if not target:
            return (results, rule) if rule else None
        text, m, names, ellipsis = target
        i = results.index(text)
        if ellipsis:
            new = [text[:m.start()] + "*" + text[m.end():]]
            rule = "ellipsis-wildcard"
        else:
            new = [text[:m.start()] + x + text[m.end():] for x in dict.fromkeys(names)]
            rule = rule or "alternatives"
        results[i:i + 1] = new
        if len(results) > MAX_EXPANSION:
            return None


def _with(hits, extra):
    """Copy hits with extra repair rules added to their rule field (used to record what was repaired)."""
    out = []
    for h in hits:
        rule = ";".join(dict.fromkeys(x for x in [*extra, *([h.rule] if h.rule else [])] if x))
        out.append(Hit(h.kind, h.value, rule, h.apex))
    return out


def parse_entry(raw: str, psl) -> Parsed:
    """The public entry point: understand one raw scope string. See the module docstring for the decision order."""
    s, pre = clean_text(raw)
    if not s or s.startswith("#"):
        return Parsed(blank=True)
    # Tags a source puts in FRONT of an entry to say how it was found (several may be chained, e.g. "api:desc:host"):
    #   desc:   found inside a description / instruction text, not in the asset list proper  -> rule "from-description"
    #   guess:  same, but only mentioned in a sentence (not a list item)                      -> every hit becomes kind "maybe"
    #   api:    the platform itself declared the asset type as API                            -> rule "declared-api"
    tag = re.match(r"(desc|guess|api):(?=\S)", s, re.I)
    if tag:
        which = tag.group(1).lower()
        inner = parse_entry(s[tag.end():], psl)
        if not inner.hits:
            return inner
        if which == "guess":
            return Parsed([Hit("maybe", h.value, "from-description", h.apex) for h in inner.hits
                           if h.kind in ("host", "wildcard", "url", "ip", "asn")] or inner.hits)
        return Parsed(_with(inner.hits, ["from-description" if which == "desc" else "declared-api"]))
    if s.lower().startswith("app:"):                              # a platform file said "this is an app"
        val = s[4:].strip()
        if not val:
            return Parsed(reject="free-text")
        if re.search(r"\s", val):                                  # "Klarna iOS App (com.klarna.app)", "Foo -> https://play.google.com/...": keep what IS an id
            found = extract_app_ids(val)
            return Parsed([Hit("app", a, "app-extracted") for a in found]) if found else Parsed(reject="free-text")
        return Parsed([Hit("app", store_app(val) or val, "")])
    expanded = expand_alternatives(s)
    if expanded:                                                   # "{com,co.uk}", "(se|fi).x.com": parse each choice on its own
        strings, rule = expanded
        hits, reasons = [], []
        for x in strings:
            sub = parse_entry(x, psl)
            hits += sub.hits
            if sub.reject:
                reasons.append(sub.reject)
        hits = list(dict.fromkeys(hits))
        return Parsed(_with(hits, pre + [rule])) if hits else Parsed(reject=reasons[0] if reasons else "free-text")
    if s.lower() in PLACEHOLDERS or re.fullmatch(r"[-–—_.*/\s]+", s):
        return Parsed(reject="placeholder")
    asn = parse_asn(s)                                             # "AS16314", "AS6720 IPv6 1/2"
    if asn:
        return Parsed(_with([Hit("asn", asn[0], "comment-stripped" if asn[1] else "")], pre))
    # "1.2.3.4 - 1.2.3.20" / "1.2.3.4 to 1.2.3.20" (spaces) and "1.2.3.0 - 255"
    ipr = parse_ip(s)
    if isinstance(ipr, list):
        return Parsed(_with(ipr, pre))
    hits, reason = ([], None) if re.search(r"\s", s) else parse_token(s, psl)     # spaces: a list or a sentence, not one URL
    if hits:
        return Parsed(_with(hits, pre))
    if not re.search(r"[\s,;|]", s) and not re.search(r"[()]", s):
        return Parsed(reject=reason or "bad-chars")
    return _parse_text(s, psl, pre, reason)


def _parse_text(s: str, psl, pre, whole_reason):
    """Entry with spaces / commas / comments. Three outcomes, in this order:

    A1. every non-host word is a connector ("a.com and b.org")  -> several clean hits, rule "multi-entry"
    A2. starts with a host followed by a comment ("host (note)", "host - note", "host: note")
                                                               -> that host, rule "comment-stripped"
    B.  hosts / URLs / IPs / ASNs mentioned inside a sentence   -> kind "maybe" (a guess, needs a human look);
        GitHub / repo / store links inside a sentence still go to their own asset type, rule "text-extract"
    Anything else is rejected as "free-text".
    """
    toks = [t for t in re.split(r"[\s,;|]+", s) if t]
    parsed = []                                                    # (token, hits)
    others = []
    for t in toks:
        h, _ = parse_token(t, psl)
        h = [x for x in h if x.kind in ("host", "wildcard", "url", "ip", "asn", "github", "repo") or (x.kind == "app" and "store-url" in x.rule)]
        if h:
            parsed.append((t, h))
        else:
            others.append(t.strip("()[]<>{}\"'.,;:").lower())
    if not parsed:
        return Parsed(reject="free-text" if re.search(r"\s", s) else (whole_reason or "bad-chars"))
    # A: every other word is a connector  -> a list of real entries
    if all(o in CONNECTORS or o == "" for o in others):
        return Parsed(_with([x for _, hs in parsed for x in hs], pre + ["multi-entry"]))
    # A: "host (comment)"  /  "host - comment"  /  "host: comment"
    first_tok, first_hits = parsed[0]
    idx = s.find(first_tok)
    if idx >= 0 and s[:idx].strip("([<{\"'`") == "":
        rest = s[idx + len(first_tok):].lstrip()
        if rest[:1] in ("(", "[", "-", "–", "—", ":") or first_tok.endswith(":"):
            hits = _with(first_hits, pre + ["comment-stripped"])
            for _, hs in parsed[1:]:                               # more hosts inside the comment: only a lead
                hits += [Hit("maybe", x.value, "text-extract", x.apex) for x in hs if x.kind in ("host", "wildcard", "url", "ip", "asn")]
            return Parsed(hits)
    # B: hosts mentioned inside a sentence -> maybe (review by hand)
    hits = [Hit("maybe", x.value, "text-extract", x.apex) for _, hs in parsed for x in hs if x.kind in ("host", "wildcard", "url", "ip", "asn")]
    others_hits = [x for _, hs in parsed for x in hs if x.kind in ("github", "repo", "app")]
    hits += _with(others_hits, pre + ["text-extract"])
    return Parsed(hits) if hits else Parsed(reject="free-text")
