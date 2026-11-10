"""textscope: find scope entries that a program wrote into DESCRIPTION / INSTRUCTION text instead of the asset list.

Why this exists
---------------
Many programs list one broad asset ("*.yahoo.com", "Other", "Web application") and then put the REAL list of
targets into the free-text description of that asset: hundreds of hosts, URL paths, API endpoints, plus a few
"out of scope" lines. The platform page shows them when you click "expand asset". Reading only the asset NAME
(what the first versions did) therefore misses most of the scope. This module reads the text as well.

What it does (stdlib only, Python 3.8)
--------------------------------------
rows_from_text(text, status, prog, purl, psl) -> [(raw, status, prog, purl), ...]    the same row shape every source returns

  1. Clean the text: HTML tags and entities, markdown links/bold/backticks.
  2. Go through it line by line and remember the SECTION we are in:
       a heading-like line with "out of scope / not in scope / excluded / do not test ..." switches to OUT-OF-SCOPE,
       a heading-like line with "in scope / targets ..." switches back to IN-SCOPE.
     A normal sentence that contains such a word marks only its own tokens.
  3. Pick the tokens of every line: URLs, wildcards, hosts, host/path, IPs and CIDR ranges.
     Mail addresses, file names (app.js), the platform's own sites, social/doc sites and example domains are dropped.
  4. Decide how much to trust a token:
       in a list item / table row / line made of the token            -> "desc:<token>"   (a real entry; rule "from-description")
       only mentioned inside a sentence                               -> "guess:<token>"  (goes to maybe.txt, a human looks)
       in an out-of-scope section or sentence                         -> (token, "out-of-scope")
     The "desc:" / "guess:" tags are understood by scopeparse.parse_entry; the PSL check there throws away
     everything that is not a real domain name.

The bounty status of an extracted entry is the bounty status of the asset (or program) the text belongs to.
Nothing here ever fails the run: a bad text just gives no rows.
"""
from __future__ import annotations

import html
import re

OOS = "out-of-scope"                  # same value as update_bb_domains.OOS (kept literal so this module has no imports)
MAX_ROWS = 3000                       # per text; a safety net against a pasted wordlist
MAX_TEXT = 400_000                    # characters read from one text

# ----- section words
OOS_RE = re.compile(r"out[\s-]*of[\s-]*scope|not\s+in[\s-]*scope|non[\s-]*scope|not\s+eligible|ineligible|excluded?|exclusions?|"
                    r"do\s+not\s+test|don'?t\s+test|must\s+not\s+be\s+tested|prohibited|forbidden|not\s+part\s+of", re.I)
IN_RE = re.compile(r"(?<!out of )(?<!not )(?<!out-of-)\bin[\s-]*scope\b|\bscope\b|eligible\s+(?:targets?|assets?|domains?)|"
                   r"\btargets?\b|\bassets?\b|\bdomains?\b|\bendpoints?\b|\bapis?\b", re.I)

# ----- tokens
URL_RE = r"(?:https?|ftp)://[^\s<>\"'`\\]+"
HOST_RE = (r"(?:\*\.)?(?:[a-z0-9_-]+\.)+[a-z]{2,24}(?::\d{1,5})?(?:/[^\s<>\"'`\\]*)?")
IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"
TOKEN_RE = re.compile(rf"(?<![\w@./+-])(?:{URL_RE}|{IP_RE}|{HOST_RE})", re.I)
TRIM = ".,;:!?)]}>*\"'`"

# hosts that are never targets when they only appear in prose: the platforms, docs, social media, examples
NOISE_APEX = {
    "hackerone.com", "hackerone-user-content.com", "intigriti.com", "intigriti.me", "bugcrowd.com", "yeswehack.com", "hackenproof.com",
    "immunefi.com", "openbugbounty.org", "twitter.com", "x.com", "facebook.com", "linkedin.com", "youtube.com", "youtu.be",
    "instagram.com", "medium.com", "wikipedia.org", "w3.org", "owasp.org", "mitre.org", "nist.gov", "first.org", "cvss.org",
    "localhost", "wikimedia.org", "stackoverflow.com", "reddit.com", "discord.gg",
    "discord.com", "t.me", "telegram.org", "gitbook.io", "notion.so", "notion.site", "docs.google.com", "drive.google.com",
    "forms.gle", "goo.gl", "bit.ly", "tinyurl.com", "calendly.com", "mozilla.org", "apple.com/legal", "ietf.org", "rfc-editor.org",
}
# placeholders: only these exact names (a real program may well own sub.example.com in a test or demo)
EXACT_NOISE = {"example.com", "www.example.com", "example.org", "www.example.org", "example.net", "www.example.net", "test.com", "domain.com", "yourdomain.com", "target.com"}
# the last label of a "host" that is really a file name (readme.md, app.js ...): never a domain here
FILE_TLDS = {"js", "css", "json", "html", "htm", "php", "py", "sh", "txt", "png", "jpg", "jpeg", "gif", "svg", "pdf", "md", "xml",
             "yml", "yaml", "exe", "zip", "gz", "tar", "rb", "java", "cs", "go", "so", "dll", "log", "csv", "ini", "conf", "bak", "env"}


def clean(text: str) -> str:
    """Plain text with one item per line: tags, entities and markdown decoration removed."""
    t = text[:MAX_TEXT]
    t = re.sub(r"(?i)<\s*(?:br|/p|/li|/tr|/div|/h\d|li|tr)\b[^>]*>", "\n", t)
    t = re.sub(r"(?i)</t[dh]\s*>", " | ", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(t)
    # [label](https://x) keeps both; images and reference marks go
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", t)
    t = re.sub(r"\[([^\]]*)\]\(([^)\s]+)[^)]*\)", r"\1 \2 ", t)
    t = t.replace("\\_", "_").replace("\\*", "*").replace("​", "").replace("\xa0", " ")
    t = re.sub(r"[`]+", " ", t)
    t = re.sub(r"(?<!\*)\*\*(?!\*)", "", t)               # **bold** (a lone "*.example.com" stays)
    return t.replace("\r", "\n")


def page_text(page_html: str) -> str:
    """The readable text of a web page: scripts, styles, menus and footers removed, so only the program's own words are left
    (a link in a menu or footer is never a target). Used for the self-hosted program pages."""
    t = re.sub(r"(?is)<!--.*?-->|<(script|style|noscript|svg|nav|footer|header|form|template)\b.*?</\1\s*>", " ", page_html[:3_000_000])
    return t


def _is_list_line(line: str, tok: str) -> bool:
    """A line that IS an entry: bullet / number / table row / nothing but the token and a short remark."""
    s = line.strip()
    if re.match(r"^(?:[-*+•▪◦●»>]|\d+[.)]|\|)\s*", s):
        return True
    rest = s.replace(tok, " ", 1).strip(" \t-–—:|,;")
    return len(rest) <= 40                                 # "api.example.com (production)" / "api.example.com - v2"


def _heading_like(line: str) -> bool:
    s = re.sub(r"^[#>*\-\s]+", "", line.strip()).rstrip("*_ ")
    return bool(s) and (len(s) <= 90 or s.endswith(":")) and not TOKEN_RE.search(s.split(":")[0] if ":" in s else s)


def _noise(tok: str) -> bool:
    """True for tokens that cannot be a target: mail, files, the platforms' own sites, doc / social sites, examples."""
    host = re.sub(r"^[a-z]+://", "", tok.lower()).split("/")[0].split(":")[0].lstrip("*.")
    if not host or "@" in tok:
        return True
    if re.fullmatch(r"\d+(?:\.\d+){3}", host):             # an IP: version numbers like 1.2.3.4 are rare, scopeparse validates
        return False
    labels = host.split(".")
    if labels[-1] in FILE_TLDS and "/" not in tok and "://" not in tok:
        return True
    if host in EXACT_NOISE or any(host == n or host.endswith("." + n) for n in NOISE_APEX if "/" not in n):
        return True
    return False


def rows_from_text(text, status: str, prog: str, purl: str, psl=None) -> list:
    """All scope rows hidden in one description / instruction text (see the module docstring)."""
    if not isinstance(text, str) or len(text) < 4:
        return []
    out, seen = [], set()
    state = None                                           # None / "in" / "oos": the section the current line belongs to
    for line in clean(text).split("\n"):
        line = line.strip()
        if not line:
            continue
        has_oos, has_in = bool(OOS_RE.search(line)), bool(IN_RE.search(line))
        heading = _heading_like(line)
        if heading and has_oos:
            state = "oos"
        elif heading and has_in:
            state = "in"
        toks = []
        for m in TOKEN_RE.finditer(line):
            tok = m.group(0).rstrip(TRIM)
            if tok.endswith("(") or not tok or _noise(tok):
                continue
            toks.append(tok)
        for tok in toks:
            if state == "oos" or (has_oos and not heading and not has_in):
                key, row = ("o", tok), (tok, OOS, prog, purl)
            elif _is_list_line(line, tok) and not (has_oos and not heading):
                key, row = ("d", tok), ("desc:" + tok, status, prog, purl)
            else:
                key, row = ("g", tok), ("guess:" + tok, status, prog, purl)
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
            if len(out) >= MAX_ROWS:
                return out
    return out


def merge(*row_lists) -> list:
    """Concatenate row lists, keeping the first occurrence of each row (rows are tuples)."""
    seen, out = set(), []
    for rows in row_lists:
        for r in rows:
            if r not in seen:
                seen.add(r)
                out.append(r)
    return out
