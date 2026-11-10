#!/usr/bin/env python3
"""bbclean - normalize and validate hostnames for the bug bounty pipeline (stdlib only).

ROLE IN THE PROJECT: a standalone command-line cleaner (handy for ad-hoc lists). The daily pipeline does NOT call
it any more (scopeparse.py replaced it); scopeparse only imports three constants from here (LABEL_RE, FILE_EXT,
REVERSE_DNS_FIRST). It is safe to keep or to delete if you also move those three constants into scopeparse.py.

Reads lines from files or stdin and prints cleaned, de-duplicated, sorted hostnames.

What it does to each line
  - lowercases; strips scheme, path, query, user@, :port, "*." prefix and trailing dots
  - converts non-ASCII (IDN) names to punycode; rejects hidden/bidi characters
  - rejects: IPs, single labels, leading dots (".com"), bad characters/spaces, numeric TLDs,
    file-like endings (".html"), bare public suffixes ("co.uk"), reverse-DNS app ids
    ("com.example.app")
  - with --tlds FILE (IANA list): rejects names whose TLD does not exist ("aon.comcreate")
  - with --deny FILE: drops names under shared multi-tenant platforms (amazonaws.com, ...)

Every rejected line can be logged with its reason: --rejects FILE  (reason<TAB>original line)

Examples
  bbclean.py < raw.txt > clean.txt
  bbclean.py --tlds tlds.txt --deny shared-infra-denylist.txt --rejects rej.txt --stats raw.txt
"""
import argparse
import re
import sys
from collections import Counter

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# Endings that mean "this is a file name, not a host". Real TLDs such as .zip .mov .md .sh .py are NOT listed.
FILE_EXT = set("html htm php aspx asp jsp js json css png jpg jpeg gif svg txt xml pdf".split())

# First labels typical for reverse-DNS app ids (com.example.app).
REVERSE_DNS_FIRST = {"com", "org", "net", "io", "edu", "gov"}

# Used only for the reverse-DNS heuristic when no --tlds file is given.
COMMON_TLDS = set((
    "com org net io co uk de nl fr it es ru jp cn in br au ca ch be se no dk fi pl cz at pt gr tr ie nz za mx ar cl "
    "kr tw hk sg my id ph th vn ae sa il ua ro hu sk bg hr lt lv ee si rs info biz app dev ai tv me cc xyz online "
    "site tech cloud edu gov mil eu us int name pro mobi world network money bank finance crypto exchange games "
    "game live store shop link page space top club one fun ly to sh so gg is im la ws"
).split())

# Two-level public suffixes that sometimes show up as if they were domains.
PUBLIC_SUFFIXES = set((
    "co.uk org.uk ac.uk gov.uk me.uk net.uk ltd.uk plc.uk sch.uk com.au net.au org.au edu.au gov.au co.nz org.nz "
    "net.nz govt.nz ac.nz co.za org.za gov.za co.jp or.jp ne.jp ac.jp go.jp com.br net.br org.br gov.br com.cn "
    "net.cn org.cn gov.cn com.mx org.mx com.tr org.tr com.ar com.co co.in net.in org.in co.il org.il co.kr or.kr "
    "com.sg com.hk com.tw com.my com.ph com.vn co.id or.id co.th com.ua com.pl com.pt com.es com.ng co.ke"
).split())


def load_set(path, lower=True):
    items = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                items.add(line.lower() if lower else line)
    return items


def clean_line(raw, tlds):
    """Return (host, None) when usable, (None, reason) when rejected, (None, None) when blank/comment."""
    s = raw.strip().lstrip("﻿").strip("\"'<>,;")
    if not s or s.startswith("#"):
        return None, None
    s = s.lower()
    s = SCHEME_RE.sub("", s)
    s = re.split(r"[/?#\\]", s, maxsplit=1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = re.sub(r":\d{1,5}$", "", s)
    if s.startswith("*."):
        s = s[2:]
    s = s.rstrip(".")
    if not s:
        return None, "empty"
    if s.startswith("."):
        return None, "leading-dot"
    if IPV4_RE.match(s):
        return None, "ip"
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "bad-idn"
    if len(s) > 253:
        return None, "too-long"
    labels = s.split(".")
    if len(labels) < 2:
        return None, "single-label"
    if any(not LABEL_RE.match(label) for label in labels):
        return None, "bad-chars"
    tld = labels[-1]
    if tld.isdigit():
        return None, "numeric-tld"
    if tld in FILE_EXT:
        return None, "file-ext"
    if s in PUBLIC_SUFFIXES:
        return None, "public-suffix"
    if tlds is not None:
        if tld not in tlds:
            return None, "bad-tld"
    elif labels[0] in REVERSE_DNS_FIRST and len(labels) >= 3 and tld not in COMMON_TLDS:
        return None, "reverse-dns"
    return s, None


def is_denied(host, deny):
    parts = host.split(".")
    return any(".".join(parts[i:]) in deny for i in range(len(parts)))


def main():
    ap = argparse.ArgumentParser(description="Normalize and validate hostnames (stdlib only).")
    ap.add_argument("files", nargs="*", help="input files (default: stdin)")
    ap.add_argument("--tlds", help="IANA TLD list (tlds-alpha-by-domain.txt); enables the bad-tld check")
    ap.add_argument("--deny", help="shared-infrastructure denylist: drop these apexes and everything under them")
    ap.add_argument("--rejects", help="write 'reason<TAB>line' for every rejected line to this file")
    ap.add_argument("--stats", action="store_true", help="print a summary to stderr")
    args = ap.parse_args()

    tlds = load_set(args.tlds) if args.tlds else None
    deny = load_set(args.deny) if args.deny else set()

    def lines():
        if args.files:
            for path in args.files:
                with open(path, encoding="utf-8", errors="replace") as f:
                    yield from f
        else:
            yield from sys.stdin

    keep, reasons = set(), Counter()
    rej = open(args.rejects, "w", encoding="utf-8") if args.rejects else None
    total = 0
    for raw in lines():
        host, reason = clean_line(raw, tlds)
        if host is None and reason is None:
            continue
        total += 1
        if host is not None and deny and is_denied(host, deny):
            host, reason = None, "shared-infra"
        if host is None:
            reasons[reason] += 1
            if rej:
                rej.write("%s\t%s\n" % (reason, raw.rstrip("\r\n")))
        else:
            keep.add(host)
    if rej:
        rej.close()

    out = sys.stdout
    for host in sorted(keep):
        out.write(host + "\n")

    if args.stats:
        sys.stderr.write("bbclean: %d lines in, %d kept (unique), %d rejected\n" % (total, len(keep), sum(reasons.values())))
        for reason, n in reasons.most_common():
            sys.stderr.write("  %-14s %d\n" % (reason, n))


if __name__ == "__main__":
    main()
