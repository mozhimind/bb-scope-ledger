#!/usr/bin/env python3
"""build_site.py - turns the files of the daily run (data/, history/) into a static website with a static API.

    python3 site/build_site.py                      # reads ./data and ./history, writes ./site/public
    python3 site/build_site.py --out /var/www/bb    # another output folder
    BB_ROOT=/some/project python3 site/build_site.py

WHAT COMES OUT (everything is a plain file: no database, no server code; any web server can host it)
    public/index.html, app.js, style.css ...   the web UI (copied from site/ui/)
    public/api/v1/index.json                   list of every endpoint, the date of the data, the asset types
    public/api/v1/stats.json                   the numbers of the last run + per-platform table + headline cards
    public/api/v1/history.json                 daily counts / new / removed per asset type (charts)
    public/api/v1/sources.json                 health of every source (the "Sources today" table)
    public/api/v1/programs.json                every program: platform, hosting, bounty, number of values per asset type
    public/api/v1/programs/<slug>.json         one program with its whole scope
    public/api/v1/programs/<slug>/<asset>.txt  one program's values of one asset type, one per line (pipe into tools)
    public/api/v1/assets/<asset>[-paying|-new|-removed].txt   the lists of data/ (plus master.txt)
    public/api/v1/platforms/<platform>/<asset>[-paying].txt   what one platform lists (hackerone, bugcrowd, ..., self-hosted)
    public/api/v1/feeds/new.txt, new-paying.txt, removed.txt  today's changes, one value per line
    public/api/v1/changes/index.json, latest.json, <date>.json   what was new / removed per day, with context
    public/api/v1/scope/<asset>.json           every value of an asset type with bounty, hosting, sources, programs (search)
    public/api/v1/out-of-scope/<asset>.txt, master.txt           what programs EXCLUDE (an exclusion list for your tools)
    public/api/v1/out-of-scope.json            every excluded value with the programs that exclude it (the scope check uses it)
    public/api/v1/programs/<slug>/out-of-scope.txt               what one program excludes
    public/api/v1/quality/rejected.json, recovered.json          what the parser could not / only partly understand

IMPORTANT FACTS
    * Standard library only. The output folder is built next to the target and swapped in at the end, so a web server
      that is running never serves a half-built site.
    * Program ids are the same as in data/programs.txt (column id, see program_id in update_bb_domains.py). A program's
      slug is its name + id, for example "zoho-3fa91c0b2d".
    * scope/<asset>.json refers to programs by their position in programs.json (a small number instead of a long name).
    * Old data without the newer files (programs.txt id column, program-scope.tsv, stats.json) still builds: the parts
      that need them are simply empty.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import insights  # noqa: E402  (extra facts: third-party hosting, shared hosts, IP space ...)

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("BB_ROOT") or HERE.parent)
API = "api/v1"

# Same order as ASSETS in update_bb_domains.py (file name stems of data/).
OVERLAY = {"wildcards", "apis"}     # lists that only repeat values of other lists: kept out of totals so nothing is counted twice
ASSETS = ["apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"]
ASSET_INFO = {
    "apex": "Registrable domains (example.com)",
    "subdomains": "Hosts below an apex (app.example.com)",
    "wildcards": "Wildcard bases (*.example.com is stored as example.com)",
    "apis": "APIs: platform-declared API assets and addresses that look like one (api.x.com, /api/, /graphql, /v1/); also listed in subdomains or urls",
    "urls": "Addresses with a path: the path is the scope (https://storage.googleapis.com/kubernetes-release)",
    "ips": "IP addresses and CIDR ranges",
    "asn": "Autonomous system numbers (AS16314)",
    "github": "In-scope GitHub projects and organisations",
    "repos-other": "Repos on GitLab, Bitbucket and others",
    "apps": "Store URLs and package ids",
    "patterns": "Wildcards and templates that cannot become one host (api-*.example.com)",
    "internal-hosts": "Private, internal or non-public hosts (reference only)",
    "maybe": "Hosts found inside free text: a guess, check by hand",
}
BOUNTY_CODE = {"paying": 0, "non-paying": 1, "unknown": 2}
HOSTING_CODE = {"platform": 0, "self-hosted": 1, "both": 2, "unknown": 3}

# program page domain -> platform key shown in the UI and used in /platforms/<key>/
PLATFORM_KEYS = {
    "hackerone.com": "hackerone", "bugcrowd.com": "bugcrowd", "intigriti.com": "intigriti", "yeswehack.com": "yeswehack",
    "hackenproof.com": "hackenproof", "immunefi.com": "immunefi", "federacy.com": "federacy", "synack.com": "synack",
    "yogosha.com": "yogosha", "zerocopter.com": "zerocopter", "openbugbounty.org": "openbugbounty", "cobalt.io": "cobalt",
    "standoff365.com": "standoff365", "huntr.com": "huntr", "huntr.dev": "huntr", "bugbase.in": "bugbase", "bugbase.ai": "bugbase",
    "code4rena.com": "code4rena", "sherlock.xyz": "sherlock", "cantina.xyz": "cantina", "hats.finance": "hats",
}


# ----------------------------------------------------------------------------- small helpers
def read_lines(path: Path) -> list[str]:
    """Non-empty lines of a text file ([] when the file does not exist)."""
    try:
        return [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except OSError:
        return []


def read_table(path: Path) -> list[dict]:
    """A tab-separated file with a header line -> list of dicts. Missing columns become ''."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.is_file() else []
    if not lines:
        return []
    head = lines[0].split("\t")
    out = []
    for line in lines[1:]:
        if not line:
            continue
        cols = line.split("\t")
        out.append({h: (cols[i] if i < len(cols) else "") for i, h in enumerate(head)})
    return out


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, obj, pretty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=1 if pretty else None, separators=None if pretty else (",", ":")) + "\n", encoding="utf-8")


def write_text(path: Path, lines) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{l}\n" for l in lines), encoding="utf-8")


def program_id(name: str, url: str) -> str:
    """Same as program_id() in update_bb_domains.py (used when programs.txt has no id column yet)."""
    return hashlib.sha1(f"{name}\n{url}".encode("utf-8")).hexdigest()[:10]


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:32] or "program"


def platform_of(url: str) -> str:
    """Platform key from a program page URL: hackerone, bugcrowd, ... or "self-hosted" (any other site), "" without url."""
    if not url:
        return ""
    host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    for dom, key in PLATFORM_KEYS.items():
        if host == dom or host.endswith("." + dom):
            return key
    return "self-hosted" if host else ""


def split_programs(cell: str) -> list[str]:
    """review-*.txt column `programs` is "a; b; c (+2 more)": the names, without the "(+N more)" tail."""
    cell = re.sub(r"\s*\(\+\d+ more\)\s*$", "", cell or "")
    return [p.strip() for p in cell.split("; ") if p.strip()]


# ----------------------------------------------------------------------------- the build
def build(data: Path, history: Path, out: Path) -> dict:
    api = out / API
    stats = read_json(data / "stats.json", {})
    data_date = stats.get("date") or ""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---- programs (programs.txt) and their scope (program-scope.tsv)
    prog_rows = read_table(data / "programs.txt")
    # A company page (hosting "both": its domains are also in a platform program) and the platform program of the SAME name are one
    # program to a reader. The page is attached to the platform program (self_url) instead of being listed a second time; every
    # value of both is shown under the platform program. Only when exactly one platform program has that name.
    def _norm(n): return re.sub(r"[^a-z0-9]+", "", (n or "").lower())
    plat_by_norm: dict[str, list] = defaultdict(list)
    for r in prog_rows:
        if r.get("hosting") == "platform":
            plat_by_norm[_norm(r.get("program"))].append(r)
    id_map: dict[str, str] = {}                      # id of a merged self-hosted program -> id of the platform program that absorbed it
    absorbed: dict[str, list] = defaultdict(list)    # platform program id -> the merged rows
    for r in prog_rows:
        if r.get("hosting") == "both" and len(plat_by_norm.get(_norm(r.get("program")), [])) == 1:
            target = plat_by_norm[_norm(r.get("program"))][0]
            tid = target.get("id") or program_id(target.get("program", ""), target.get("program_url", ""))
            sid = r.get("id") or program_id(r.get("program", ""), r.get("program_url", ""))
            id_map[sid] = tid
            absorbed[tid].append(r)
    programs, by_id, by_name = [], {}, defaultdict(list)
    for r in prog_rows:
        pid = r.get("id") or program_id(r.get("program", ""), r.get("program_url", ""))
        if pid in id_map:
            continue
        plat = platform_of(r.get("program_url", "")) or "unknown"
        p = {"id": pid, "slug": f"{slugify(r.get('program', ''))}-{pid}", "name": r.get("program", ""), "url": r.get("program_url", ""),
             "hosting": r.get("hosting", "unknown"), "platform": plat, "bounty": r.get("bounty", "unknown"),
             "hosts": int(r.get("hosts") or 0), "sources": [s for s in r.get("sources", "").split(",") if s],
             "also_on": r.get("also_on", ""), "counts": {}, "new": 0}
        for extra in absorbed.get(pid, []):
            p.setdefault("self_urls", []).append(extra.get("program_url", ""))
            p["sources"] = sorted(set(p["sources"]) | {x for x in extra.get("sources", "").split(",") if x})
            if extra.get("bounty") == "paying":
                p["bounty"] = "paying"
            p["hosting"] = "both"
        by_id[pid] = len(programs)
        by_name[p["name"]].append(len(programs))
        programs.append(p)

    scope_rows = read_table(data / "program-scope.tsv")
    prog_scope: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))     # program idx -> asset -> [(value, bounty)]
    value_programs: dict[tuple, set] = defaultdict(set)                                # (asset, value) -> program idxs
    seen_ps: set = set()
    for r in scope_rows:
        i = by_id.get(id_map.get(r["id"], r["id"]))
        if i is None:
            continue
        if (i, r["asset"], r["value"], r["bounty"]) in seen_ps:             # a merged program lists the same value twice
            continue
        seen_ps.add((i, r["asset"], r["value"], r["bounty"]))
        prog_scope[i][r["asset"]].append((r["value"], r["bounty"]))
        value_programs[(r["asset"], r["value"])].add(i)
    for i, assets in prog_scope.items():
        programs[i]["counts"] = {a: len(v) for a, v in assets.items()}
        if programs[i].get("self_urls"):                                       # merged: the value count is of both pages together
            programs[i]["hosts"] = sum(len(v) for a, v in assets.items() if a not in OVERLAY)

    # ---- program events (history/program-events.tsv): appeared / left / returned / shrank / grew, written by scripts/proghistory.py
    ev_rows = read_table(history / "program-events.tsv")
    slug_by_id = {p["id"]: p["slug"] for p in programs}
    for sid, tid in id_map.items():
        slug_by_id.setdefault(sid, slug_by_id.get(tid, ""))
    events = [{"date": r["date"], "event": r["event"], "id": r["id"], "slug": slug_by_id.get(r["id"], ""), "program": r["program"], "url": r["url"],
               "count": int(r.get("count") or 0), "previous": int(r.get("previous") or 0), "note": r.get("note", "")} for r in ev_rows]
    events_by_date: dict[str, list] = defaultdict(list)
    for e in events:
        events_by_date[e["date"]].append(e)

    # ---- what programs EXCLUDE (program-out-of-scope.tsv; absent in data of older runs -> everything below is simply empty)
    prog_oos: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))      # program idx -> asset (or "text") -> [values]
    oos_programs: dict[tuple, set] = defaultdict(set)                                  # (asset, value) -> program idxs (never "text")
    for r in read_table(data / "program-out-of-scope.tsv"):
        i = by_id.get(id_map.get(r.get("id", ""), r.get("id", "")))
        if i is None or not r.get("value"):
            continue
        prog_oos[i][r["asset"]].append(r["value"])
        if r["asset"] != "text":
            oos_programs[(r["asset"], r["value"])].add(i)
    for i in range(len(programs)):
        programs[i]["excluded"] = sum(len(v) for v in prog_oos.get(i, {}).values())

    # ---- every value with bounty / hosting / sources (review-by-source.txt)
    review = read_table(data / "review-by-source.txt")
    values: dict[str, list] = defaultdict(list)        # asset -> [(value, bounty, hosting, [sources])]
    for r in review:
        values[r["assets"]].append((r["host"], r["bounty"], r.get("hosting") or "unknown", [s for s in r["sources"].split(",") if s]))
    # apis is an OVERLAY (see OVERLAY): the collector does not write it per program, so it is derived here: a program "has" the APIs
    # among its hosts / wildcards / urls that the global apis list names. Shown as its own tab, never added to totals.
    api_set = {v[0] for v in values.get("apis", [])}
    for i in list(prog_scope):
        for a in ("subdomains", "wildcards", "urls"):
            for v, b in prog_scope[i].get(a, []):
                if v in api_set and (v, b) not in prog_scope[i]["apis"]:
                    prog_scope[i]["apis"].append((v, b))
                    value_programs[("apis", v)].add(i)
    source_names = sorted({s for rows in values.values() for v in rows for s in v[3]})
    src_idx = {s: i for i, s in enumerate(source_names)}

    # ---- today's changes (review-new / review-removed) -> programs with new scope, new per platform
    def review_rows(path: Path) -> list[dict]:
        return [{"bounty": r.get("bounty", ""), "asset": r.get("assets", ""), "host": r.get("host", ""), "sources": r.get("sources", ""),
                 "programs": r.get("programs", ""), "program_urls": r.get("program_urls", ""), "raw": r.get("raw_entries", ""),
                 **({"last_seen_in": r["last_seen_in"]} if "last_seen_in" in r else {}), **({"why": r["why_removed"]} if r.get("why_removed") else {})} for r in read_table(path)]

    new_rows, new_pay_rows, removed_rows = (review_rows(data / f) for f in ("review-new.txt", "review-new-paying.txt", "review-removed.txt"))
    new_programs: set[int] = set()
    new_by_platform: Counter = Counter()
    for r in new_rows:
        idxs = value_programs.get((r["asset"], r["host"]), set())
        new_programs |= idxs
        for plat in {programs[i]["platform"] for i in idxs}:
            if r["asset"] not in OVERLAY:
                new_by_platform[plat] += 1
    for i in new_programs:
        programs[i]["new"] = sum(1 for r in new_rows if r["asset"] != "apis" and i in value_programs.get((r["asset"], r["host"]), ()))

    # ---- platform table (like the stats page of bbscope / HuntDeck)
    plat_stats: dict[str, dict] = {}
    for i, p in enumerate(programs):
        st = plat_stats.setdefault(p["platform"], {"platform": p["platform"], "programs": 0, "paying_programs": 0, "free_programs": 0,
                                                    "assets": 0, "paying_assets": 0, "wildcards": 0, "new_assets": 0})
        st["programs"] += 1
        st["paying_programs"] += p["bounty"] == "paying"
        st["free_programs"] += p["bounty"] != "paying"
    seen_plat: dict[str, set] = defaultdict(set)
    seen_pay: dict[str, set] = defaultdict(set)
    for (asset, value), idxs in value_programs.items():
        for i in idxs:
            plat = programs[i]["platform"]
            if asset == "wildcards":
                seen_plat[plat + "#w"].add(value)
                continue
            seen_plat[plat].add((asset, value))
    for r in scope_rows:
        i = by_id.get(r["id"])
        if i is not None and r["bounty"] == "paying" and r["asset"] not in OVERLAY:
            seen_pay[programs[i]["platform"]].add((r["asset"], r["value"]))
    for plat, st in plat_stats.items():
        st["assets"] = len(seen_plat.get(plat, ()))
        st["wildcards"] = len(seen_plat.get(plat + "#w", ()))
        st["paying_assets"] = len(seen_pay.get(plat, ()))
        st["new_assets"] = new_by_platform.get(plat, 0)
    platforms_table = sorted(plat_stats.values(), key=lambda s: -s["programs"])

    hosting_counts = Counter(p["hosting"] for p in programs)
    bounty_counts = Counter(p["bounty"] for p in programs)
    assets_info = {a["asset"]: a for a in stats.get("assets", [])}
    cards = {
        "paying_programs": bounty_counts.get("paying", 0),
        "free_programs": bounty_counts.get("non-paying", 0),
        "unknown_programs": bounty_counts.get("unknown", 0),
        "self_hosted_programs": hosting_counts.get("self-hosted", 0) + hosting_counts.get("both", 0),
        "programs_with_new_scope": len(new_programs),
        "wildcards": (assets_info.get("wildcards") or {}).get("count", len(values.get("wildcards", []))),
        "assets_total": sum((assets_info.get(a) or {}).get("count", len(values.get(a, []))) for a in ASSETS if a not in OVERLAY),
        "new_today": sum((assets_info.get(a) or {}).get("new") or 0 for a in ASSETS if a not in OVERLAY),
        "removed_today": sum((assets_info.get(a) or {}).get("removed") or 0 for a in ASSETS if a not in OVERLAY),
        "new_paying_today": len(new_pay_rows),
        "excluded_values": len(oos_programs),
        "programs_with_exclusions": sum(1 for p in programs if p["excluded"]),
    }

    # ---- history (history/daily/<date>/stats.json when there, otherwise counted from the files)
    days = sorted(d.name for d in (history / "daily").glob("*") if d.is_dir()) if (history / "daily").is_dir() else []
    hist = {"dates": [], "series": {a: {"count": [], "paying": [], "new": [], "removed": []} for a in ASSETS}, "programs": [], "files": []}
    changes_index = []
    for d in days:
        folder = history / "daily" / d
        js = read_json(folder / "stats.json", {})
        have = {a["asset"]: a for a in js.get("assets", [])}
        new_c, rem_c = Counter(), Counter()
        for r in read_table(folder / "review-new.txt"):
            new_c[r.get("assets", "")] += 1
        for r in read_table(folder / "review-removed.txt"):
            rem_c[r.get("assets", "")] += 1
        hist["dates"].append(d)
        for a in ASSETS:
            h = have.get(a)
            hist["series"][a]["count"].append(h["count"] if h else len(read_lines(folder / f"{a}.txt")))
            hist["series"][a]["paying"].append(h["paying"] if h else None)
            hist["series"][a]["new"].append(new_c.get(a, 0))
            hist["series"][a]["removed"].append(rem_c.get(a, 0))
        hist["programs"].append((js.get("files") or {}).get("programs"))
        note = js.get("diff_note", "")
        baseline = bool(js) and not js.get("have_diffs", True)
        changes_index.append({"date": d, "new": sum(new_c.values()), "removed": sum(rem_c.values()), "baseline": baseline, "note": note})
        write_json(api / "changes" / f"{d}.json", {"date": d, "baseline": baseline, "note": note,
                   "new": review_rows(folder / "review-new.txt"), "removed": review_rows(folder / "review-removed.txt"),
                   "programs": events_by_date.get(d, [])})
    write_json(api / "history.json", hist)
    changes_index.sort(key=lambda c: c["date"], reverse=True)
    write_json(api / "changes" / "index.json", {"days": changes_index})
    write_json(api / "changes" / "latest.json", {"date": data_date, "note": stats.get("diff_note", ""), "new": new_rows,
               "new_paying": new_pay_rows, "removed": removed_rows, "programs": events_by_date.get(data_date, [])})
    write_json(api / "program-events.json", {"count": len(events), "events": events[::-1][:1500], "note": "newest first; kinds: appeared, left, returned, shrank, grew"})

    # ---- text endpoints that tools can pipe: assets/, feeds/, platforms/, programs/<slug>/
    for a in ASSETS:
        for suf in ("", "-paying", "-new", "-removed"):
            f = data / f"{a}{suf}.txt"
            if f.is_file():
                write_text(api / "assets" / f"{a}{suf}.txt", read_lines(f))
    write_text(api / "assets" / "master.txt", read_lines(data / "master.txt"))
    # the ALL-TIME database (history/all-time.tsv, written by scripts/archive.py): every value ever in scope, also the ones that are gone.
    # archive/<asset>-ever.txt = every value ever seen; archive/<asset>-gone.txt = "value<TAB>first seen<TAB>gone on" of those no longer listed.
    arch_stats: dict[str, dict] = {}
    arch_ever: dict[str, list] = defaultdict(list)
    arch_gone: dict[str, list] = defaultdict(list)
    for r in read_table(history / "all-time.tsv"):
        a = r.get("asset", "")
        arch_ever[a].append(r["value"])
        if r.get("gone_on"):
            arch_gone[a].append(f"{r['value']}\t{r.get('first_seen', '')}\t{r['gone_on']}")
    for a, vals in arch_ever.items():
        arch_stats[a] = {"total": len(vals), "gone": len(arch_gone.get(a, []))}
        write_text(api / "archive" / f"{a}-ever.txt", sorted(vals))
        if arch_gone.get(a):
            write_text(api / "archive" / f"{a}-gone.txt", sorted(arch_gone[a]))
    # all.txt = exactly the list of the Targets page "All" tab: every asset type in one list (wildcards written as *.base), without
    # the apis overlay (its values are already in subdomains / urls) and without the maybe guesses.
    all_lines = sorted({("*." + v[0] if a == "wildcards" else v[0]) for a, rows in values.items() if a not in ("apis", "maybe") for v in rows})
    write_text(api / "assets" / "all.txt", all_lines)
    write_text(api / "feeds" / "new.txt", sorted({r["host"] for r in new_rows}))
    write_text(api / "feeds" / "new-paying.txt", sorted({r["host"] for r in new_pay_rows}))
    write_text(api / "feeds" / "removed.txt", sorted({r["host"] for r in removed_rows}))

    by_plat_asset: dict[tuple, set] = defaultdict(set)
    by_plat_asset_pay: dict[tuple, set] = defaultdict(set)
    for r in scope_rows:
        i = by_id.get(r["id"])
        if i is None:
            continue
        key = (programs[i]["platform"], r["asset"])
        by_plat_asset[key].add(r["value"])
        if r["bounty"] == "paying":
            by_plat_asset_pay[key].add(r["value"])
    for (plat, asset), vals in by_plat_asset.items():
        write_text(api / "platforms" / plat / f"{asset}.txt", sorted(vals))
        if by_plat_asset_pay.get((plat, asset)):
            write_text(api / "platforms" / plat / f"{asset}-paying.txt", sorted(by_plat_asset_pay[(plat, asset)]))

    write_json(api / "programs.json", {"count": len(programs), "programs": programs})
    for i, p in enumerate(programs):
        scope = {a: sorted(v) for a, v in prog_scope.get(i, {}).items()}
        oos = {a: sorted(set(v)) for a, v in prog_oos.get(i, {}).items()}
        write_json(api / "programs" / f"{p['slug']}.json", {**p, "events": [e for e in events if e["id"] == p["id"]][::-1][:50], "scope": {a: [[v, b] for v, b in rows] for a, rows in scope.items()}, "out_of_scope": oos})
        for a, rows in scope.items():
            write_text(api / "programs" / p["slug"] / f"{a}.txt", [v for v, _ in rows])
        # all.txt: everything the program lists, every asset type in one plain list (the apis overlay repeats values, so it is left out)
        write_text(api / "programs" / p["slug"] / "all.txt", sorted({v for a, rows in scope.items() if a not in OVERLAY - {"wildcards"} for v, _ in rows}))
        if any(a != "text" for a in oos):                  # the exclusions as one plain list (assets only, no sentences)
            write_text(api / "programs" / p["slug"] / "out-of-scope.txt", sorted({v for a, vs in oos.items() if a != "text" for v in vs}))

    # ---- out-of-scope/<asset>.txt (what is excluded, by any program, one per line: an exclusion list for your tools) and out-of-scope.json
    oos_by_asset: dict[str, set] = defaultdict(set)
    for (asset, value) in oos_programs:
        oos_by_asset[asset].add(value)
    for asset, vals in oos_by_asset.items():
        write_text(api / "out-of-scope" / f"{asset}.txt", sorted(vals))
    write_text(api / "out-of-scope" / "master.txt", sorted({v for vals in oos_by_asset.values() for v in vals}))
    write_json(api / "out-of-scope.json", {"count": len(oos_programs), "programs_ref": "programs.json (position in its programs array)",
               "text_entries": sum(len(v.get("text", [])) for v in prog_oos.values()),
               "rows": [[a, v, sorted(idxs)] for (a, v), idxs in sorted(oos_programs.items())]})

    # ---- scope/<asset>.json: every value with bounty, hosting, sources and programs (for search and "check scope")
    for a in ASSETS:
        rows = []
        for value, bounty, hosting, srcs in sorted(values.get(a, [])):
            rows.append([value, BOUNTY_CODE.get(bounty, 2), HOSTING_CODE.get(hosting, 3), [src_idx[s] for s in srcs],
                         sorted(value_programs.get((a, value), ()))])
        write_json(api / "scope" / f"{a}.json", {"asset": a, "count": len(rows), "sources": source_names,
                   "bounty": ["paying", "non-paying", "unknown"], "hosting": ["platform", "self-hosted", "both", "unknown"],
                   "programs_ref": "programs.json (position in its programs array)", "rows": rows})

    # ---- quality (what the parser repaired / could not read)
    _rej = [[r["source"], r["reason"], r["raw"]] for r in read_table(data / "rejected.txt")]
    write_json(api / "quality" / "rejected.json", {"count": len(_rej), "rows": _rej,
               "reasons": stats.get("rejected", {})})
    write_json(api / "quality" / "recovered.json", {"rows": [[r["rule"], r["source"], r["raw"], r["assets"], r["result"]] for r in read_table(data / "recovered.txt")],
               "rules": stats.get("recovered", {})})

    # ---- insights (extra facts worked out from the data above; see insights.py)
    ins, ins_texts = insights.compute(values, programs, value_programs, prog_oos)
    write_json(api / "insights.json", ins)
    for rel, lines_ in ins_texts.items():
        write_text(api / rel, lines_)

    # ---- stats / sources / index
    full_stats = {**stats, "archive": arch_stats, "out_of_scope": {a: len(v) for a, v in sorted(oos_by_asset.items())}, "cards": cards, "platforms": platforms_table, "hosting": dict(hosting_counts), "bounty": dict(bounty_counts),
                  "asset_info": ASSET_INFO, "built_at": now}
    write_json(api / "stats.json", full_stats)
    write_json(api / "sources.json", {"date": data_date, "sources": stats.get("sources", []), "failed": stats.get("failed", []),
               "warnings": stats.get("warnings", [])})
    endpoints = [
        ("index.json", "This list", "json"), ("stats.json", "Numbers of the last run, headline cards, per-platform table", "json"),
        ("history.json", "Daily counts, new and removed per asset type", "json"), ("sources.json", "Health of every source", "json"),
        ("programs.json", "Every program (platform, hosting, bounty, counts)", "json"),
        ("programs/{slug}.json", "One program with its whole scope", "json"),
        ("programs/{slug}/{asset}.txt", "One program's values of one asset type, one per line", "text"),
        ("assets/{asset}.txt", "All values of an asset type (also -paying, -new, -removed)", "text"),
        ("assets/master.txt", "Every distinct value of every asset type", "text"),
        ("platforms/{platform}/{asset}.txt", "What one platform lists (also {asset}-paying.txt)", "text"),
        ("feeds/new.txt", "Everything new today, one per line", "text"), ("feeds/new-paying.txt", "New paying / unknown-bounty values today", "text"),
        ("feeds/removed.txt", "Everything removed today", "text"),
        ("changes/index.json", "Days with their new/removed counts", "json"), ("changes/latest.json", "Today's changes with context", "json"),
        ("changes/{date}.json", "One earlier day's changes", "json"),
        ("scope/{asset}.json", "Every value of an asset type with bounty, hosting, sources, programs", "json"),
        ("out-of-scope/{asset}.txt", "What programs EXCLUDE, one value per line (an exclusion list: grep -vFx it out of your targets)", "text"),
        ("out-of-scope/master.txt", "Every excluded value of every asset type", "text"),
        ("out-of-scope.json", "Every excluded value with the programs that exclude it (used by the scope check)", "json"),
        ("archive/{asset}-ever.txt", "ALL-TIME database: every value that was ever in scope, also the ones that are gone", "text"),
        ("archive/{asset}-gone.txt", "ALL-TIME database: values no longer listed (value, first seen, gone on; tab separated)", "text"),
        ("assets/all.txt", "Every asset type in one list (as the Targets page All tab; without the apis overlay and the maybe guesses)", "text"),
        ("program-events.json", "Program events: appeared, left, returned, shrank, grew (newest first)", "json"),
        ("programs/{slug}/all.txt", "Everything one program lists (all asset types in one list)", "text"),
        ("programs/{slug}/out-of-scope.txt", "What one program excludes, one per line", "text"),
        ("insights.json", "Extra facts: third-party hosting leads, top-level domains, biggest programs, shared hosts, IP space, apps, GitHub orgs", "json"),
        ("insights/services/{service}.txt", "In-scope hosts on one third-party service (e.g. aws-s3, heroku, github-pages); dangling-leads.txt = all that are worth a DNS check", "text"),
        ("insights/shared-hosts.txt", "Hosts that two or more programs list", "text"),
        ("quality/rejected.json", "Entries the parser could not use, with the reason", "json"),
        ("quality/recovered.json", "Entries the parser repaired or guessed", "json"),
    ]
    platforms = sorted({p["platform"] for p in programs})
    write_json(api / "index.json", {
        "name": "bug bounty domains", "version": 1, "data_date": data_date, "built_at": now, "base": "/" + API,
        "assets": ASSETS, "asset_info": ASSET_INFO, "platforms": platforms, "sources": source_names,
        "counts": {"programs": len(programs), "values": sum(len(v) for v in values.values())},
        "endpoints": [{"path": f"/{API}/{p}", "description": d, "type": t} for p, d, t in endpoints]}, pretty=True)
    return {"programs": len(programs), "values": sum(len(v) for v in values.values()), "days": len(days), "date": data_date}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the static website + API from data/ and history/")
    ap.add_argument("--data", type=Path, default=ROOT / "data")
    ap.add_argument("--history", type=Path, default=ROOT / "history")
    ap.add_argument("--out", type=Path, default=HERE / "public")
    a = ap.parse_args(argv)
    if not (a.data / "stats.json").is_file() and not (a.data / "review-by-source.txt").is_file():
        print(f"error: no data found in {a.data} (run scripts/update_bb_domains.py first, or git pull the repository)", file=sys.stderr)
        return 2
    out = a.out.resolve()
    tmp, old = out.with_name(out.name + ".new"), out.with_name(out.name + ".old")
    for d in (tmp, old):
        shutil.rmtree(d, ignore_errors=True)
    tmp.mkdir(parents=True)
    ui = HERE / "ui"
    for f in ui.iterdir():
        if f.is_file():
            shutil.copy2(f, tmp / f.name)
    info = build(a.data, a.history, tmp)
    if out.exists():
        out.rename(old)
    tmp.rename(out)
    shutil.rmtree(old, ignore_errors=True)
    print(f"built {out}: {info['programs']} programs, {info['values']} values, {info['days']} days of history, data of {info['date'] or '?'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
