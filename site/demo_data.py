#!/usr/bin/env python3
"""demo_data.py - writes a FAKE project folder (data/ + history/) in the exact shape of the real daily run, so the web UI
can be tried before the first real run:

    python3 site/demo_data.py /tmp/bbdemo            # fake data, all names end in .example / example-N.com
    python3 site/build_site.py --data /tmp/bbdemo/data --history /tmp/bbdemo/history --out /tmp/bbdemo/public
    python3 site/serve.py --dir /tmp/bbdemo/public

Nothing here is real bug bounty data. It is also used by the tests of the UI."""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from datetime import date, timedelta
from pathlib import Path

ASSETS = ["apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"]
PLATS = [("hackerone", "https://hackerone.com/", 60), ("bugcrowd", "https://bugcrowd.com/engagements/", 40), ("intigriti", "https://app.intigriti.com/programs/", 25),
         ("yeswehack", "https://yeswehack.com/programs/", 14), ("hackenproof", "https://hackenproof.com/programs/", 8), ("immunefi", "https://immunefi.com/bug-bounty/", 8)]
SELF = [("Zoho Demo", "https://bugbounty.demo-zoho.example.com/bb/info"), ("Goober Demo VRP", "https://bughunters.demo-goober.example.com/"),
        ("Micro Demo MSRC", "https://demo-msrc.example.com/bounty"), ("Fruit Demo Security", "https://security.demo-fruit.example.com/bounty")]
SOURCES = ["arkadiyt-domains", "arkadiyt-wildcard", "arkadiyt-hackerone", "arkadiyt-bugcrowd", "arkadiyt-intigriti", "arkadiyt-yeswehack",
           "projectdiscovery", "diodb", "immunefi-direct", "hackerone-direct", "hackerone-api", "bugcrowd-direct", "intigriti-direct",
           "yeswehack-direct", "hackenproof-direct", "self-hosted-manual"]
PLAT_SRC = {"hackerone": "arkadiyt-hackerone,hackerone-direct", "bugcrowd": "arkadiyt-bugcrowd,bugcrowd-direct", "intigriti": "arkadiyt-intigriti,intigriti-direct",
            "yeswehack": "arkadiyt-yeswehack,yeswehack-direct", "hackenproof": "hackenproof-direct", "immunefi": "immunefi-direct", "self": "self-hosted-manual"}


def pid(name: str, url: str) -> str:
    return hashlib.sha1(f"{name}\n{url}".encode()).hexdigest()[:10]


demo_excluded: dict = {}                              # filled by main(): a host and a sub-tree the first wildcard program excludes (used by tests)


def main(root: Path) -> None:
    rnd = random.Random(7)
    extra = random.Random(11)                           # separate generator: extras below must not shift the numbers above
    data, hist = root / "data", root / "history"
    data.mkdir(parents=True, exist_ok=True)
    progs = []                                          # (name, url, hosting, bounty, sources, {asset: [values]})
    n = 0
    words = ["nova", "pixel", "orbit", "delta", "lumen", "vertex", "cobalt", "atlas", "pulse", "forge", "ember", "quartz", "harbor", "zenith"]
    for plat, base, count in PLATS:
        for i in range(count):
            n += 1
            name = f"{rnd.choice(words).title()} {rnd.choice(words).title()} {n}"
            dom = f"{name.split()[0].lower()}{n}.example.com"
            pay = rnd.random() < 0.6
            vals = {"apex": [dom], "subdomains": [f"{s}.{dom}" for s in rnd.sample(["www", "api", "app", "admin", "dev", "mail", "cdn", "auth", "beta", "shop"], rnd.randint(1, 8))],
                    "wildcards": [dom] if rnd.random() < 0.35 else [], "ips": [f"203.0.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}"] if rnd.random() < 0.15 else [],
                    "apps": [f"com.{name.split()[0].lower()}{n}.app"] if rnd.random() < 0.3 else [], "github": [f"https://github.com/{name.split()[0].lower()}{n}"] if rnd.random() < 0.15 else [],
                    "patterns": [f"api-*.{dom}"] if rnd.random() < 0.05 else [], "asn": [f"AS{rnd.randint(1000, 60000)}"] if rnd.random() < 0.03 else []}
            if extra.random() < 0.2:                                   # a host on third-party hosting (shows on the Insights page)
                vals["subdomains"].append(f"{extra.choice(['assets', 'static', 'files'])}-{n}" + extra.choice([".s3.amazonaws.com", ".herokuapp.com", ".github.io", ".azurewebsites.net", ".netlify.app", ".cloudfront.net"]))
            if extra.random() < 0.25:                                  # an address WITH a path: the path is the scope, the host itself is not
                vals["urls"] = [f"https://{extra.choice(['storage', 'files', 'cdn'])}.{dom}/{extra.choice(['releases', 'public', 'download'])}-{n}"]
            # apis.txt is an overlay: every host / url whose address names an API (the same rule as looks_like_api in the collector)
            vals["apis"] = [x for x in vals["subdomains"] + vals.get("urls", []) if re.search(r"(?:^|//)api\.|/api", x)]
            if extra.random() < 0.06:
                vals["ips"] = vals["ips"] + [f"198.51.{extra.randint(1, 250)}.0/24"]
            if extra.random() < 0.1:
                vals["apps"] = vals["apps"] + [f"https://apps.apple.com/app/id{900000 + n}", f"https://play.google.com/store/apps/details?id=com.demo{n}.mobile"]
            progs.append((name, base + name.split()[0].lower() + str(n), "platform", "paying" if pay else "non-paying", PLAT_SRC[plat], {k: v for k, v in vals.items() if v}))
    for k, (name, url) in enumerate(SELF):
        dom = f"demo-self{k}.example.com"
        vals = {"apex": [dom], "subdomains": [f"{s}.{dom}" for s in ("www", "api", "accounts", "mail")], "wildcards": [dom]}
        progs.append((name, url, "self-hosted", "paying", PLAT_SRC["self"], vals))
    # one self-hosted program that is also on a platform
    shared = progs[3][5]["apex"][0]
    progs.append(("Both Demo VRP", "https://security.both-demo.example.com/", "both", "paying", PLAT_SRC["self"], {"apex": [shared], "subdomains": [f"portal.{shared}"]}))

    # a program whose ONLY scope is a path on a shared host (like HackerOne "kubernetes": storage.googleapis.com/kubernetes-release).
    # The host itself is NOT in scope; the tests check that the scope check says so.
    progs.append(("Bucket Demo VRP", "https://bucket-demo.example.com/security", "self-hosted", "paying", PLAT_SRC["self"], {"urls": ["https://storage.bucket-demo.example.com/release-files"]}))

    # a company page AND a platform program of the same name: the site shows ONE program (platform one) with "Also self-hosted"
    progs.append(("Merge Demo", "https://hackerone.com/merge-demo", "platform", "paying", PLAT_SRC["hackerone"], {"apex": ["merge-demo.example.com"], "subdomains": ["www.merge-demo.example.com"]}))
    progs.append(("Merge Demo", "https://merge-demo.example.com/security", "both", "paying", PLAT_SRC["self"], {"apex": ["merge-demo.example.com"], "subdomains": ["portal.merge-demo.example.com"]}))

    allvals = {a: {} for a in ASSETS}                                   # asset -> value -> (bounty, hosting, sources)
    ptab, stab = [], []
    for name, url, hosting, bounty, srcs, vals in progs:
        i = pid(name, url)
        total = sum(len(v) for v in vals.values())
        ptab.append((hosting, bounty, name, url, str(total), srcs, "Merge Demo" if hosting == "both" else "", i))
        for a, vs in vals.items():
            for v in vs:
                stab.append((i, a, v, bounty))
                cur = allvals[a].get(v)
                allvals[a][v] = ("paying" if bounty == "paying" or (cur and cur[0] == "paying") else bounty, "self-hosted" if hosting != "platform" else "platform", srcs)
    for k in range(40):                                                  # values only the flat mirrors know (no program)
        allvals["subdomains"][f"flat{k}.mirror-only{k % 7}.example.org"] = ("unknown", "unknown", "arkadiyt-domains")
    for k in range(30):
        allvals["internal-hosts"][f"host{k}.corp.internal"] = ("unknown", "unknown", "arkadiyt-domains")
        allvals["maybe"][f"guess{k}.maybe-example.com"] = ("unknown", "unknown", "diodb")

    def lines(path, items):
        path.write_text("".join(f"{x}\n" for x in items), encoding="utf-8")

    for a in ASSETS:
        vs = sorted(allvals[a])
        lines(data / f"{a}.txt", vs)
        lines(data / f"{a}-paying.txt", [v for v in vs if allvals[a][v][0] in ("paying", "unknown")])
    lines(data / "master.txt", sorted({v for a in ASSETS for v in allvals[a]}))
    review = [(allvals[a][v][0], a, v, allvals[a][v][2], allvals[a][v][1]) for a in ASSETS for v in allvals[a]]
    (data / "review-by-source.txt").write_text("bounty\tassets\thost\tsources\thosting\n" + "".join("\t".join(r) + "\n" for r in sorted(review, key=lambda r: (r[2], r[1]))), encoding="utf-8")
    (data / "programs.txt").write_text("hosting\tbounty\tprogram\tprogram_url\thosts\tsources\talso_on\tid\n" + "".join("\t".join(r) + "\n" for r in ptab), encoding="utf-8")
    (data / "program-scope.tsv").write_text("id\tasset\tvalue\tbounty\n" + "".join("\t".join(r) + "\n" for r in sorted(stab)), encoding="utf-8")

    # what each program EXCLUDES (data/program-out-of-scope.tsv: id, asset, value). The first program with a wildcard excludes one host
    # and one sub-tree under that wildcard, so the scope check has something to say "excluded" about (the tests use it).
    otab, DOS = [], ["Denial of service attacks", "Social engineering of staff", "Physical attacks", "Third-party services and SaaS", "Automated scanning without prior approval"]
    first_wild = True
    for name, url, hosting, bounty, srcs, vals in progs:
        i = pid(name, url)
        if not vals.get("apex"):                                   # the bucket program: scope is one URL path; it excludes a sub-path of it
            otab.append((i, "urls", "https://storage.bucket-demo.example.com/release-files/internal"))
            continue
        dom = vals["apex"][0]
        if vals.get("wildcards") and first_wild:
            first_wild = False
            otab += [(i, "subdomains", f"blocked.{dom}"), (i, "wildcards", f"internal.{dom}")]
            demo_excluded.update({"host": f"blocked.{dom}", "tree": f"x.internal.{dom}", "program": name})
        if rnd.random() < 0.5:
            otab += [(i, "subdomains", f"{rnd.choice(['staging', 'old', 'legacy', 'status'])}.{dom}")]
        if rnd.random() < 0.15:
            otab += [(i, "ips", f"198.51.{rnd.randint(1, 250)}.0/24")]
        otab += [(i, "text", t) for t in rnd.sample(DOS, rnd.randint(0, 3))]
    (data / "program-out-of-scope.tsv").write_text("id\tasset\tvalue\n" + "".join("\t".join(r) + "\n" for r in sorted(set(otab))), encoding="utf-8")

    today = date(2026, 11, 7)
    new_vals = []
    for a in ("subdomains", "apex", "apps", "github"):
        new_vals += [(a, v) for v in rnd.sample(sorted(allvals[a]), min(14, len(allvals[a])))]
    pname = {pid(p[0], p[1]): p for p in progs}
    value_prog = {}
    for i, a, v, b in stab:
        value_prog.setdefault((a, v), []).append(i)

    def review_line(a, v, extra=""):
        ps = value_prog.get((a, v), [])
        names = "; ".join(sorted({pname[i][0] for i in ps})[:5])
        urls = "; ".join(sorted({pname[i][1] for i in ps})[:3])
        b = allvals[a][v][0] if v in allvals[a] else "paying"
        return f"{b}\t{a}\t{v}\t{allvals[a].get(v, ('', '', 'arkadiyt-domains'))[2]}\t{names}\t{urls}\t{v}{extra}\n"

    head = "bounty\tassets\thost\tsources\tprograms\tprogram_urls\traw_entries"
    (data / "review-new.txt").write_text(head + "\n" + "".join(review_line(a, v) for a, v in new_vals), encoding="utf-8")
    (data / "review-new-paying.txt").write_text(head + "\n" + "".join(review_line(a, v) for a, v in new_vals if allvals[a][v][0] != "non-paying"), encoding="utf-8")
    removed = [("subdomains", f"gone{k}.old-example.com") for k in range(9)]
    (data / "review-removed.txt").write_text(head + "\tlast_seen_in\n" + "".join(f"paying\t{a}\t{v}\tarkadiyt-hackerone\tOld Program\thttps://hackerone.com/old\t{v}\t2026-11-06\n" for a, v in removed), encoding="utf-8")
    for a in ASSETS:
        nn = [v for aa, v in new_vals if aa == a]
        lines(data / f"{a}-new.txt", nn)
        lines(data / f"{a}-removed.txt", [v for aa, v in removed if aa == a])
    rej = [("arkadiyt-hackerone", "free-text", "See the program policy for details about which assets are in scope")] * 3 + [("arkadiyt-bugcrowd", "single-label", "localhost"), ("diodb", "placeholder", "example.com")]
    (data / "rejected.txt").write_text("source\treason\traw\n" + "".join("\t".join(r) + "\n" for r in rej), encoding="utf-8")
    (data / "recovered.txt").write_text("rule\tsource\traw\tassets\tresult\n" + "\t".join(["alternatives", "bugcrowd-direct", "*.demo.{com,net}", "wildcards", "demo.com demo.net"]) + "\n", encoding="utf-8")
    lines(data / "failed-sources.txt", [])

    def stats_json(day, k):
        assets = []
        for a in ASSETS:
            c = len(allvals[a]) - (len(ASSETS) - k) % 5 * 2
            assets.append({"asset": a, "count": max(c, 1), "paying": max(int(c * .6), 0), "new": rnd.randint(0, 9) if k else None, "removed": rnd.randint(0, 4) if k else None})
        return {"date": day.isoformat(), "generated_at": day.isoformat() + "T21:35:00Z", "parser_version": "demo", "diff_note": f"diffs against {(day - timedelta(1)).isoformat()}" if k else "first run",
                "have_diffs": bool(k), "headline": f"{day} | demo", "master": len({v for a in ASSETS for v in allvals[a]}), "overlap": 0,
                "files": {"programs": len(ptab) - (30 - k) // 6, "review_new": 40, "review_removed": 9, "recovered": 1, "rejected": 5, "review_by_source": len(review), "program_scope": len(stab), "program_out_of_scope": len(otab), "failed_sources": 0, "review_new_paying": 30},
                "assets": assets,
                "sources": [{"name": s, "status": "ok" if s != "hackenproof-direct" else "ok", "rows": rnd.randint(500, 40000), "rejected": rnd.randint(0, 300), "seconds": round(rnd.uniform(0.2, 200), 1),
                             "note": "3 of 518 Bugcrowd engagements skipped" if s == "bugcrowd-direct" else ("needs H1_USERNAME and H1_TOKEN" if s == "hackerone-api" else "")} for s in SOURCES],
                "failed": [], "warnings": [], "recovered": {"pattern": 120, "alternatives": 40, "text-extract": 90}, "rejected": {"free-text": 3, "single-label": 1, "placeholder": 1}}

    for k in range(25):
        day = today - timedelta(days=24 - k)
        folder = hist / "daily" / day.isoformat()
        folder.mkdir(parents=True, exist_ok=True)
        sj = stats_json(day, k)
        (folder / "stats.json").write_text(json.dumps(sj), encoding="utf-8")
        for a in ASSETS:
            lines(folder / f"{a}.txt", sorted(allvals[a])[: max(1, len(allvals[a]) - (24 - k) // 3)])
        if k:
            nv = rnd.sample(new_vals, 8)
            (folder / "review-new.txt").write_text(head + "\n" + "".join(review_line(a, v) for a, v in nv), encoding="utf-8")
            (folder / "review-removed.txt").write_text(head + "\tlast_seen_in\n" + "".join(f"paying\tsubdomains\tgone{k}-{j}.old-example.com\tarkadiyt-hackerone\tOld Program\thttps://hackerone.com/old\tx\t{(day - timedelta(1)).isoformat()}\n" for j in range(rnd.randint(0, 5))), encoding="utf-8")
        else:
            (folder / "review-new.txt").write_text(head + "\n", encoding="utf-8")
            (folder / "review-removed.txt").write_text(head + "\tlast_seen_in\n", encoding="utf-8")
        if k == 24:
            sj["files"]["programs"] = len(ptab)
            (data / "stats.json").write_text(json.dumps(sj, indent=1), encoding="utf-8")
            (data / "stats.txt").write_text("demo stats\n", encoding="utf-8")
            # program events (history/program-events.tsv): one of each kind on the last day, so the Changes "Programs" tab and the program history have content
            ids = [r[7] for r in ptab]
            evs = [(day.isoformat(), "left", ids[0], ptab[0][2], ptab[0][3], 0, 12, "last listed by arkadiyt-hackerone; every one of them answered, so it was really dropped (made private, paused or closed)"),
                   (day.isoformat(), "appeared", ids[1], ptab[1][2], ptab[1][3], 6, 0, "listed by hackerone-direct"),
                   (day.isoformat(), "shrank", ids[2], ptab[2][2], ptab[2][3], 4, 30, "values of this program fell to half or less: scope edit, or a page the parser no longer understands"),
                   ((day - timedelta(1)).isoformat(), "returned", ids[3], ptab[3][2], ptab[3][3], 8, 8, "had left (last listed on 2026-10-01)")]
            arch = [(a, v, "2026-10-01", "", allvals[a][v][0], "Demo") for a in ASSETS if a != "apis" for v in allvals[a]]
            arch += [("subdomains", f"old{j}.gone-example.com", "2026-09-01", "2026-10-15", "paying", "Old Program") for j in range(3)]
            (hist / "all-time.tsv").write_text("asset\tvalue\tfirst_seen\tgone_on\tbounty\tprograms\n" + "".join("\t".join(r) + "\n" for r in sorted(arch)), encoding="utf-8")
            (hist / "program-events.tsv").write_text("date\tevent\tid\tprogram\turl\tcount\tprevious\tnote\n" + "".join("\t".join(str(c) for c in e) + "\n" for e in evs), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "demo-project"))
