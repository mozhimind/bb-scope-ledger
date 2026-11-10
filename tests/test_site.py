#!/usr/bin/env python3
"""test_site.py - tests of the website and the static API (site/).

    python3 -I tests/test_site.py

Part 1  BUILD: the daily pipeline is run by tests/simulate.py (kept with SIM_KEEP), site/build_site.py turns its data/ and
        history/ into the API, and the API is compared with the data files (same lists, same counts, valid JSON).
Part 2  SERVER: site/serve.py answers with the right types, gzip, CORS, 304, 404 and refuses path tricks.
Part 3  BROWSER (needs the `playwright` package and a Chromium; skipped with a message when missing): every page loads
        without console errors on a desktop and a phone screen, without sideways scrolling; the scope check, filters,
        program pages, the API builder and the theme switch work; and text from the data is never run as HTML (XSS)."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PASS = FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += not ok
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"   {detail}"))


def run(cmd, **kw):
    return subprocess.run([sys.executable, "-I", *cmd], capture_output=True, text=True, **kw)


tmp = Path(tempfile.mkdtemp(prefix="bbsite_"))
srv = None
try:
    # ------------------------------------------------------------------ part 1: build from the real pipeline output
    keep = tmp / "keep"
    r = subprocess.run([sys.executable, "-I", str(HERE / "simulate.py")], capture_output=True, text=True, env={**os.environ, "SIM_KEEP": str(keep)})
    check("pipeline simulation ran (source of the data used below)", "ALL PASS" in r.stdout, r.stdout[-300:])
    out = tmp / "public"
    r = run([str(ROOT / "site" / "build_site.py"), "--data", str(keep / "data"), "--history", str(keep / "history"), "--out", str(out)])
    check("build_site runs on the pipeline output", r.returncode == 0 and (out / "index.html").is_file(), r.stdout + r.stderr)
    api = out / "api" / "v1"
    data = keep / "data"
    lines = lambda p: [l for l in p.read_text().splitlines() if l.strip()] if p.is_file() else []
    assets = ["apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"]
    same = all(lines(api / "assets" / f"{a}{s}.txt") == lines(data / f"{a}{s}.txt") for a in assets for s in ("", "-paying", "-new", "-removed") if (data / f"{a}{s}.txt").is_file())
    check("api/v1/assets/*.txt are the same lists as data/*.txt", same)
    check("assets/master.txt equals data/master.txt", lines(api / "assets" / "master.txt") == lines(data / "master.txt"))
    for name in ("index", "stats", "history", "sources", "programs", "changes/index", "changes/latest", "quality/rejected", "quality/recovered"):
        try:
            json.loads((api / f"{name}.json").read_text())
            ok = True
        except Exception as e:  # noqa: BLE001
            ok = False
        check(f"api/v1/{name}.json is valid JSON", ok)
    prog_txt = lines(data / "programs.txt")[1:]
    progs = json.loads((api / "programs.json").read_text())
    check("programs.json has one entry per line of programs.txt", progs["count"] == len(prog_txt) == len(progs["programs"]), f"{progs['count']} vs {len(prog_txt)}")
    rbs = lines(data / "review-by-source.txt")[1:]
    n_rows = sum(json.loads((api / "scope" / f"{a}.json").read_text())["count"] for a in assets)
    check("scope/<asset>.json together have one row per line of review-by-source.txt", n_rows == len(rbs), f"{n_rows} vs {len(rbs)}")
    check("every program has its own json and per-asset text files", all((api / "programs" / f"{p['slug']}.json").is_file() for p in progs["programs"]))
    st = json.loads((api / "stats.json").read_text())
    check("stats.json has the cards, platform table and source health", all(k in st for k in ("cards", "platforms", "sources", "assets", "date")))
    idx = json.loads((api / "index.json").read_text())
    check("index.json lists the endpoints and every asset type", len(idx["endpoints"]) >= 15 and idx["assets"] == assets)
    r = run([str(ROOT / "site" / "build_site.py"), "--data", str(tmp / "nothing"), "--history", str(tmp / "nothing"), "--out", str(tmp / "x")])
    check("build_site without data: clear error, no crash trace", r.returncode == 2 and "no data found" in r.stderr and "Traceback" not in r.stderr, r.stderr[-200:])
    again = run([str(ROOT / "site" / "build_site.py"), "--data", str(keep / "data"), "--history", str(keep / "history"), "--out", str(out)])
    check("a second build replaces the first one cleanly", again.returncode == 0 and not (tmp / "public.new").exists() and not (tmp / "public.old").exists())

    # ------------------------------------------------------------------ richer fake data for server + browser tests
    demo = tmp / "demo"
    r = run([str(ROOT / "site" / "demo_data.py"), str(demo)])
    dpub = demo / "public"
    r = run([str(ROOT / "site" / "build_site.py"), "--data", str(demo / "data"), "--history", str(demo / "history"), "--out", str(dpub)])
    check("demo data builds", r.returncode == 0, r.stdout + r.stderr)

    # one CIDR range in the demo data (the demo has only single IPs)
    ipj = json.loads((dpub / "api/v1/scope/ips.json").read_text())
    ipj["rows"].append(["198.51.100.0/24", 0, 0, [0], [0]])
    (dpub / "api/v1/scope/ips.json").write_text(json.dumps(ipj))

    # hostile text in the data: must be shown as text, never run
    latest = json.loads((dpub / "api/v1/changes/latest.json").read_text())
    evil = '<img src=x onerror="window.__xss=1">'
    latest["new"].insert(0, {"bounty": "paying", "asset": "subdomains", "host": evil, "sources": "x", "programs": evil, "program_urls": "javascript:window.__xss=1", "raw": evil})
    latest["new_paying"].insert(0, latest["new"][0])
    (dpub / "api/v1/changes/latest.json").write_text(json.dumps(latest))

    # ------------------------------------------------------------------ part 2: server
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = subprocess.Popen([sys.executable, "-I", str(ROOT / "site" / "serve.py"), "--dir", str(dpub), "--port", str(port), "--host", "127.0.0.1"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)

    def get(path, headers=None):
        req = urllib.request.Request(base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    code, h, body = get("/api/v1/assets/subdomains.txt")
    check("server: .txt is text/plain with open CORS", code == 200 and h["Content-Type"].startswith("text/plain") and h.get("Access-Control-Allow-Origin") == "*")
    code, h, body = get("/api/v1/stats.json", {"Accept-Encoding": "gzip"})
    check("server: json is application/json and gzipped when asked", h["Content-Type"].startswith("application/json") and h.get("Content-Encoding") == "gzip")
    etag = h.get("ETag")
    code, h2, _ = get("/api/v1/stats.json", {"If-None-Match": etag})
    check("server: ETag gives 304", code == 304)
    check("server: /api/v1/ answers with the index", json.loads(get("/api/v1/")[2])["name"] == "bug bounty domains")
    check("server: unknown path is 404", get("/api/v1/nope.txt")[0] == 404)
    check("server: path tricks are refused", get("/..%2f..%2fetc/passwd")[0] == 404 and get("/%2e%2e/%2e%2e/etc/passwd")[0] == 404)
    code, h, _ = get("/")
    check("server: index.html has a content security policy that blocks inline scripts", "script-src 'self'" in h.get("Content-Security-Policy", ""), str(h.get("Content-Security-Policy")))

    # ------------------------------------------------------------------ part 3: browser
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        print("SKIP  browser tests (python package `playwright` not installed)")
        sync_playwright = None
    if sync_playwright:
        scope = lambda a: json.loads((dpub / f"api/v1/scope/{a}.json").read_text())
        subs = scope("subdomains")["rows"]
        sub_ok = subs[0][0]
        wild = scope("wildcards")["rows"][0][0]
        ips = [r[0] for r in scope("ips")["rows"]]
        cidr = "198.51.100.0/24"
        selfhosted = [p for p in json.loads((dpub / "api/v1/programs.json").read_text())["programs"] if p["hosting"] in ("self-hosted", "both")]
        errors = []
        with sync_playwright() as p:
            b = p.chromium.launch()
            routes = ["#/", "#/check?q=" + sub_ok, "#/programs", "#/programs?hosting=self", "#/targets", "#/targets/wildcards", "#/targets/ips",
                      "#/changes", "#/sources", "#/api", "#/insights", "#/targets/out-of-scope"]
            for label, vp, mobile in (("desktop", {"width": 1360, "height": 900}, False), ("phone", {"width": 390, "height": 844}, True)):
                ctx = b.new_context(viewport=vp, is_mobile=mobile, has_touch=mobile)
                pg = ctx.new_page()
                pg.on("console", lambda m, l=label: errors.append((l, m.text)) if m.type == "error" else None)
                pg.on("pageerror", lambda e, l=label: errors.append((l, str(e))))
                overflow = []
                for rt in routes:
                    pg.goto(f"{base}/{rt}")
                    pg.wait_for_timeout(500)
                    if pg.evaluate("document.querySelector('#view .notice.bad') !== null"):
                        errors.append((label, f"error box on {rt}"))
                    if pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") > 1:
                        overflow.append(rt)
                check(f"browser {label}: every page loads without errors", not [e for e in errors if e[0] == label], str(errors[:3]))
                check(f"browser {label}: no page scrolls sideways", not overflow, str(overflow))
                ctx.close()

            ctx = b.new_context(viewport={"width": 1360, "height": 900})
            pg = ctx.new_page()
            pg.goto(base + "/")
            pg.wait_for_selector("#ask")
            check("overview: the headline numbers, platform table and asset table", pg.locator(".glance > a").count() >= 6 and pg.locator("#view .ledger").count() >= 3)
            box = pg.locator("#ask")
            box.fill(sub_ok)
            pg.wait_for_selector(".verdict.yes", timeout=5000)
            check("scope check: a listed host is 'in scope' with its program", "In scope" in pg.inner_text("#askOut") and pg.locator("#askOut .progs a").count() >= 1)
            box.fill("a.b." + wild)
            pg.wait_for_selector("#askOut:has-text('wildcard')", timeout=5000)
            check("scope check: a host under a wildcard is covered by it", "*." + wild in pg.inner_text("#askOut"))
            box.fill(f"https://{sub_ok}:8443/login?next=/x")
            pg.wait_for_selector("#askOut:has-text('listed exactly')", timeout=5000)
            check("scope check: a full URL with port, path and query is reduced to its host", "listed exactly" in pg.inner_text("#askOut"))
            box.fill("definitely-not-listed.invalid-zone.test")
            pg.wait_for_selector(".verdict.no", timeout=5000)
            check("scope check: an unknown host is 'not in the lists'", "Not in the lists" in pg.inner_text("#askOut"))
            if cidr:
                base_ip = cidr.split("/")[0].rsplit(".", 1)[0] + "." + str(int(cidr.split("/")[0].rsplit(".", 1)[1]) + 1)
                box.fill(base_ip)
                pg.wait_for_selector("#askOut:has-text('range')", timeout=5000)
                check("scope check: an IP inside a listed CIDR range is in scope", "In scope" in pg.inner_text("#askOut"), pg.inner_text("#askOut"))
            else:
                print("SKIP  CIDR check (no range in demo data)")

            # programs: filter, open one
            pg.goto(base + "/#/programs?hosting=self")
            pg.wait_for_selector("#out .row[data-href], #out .row.click", timeout=5000)
            n_self = pg.locator("#out .row[data-href]").count()
            check("programs: the self-hosted filter lists only self-hosted programs", n_self == len(selfhosted), f"{n_self} vs {len(selfhosted)}")
            pg.locator("#out .row[data-href]").first.click()
            pg.wait_for_url("**/#/program/*")
            pg.wait_for_selector("#ptxt")
            check("program page: name, scope tabs and a plain-list link", pg.locator(".tabs button").count() >= 1 and "programs/" in (pg.get_attribute("#ptxt", "href") or ""))
            check("program page: an 'All' tab lists every asset type of the program in one list",
                  pg.locator('#tabs [data-a="__all"]').count() == 1 and pg.locator("#pout .row .badge").count() >= 1 and pg.locator('#tabs [data-a="apis"]').count() <= 1)
            pg.goto(base + "/#/programs")
            pg.wait_for_selector("#out .row[data-href]")
            pg.fill("#fq", "zzzz-no-such-program")
            pg.wait_for_selector("#out .empty")
            check("programs: search with no match shows an empty-state message", "No program matches" in pg.inner_text("#out"))

            # targets: filters and the ready-made API link
            pg.goto(base + "/#/targets/subdomains")
            pg.wait_for_selector("#out .row")
            total = pg.inner_text("#tact button:first-child")
            pg.click("[data-b='paying']")
            pg.wait_for_timeout(300)
            check("targets: 'Pays' narrows the list and points at the -paying API file",
                  pg.inner_text("#tact button:first-child") != total and "subdomains-paying.txt" in (pg.get_attribute("#tact a.btn", "href") or ""))
            pg.fill("#tq", sub_ok[:8])
            pg.wait_for_timeout(400)
            check("targets: a text search removes the 'same as API' link (no ready-made file for it)", pg.locator("#tact a.btn").count() == 0)
            pg.fill("#tq", "")
            pg.click("[data-b='']")
            pg.locator("#out .row.click").first.click()
            check("targets: clicking a row opens its programs and sources", pg.locator("#out .detail:not([hidden])").count() == 1)

            # changes: hostile text, tabs
            pg.goto(base + "/#/changes")
            pg.wait_for_selector("#out .row:not(.head)")
            pg.locator("#out .row.click").first.click()
            pg.wait_for_timeout(300)
            check("security: HTML in the data is shown as text and never executed", pg.evaluate("window.__xss") is None and "onerror" in pg.inner_text("#out"))
            check("security: a javascript: link from the data is not made clickable", pg.locator("#out a[href^='javascript']").count() == 0)
            pg.click("#ctabs [data-t='removed']")
            pg.wait_for_selector("#out .row:not(.head)")
            check("changes: the 'Removed' tab lists removed values", "Removed" in pg.inner_text("#ctabs") and pg.locator("#out .row").count() > 1)
            pg.locator(".days [data-d]").nth(3).click()
            pg.wait_for_url("**/#/changes/2*")
            check("changes: clicking a day opens that day", "/changes/2" in pg.url)

            # api page
            pg.goto(base + "/#/api")
            pg.wait_for_selector("#built .code")
            pg.select_option("#bk", "-paying")
            pg.select_option("#bp", "hackerone")
            check("api page: the URL builder offers the out-of-scope lists", pg.locator('#ba option[value="oos:master"]').count() == 1)
            pg.select_option("#ba", "oos:master")
            check("api page: choosing out of scope builds the out-of-scope URL", "out-of-scope/master.txt" in pg.inner_text("#built"), pg.inner_text("#built"))
            pg.select_option("#ba", "subdomains")
            check("api page: the URL builder follows the choices", "platforms/hackerone/subdomains-paying.txt" in pg.inner_text("#built"), pg.inner_text("#built"))

            # out of scope: the scope check says "excluded", the exclusions page and program tab list them, and they never leak into targets
            oosj = json.loads((dpub / "api/v1/out-of-scope.json").read_text())
            ex_host = next((r[1] for r in oosj["rows"] if r[0] == "subdomains"), None)
            ex_tree = next((r[1] for r in oosj["rows"] if r[0] == "wildcards"), None)
            check("out of scope: demo data has exclusions to test with", bool(ex_host and ex_tree), str(oosj["rows"][:3]))
            if ex_host and ex_tree:
                master_txt = (dpub / "api/v1/assets/master.txt").read_text().split()
                check("out of scope: an excluded host is never in the target lists", ex_host not in master_txt and ex_host not in (dpub / "api/v1/assets/subdomains.txt").read_text().split())
                pg.goto(f"{base}/#/check?q={ex_host}")
                pg.wait_for_selector(".verdict")
                v1 = pg.inner_text("#view")
                check("out of scope: the scope check says an excluded host is out of scope", "xcluded" in v1 or "Out of scope" in v1, v1[:200])
                pg.goto(f"{base}/#/check?q=x.{ex_tree}")
                pg.wait_for_selector(".verdict")
                v2 = pg.inner_text("#view")
                check("out of scope: a host inside an excluded sub-tree is out of scope too", "xcluded" in v2 or "Out of scope" in v2, v2[:200])
                pg.goto(base + "/#/targets/out-of-scope")
                pg.wait_for_selector("#out .row[data-href], #out .row.click")
                check("out of scope: the exclusions page lists the excluded values", ex_host in pg.inner_text("#out"))
                progs_all = json.loads((dpub / "api/v1/programs.json").read_text())["programs"]
                pex = next(p_ for p_ in progs_all if p_.get("excluded"))
                pg.goto(f"{base}/#/program/{pex['slug']}?asset=out-of-scope")
                pg.wait_for_selector("#pout .row.t-out")
                check("out of scope: a program page shows its own exclusions in a separate tab", pg.locator("#pout .row.t-out").count() >= 1)

            # URLs with a path: the PATH is the scope (HackerOne "kubernetes": https://storage.googleapis.com/kubernetes-release/)
            urows = scope("urls")["rows"]
            uval = "https://storage.bucket-demo.example.com/release-files"       # from demo_data.py: a program whose only scope is this path
            uhost, upath = "storage.bucket-demo.example.com", "release-files"
            check("url: demo data has the bucket url entry", any(r[0] == uval for r in urows))
            check("url: the host of a url entry is not also listed as a host", uhost not in (dpub / "api/v1/assets/subdomains.txt").read_text().split() and "bucket-demo.example.com" not in (dpub / "api/v1/assets/apex.txt").read_text().split())
            for q_, want_yes, what in ((f"{uhost}/{upath}/deep/file.zip", True, "a path below the listed URL is in scope"),
                                       (f"https://{uhost}/{upath}", True, "the listed URL itself is in scope"),
                                       (f"{uhost}/{upath}-old/x", False, "a sibling path (same start, other segment) is NOT in scope"),
                                       (f"{uhost}/other", False, "another path on the same host is NOT in scope")):
                pg.goto(f"{base}/#/check?q=" + q_)
                pg.wait_for_selector(".verdict")
                yes = pg.locator(".verdict.yes").count() == 1
                check("url: " + what, yes == want_yes and (not want_yes or "listed URL" in pg.inner_text("#view")), pg.inner_text("#view")[200:420])
            pg.goto(f"{base}/#/check?q={uhost}/{upath}/internal/x")
            pg.wait_for_selector(".verdict")
            check("url: a path under an EXCLUDED url is out of scope even though its parent url is in scope", pg.locator(".verdict.no, .verdict.out").count() >= 1 and pg.locator(".verdict.yes").count() == 0, pg.inner_text("#view")[200:420])
            pg.goto(f"{base}/#/check?q={uhost}")
            pg.wait_for_selector(".verdict")
            check("url: the bare host says only a path of it is in scope", "Only part of this host" in pg.inner_text("#view") and pg.locator(".verdict.yes").count() == 0, pg.inner_text("#view")[200:420])
            pg.goto(base + "/#/targets/urls")
            pg.wait_for_selector("#out .row[data-href], #out .row.click")
            check("url: the Targets page has a URLs list", uval in pg.inner_text("#out"))
            pg.goto(base + "/#/targets/all")
            pg.wait_for_selector("#out .row[data-href], #out .row.click, #out .empty")
            check("targets: an 'All' tab searches every asset type at once and tags each row with its type",
                  pg.locator('.tabs a[href="#/targets/all"]').count() == 1 and pg.locator("#out .row .host .badge").count() >= 2, pg.inner_text("#out")[:200])
            pg.fill("#tq", uval)
            pg.wait_for_timeout(500)
            check("targets: searching in 'All' finds a url value", pg.locator("#out .row").count() >= 1 and uval in pg.inner_text("#out"))
            pg.fill("#tq", "")
            pg.wait_for_timeout(500)
            check("targets: the All tab links the ready-made all.txt", pg.locator('a[href$="assets/all.txt"]').count() >= 1)
            pg.goto(base + "/#/changes?tab=programs")
            pg.wait_for_selector("#out .row")
            check("changes: a 'Programs' tab shows the program events of the day (left first)", "Program left" in pg.inner_text("#out") and "New program" in pg.inner_text("#out") and "Shrank" in pg.inner_text("#out"), pg.inner_text("#out")[:300])
            pg.goto(base + "/#/targets/apis")
            pg.wait_for_selector("#out .row[data-href], #out .row.click, #out .empty")
            check("apis: the Targets page has an APIs tab with its list", pg.locator('.tabs a[href="#/targets/apis"]').count() == 1 and pg.locator("#out .row").count() >= 1, pg.inner_text("#out")[:200])

            check("insights: 'programs worth a look' data and plain list exist", "review" in json.loads((dpub / "api/v1/insights.json").read_text())
                  and (dpub / "api/v1/insights/programs-to-review.txt").is_file())
            _pj = json.loads((dpub / "api/v1/programs.json").read_text())["programs"]
            _md = [x for x in _pj if x["name"] == "Merge Demo"]
            check("programs: a company page and the platform program of the same name are ONE entry with the page attached",
                  len(_md) == 1 and _md[0].get("self_urls") == ["https://merge-demo.example.com/security"] and _md[0]["hosting"] == "both", str(_md))
            _mj = json.loads((dpub / f"api/v1/programs/{_md[0]['slug']}.json").read_text())
            check("programs: the merged program lists the values of both pages", "portal.merge-demo.example.com" in [v for v, _ in _mj["scope"]["subdomains"]]
                  and "www.merge-demo.example.com" in [v for v, _ in _mj["scope"]["subdomains"]], str(_mj["scope"]))
            _ev = json.loads((dpub / "api/v1/program-events.json").read_text())["events"]
            check("program events: API lists them newest first, with the program's page slug", len(_ev) == 4 and {e["event"] for e in _ev} == {"left", "appeared", "shrank", "returned"} and all(e["slug"] for e in _ev), str(_ev[:2]))
            check("all-time database: API lists everything ever seen and the gone values with their days",
                  "old0.gone-example.com" in (dpub / "api/v1/archive/subdomains-ever.txt").read_text() and "2026-10-15" in (dpub / "api/v1/archive/subdomains-gone.txt").read_text()
                  and json.loads((dpub / "api/v1/stats.json").read_text())["archive"]["subdomains"]["gone"] == 3)
            check("targets: assets/all.txt is the list of the All tab", (dpub / "api/v1/assets/all.txt").is_file() and "*." in (dpub / "api/v1/assets/all.txt").read_text())
            check("program lists: every program has an all.txt with every asset type", any((dpub / "api/v1/programs").glob("*/all.txt")))

            # insights page: sections, a service list link, tiles jump
            pg.goto(base + "/#/insights")
            pg.wait_for_selector(".glance")
            txt = pg.inner_text("#view")
            check("insights: third-party hosting, top-level domains, shared hosts and address space are shown",
                  all(w in txt for w in ("Third-party hosting", "Most used top-level domains", "Hosts listed by more than one program", "Address space")), txt[:200])
            check("insights: a service has a plain-list link into the API", pg.locator('a[href*="insights/services/"]').count() >= 1)
            r = pg.request.get(base + "/api/v1/insights/services/dangling-leads.txt")
            check("insights: the 'check DNS' list is served as plain text", r.ok and "text/plain" in r.headers.get("content-type", ""), str(r.status))

            # watchlist: star a program, see it on the overview and under the Watching filter
            pg.goto(base + "/#/programs"); pg.wait_for_selector("#out .row[data-href]")
            pg.locator("#out .star").first.click()
            pg.goto(base + "/#/programs?mine=1"); pg.wait_for_selector("#out .row[data-href]")
            check("watchlist: a starred program shows under 'Watching'", pg.locator("#out .row[data-href]").count() == 1)
            pg.evaluate("localStorage.removeItem('sl-watch')")

            # theme + menu
            pg.goto(base + "/")
            seen = []
            for t in ("dark", "fiesta", "light"):
                pg.click(f'[data-theme-set="{t}"]')
                seen.append(pg.evaluate("document.documentElement.dataset.theme"))
            check("theme: Light, Dark and Fiesta can each be chosen", seen == ["dark", "fiesta", "light"], str(seen))
            pg.click('[data-theme-set="fiesta"]'); pg.goto(base + "/#/programs")
            pg.wait_for_selector("#out .row[data-href]")
            check("theme: the choice is remembered after a page change", pg.evaluate("document.documentElement.dataset.theme") == "fiesta")
            bg = pg.evaluate("getComputedStyle(document.querySelector('.rail')).backgroundImage")
            check("theme: Fiesta really paints the side rail with a gradient", "gradient" in bg, bg[:80])
            pg.click('[data-theme-set=""]')
            ctx.close()
            ctx = b.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
            pg = ctx.new_page()
            pg.goto(base + "/")
            pg.wait_for_selector("#ask")
            pg.click("#menuBtn")
            pg.wait_for_timeout(300)
            check("phone: the menu button opens the full navigation", pg.locator("#rail.open").count() == 1 and pg.locator("#nav a").first.is_visible())
            pg.click("#nav a[data-nav='sources']")
            pg.wait_for_selector("h1:has-text('Sources')")
            check("phone: choosing a page closes the menu", pg.locator("#rail.open").count() == 0)
            ctx.close()
            b.close()
finally:
    if srv:
        srv.terminate()
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{'ALL PASS' if not FAIL else 'SOME CHECKS FAILED'}  ({PASS} passed, {FAIL} failed)")
sys.exit(1 if FAIL else 0)
