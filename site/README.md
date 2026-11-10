# The website and the API

A small, dependency-free website and a **static API** built from the files the daily run already writes (`data/` and `history/`).
No database, no framework, no third-party service: `build_site.py` turns the data into plain files, `serve.py` hands them out.

```
Raspberry Pi, every day 03:00:  update_bb_domains.py (collects)  ->  data/ + history/  ->  build_site.py  ->  site/public/  ->  serve.py
(GitHub is optional: the Pi does the whole job alone. The GitHub workflow keeps working if you still want it.)
```

## What you get

| Page | What it shows |
|---|---|
| **Overview** | today's numbers, new and removed per day (bar chart), paying targets, platform split, hosting split (platform / self-hosted / both), source health |
| **Programs** | every program, search + filters (platform, hosting, bounty), sort; click one for its full scope by asset type, with copy / download / API link |
| **Targets** | every value of every asset type (subdomains, wildcards, apex, IPs, ASN, github, apps, patterns, internal hosts, "maybe"), filter, paging, paying-only, copy all, download |
| **Changes** | new and removed values per day, history of the last days, paying-only filter |
| **Out of scope** (Targets > Out of scope, and a tab on each program) | what programs EXCLUDE, understood like any scope entry (hosts, wildcards, IP ranges), shown struck through with the program that excludes it. Never mixed into the target lists |
| **Insights** | hosts on third-party hosting (S3, Heroku, GitHub Pages, Azure ... a lead for dangling DNS / takeover), top-level domains, largest programs, most wildcards, hosts listed by 2+ programs, IP space covered, apps by store, GitHub organisations, programs with most exclusions |
| **Check scope** | paste a host, URL or IP: is it in scope, under which program, does it pay? Understands exact hosts, wildcards (`*.example.com`), glob patterns, IPv4 CIDR ranges, github prefixes, and URL paths (`host/path/file` is covered by a listed `host/path` on a segment boundary; the bare host then only gets "a path of it is in scope") |
| **Sources** | which sources worked today, row counts, warnings, rejected and recovered entries with the reason |
| **API** | endpoint list, a URL builder, copy-paste recipes for `curl`, `httpx`, `nuclei`, `subfinder`, `anew`, ... |

It works on a phone (bottom tab bar, stacked rows, filters in two columns), has four theme choices at the bottom of the menu: **Auto** (follows the system), **Light**, **Dark** and **Fiesta** (the colourful one: violet-to-orange side bar, every tile in its own colour), and never loads anything from the internet. Star a program to **watch** it (kept in the browser; shown on the Overview and under the Watching filter). Press `/` to jump to the scope check.

## The API (read only, static files)

Base: `http://<pi-ip>:8080/api/v1/`   (the list of everything is at that address)

| URL | Gives |
|---|---|
| `assets/<asset>.txt` | all values of one asset type, one per line (`subdomains`, `wildcards`, `urls`, `apis`, `apex`, `ips`, `asn`, `github`, `repos-other`, `apps`, `patterns`, `internal-hosts`, `maybe`) |
| `assets/<asset>-paying.txt` | only paying (and unknown-bounty) values |
| `assets/<asset>-new.txt`, `-removed.txt` | what changed today |
| `assets/master.txt` | everything in one list |
| `platforms/<platform>/<asset>.txt` (`-paying.txt`) | one platform only: `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, `hackenproof`, `immunefi`, `self` |
| `programs/<slug>/<asset>.txt` | one program's scope |
| `programs.json`, `programs/<slug>.json` | program list / one program with all its scope |
| `feeds/new.txt`, `new-paying.txt`, `removed.txt` | today's changes, one per line |
| `changes/latest.json`, `changes/<date>.json`, `changes/index.json` | the diffs per day |
| `stats.json`, `history.json`, `sources.json`, `index.json` | numbers, per-day history, source health, the endpoint list |
| `scope/<asset>.json` | what the "Check scope" page uses |
| `out-of-scope/<asset>.txt`, `out-of-scope/master.txt` | what programs exclude, one per line (an exclusion list: `grep -vxFf`) |
| `programs/<slug>/out-of-scope.txt`, `out-of-scope.json` | one program's exclusions / every exclusion with the programs behind it |
| `insights.json`, `insights/services/<service>.txt`, `insights/services/dangling-leads.txt`, `insights/shared-hosts.txt` | the Insights page data and its lists |
| `quality/rejected.json`, `quality/recovered.json` | entries the parser rejected / rescued, with reasons |

Examples (plain text, so they pipe):
```bash
B=http://192.168.1.50:8080/api/v1
curl -s $B/assets/subdomains-paying.txt | httpx -silent                 # probe every paying subdomain
curl -s $B/feeds/new-paying.txt | nuclei -l /dev/stdin -t exposures/    # scan only what is new and pays
curl -s $B/platforms/hackerone/wildcards.txt | sed 's/^\*\.//' | subfinder -dL -
curl -s $B/programs/zoho/subdomains.txt                                  # one program (slug is in programs.json)
curl -s $B/feeds/new.txt | anew ~/seen.txt                               # keep only the unseen
curl -s $B/stats.json | jq .
```
CORS is open, gzip is on, files are cached with ETag, so scripts and other web pages can call it too.

## Run it on the Raspberry Pi (Ubuntu), standalone, no GitHub

The Pi collects the data itself every day, builds the site and serves it. You never log in to GitHub from the Pi.

1. **Copy the project to the Pi** (unzip it there, or `scp -r` from your computer) and open a terminal in it:
   ```bash
   cd ~/bb-domains-patched
   sudo apt update && sudo apt install -y python3     # Python 3.8 or newer (Ubuntu 20.04 and later all qualify)
   ```
2. **Install**
   ```bash
   bash deploy/install-pi.sh
   ```
   It runs the collector once (a few minutes, needs internet), builds the site, starts the web server, and switches on the daily timer.
   Settings such as the port go **in front of the command, on the same line**:
   ```bash
   PORT=80 bash deploy/install-pi.sh            # another port (default 8080)
   DEMO=1 bash deploy/install-pi.sh             # made-up demo data instead of a real run, to look around first
   PORT=80 DEMO=1 bash deploy/install-pi.sh     # both
   ```
   After a demo install, run `bash deploy/install-pi.sh` once without `DEMO=1` to get real data and the daily timer.
3. **Open** `http://<pi-ip>:8080/` from your phone or laptop on the same network. Find the address with `hostname -I`, or try `http://<hostname>.local:8080/`.

**No cron needed.** The installer sets up a systemd timer that does what cron would: every day at 03:00 (Pi time) it runs `site/update.sh` (collect, then rebuild the site). If the Pi was off at 03:00 it runs when it is back on. Check with `systemctl list-timers bb-domains-update.timer`. Set the Pi's time zone with `sudo timedatectl set-timezone Asia/Kolkata`. (Prefer cron? `crontab -e` and add `0 3 * * * /bin/bash /home/ubuntu/bb-domains-patched/site/update.sh >> /home/ubuntu/bb.log 2>&1`, and skip the timer with `sudo systemctl disable --now bb-domains-update.timer`.)

**First days:** the first run only records a starting point, so "new today" and "removed today" are empty; changes show from the second day on. History and "days since" fill up over time.

**Optional API tokens** (HackerOne, Intigriti, YesWeHack, HackenProof direct sources): `cp config/secrets.env.example config/secrets.env`, fill in what you have, done. Other settings (`BB_DISABLE`, `BB_STALE_DAYS`, ...) go in the same file; they are listed in the main README. Self-hosted programs go in `config/self-hosted-programs.tsv`; they are picked up at the next run.

Useful commands
```bash
bash site/update.sh                                 # run the whole job right now
systemctl status bb-domains-web                     # is the server up
journalctl -u bb-domains-update -n 60 --no-pager   # what the last daily run did
sudo systemctl start bb-domains-update              # start a run through systemd
sudo systemctl restart bb-domains-web               # restart the server
less data/stats.txt                                  # the run report: sources today, warnings
```

**Updating the scripts later:** copy the new files over the old ones and run `bash site/update.sh`. Keep your `data/`, `history/`, `state/` and `config/` folders (they are the memory of the project). Changing the port: run the installer again with `PORT=...`.

**Keep it private.** The server has no login. It is meant for your home network: do not forward the port on your router. For access from outside use a VPN such as Tailscale or WireGuard. For a password on the LAN, put Caddy or nginx with basic auth in front and start `serve.py` with `BB_HOST=127.0.0.1`.
Optional firewall: `sudo ufw allow ssh && sudo ufw allow from 192.168.0.0/16 to any port 8080 proto tcp && sudo ufw enable`.

**Using GitHub as well (optional):** if you keep the GitHub workflow, do not run both on the same folder. Two separate copies are fine.

## Try it without the Pi

```bash
python3 site/demo_data.py demo                       # fake project folder (all names end in .example)
python3 site/build_site.py --data demo/data --history demo/history
python3 site/serve.py                                # http://localhost:8080
```

## Files

| File | Role |
|---|---|
| `site/insights.py` | the extra facts of the Insights page (service patterns, shared hosts, IP space), used by build_site.py |
| `site/build_site.py` | data/ + history/ -> `site/public/` (UI copy + `api/v1/*`). Builds into a new folder and swaps it in, so a visitor never sees a half-built site. Stops with an error (and keeps the old site) when there is no data |
| `site/serve.py` | the web server (standard library only): types, CORS, gzip, ETag, CSP, `/healthz` |
| `site/update.sh` | the daily job: collector, then build. What the timer runs |
| `site/ui/` | the website: `index.html`, `style.css`, `core.js`, `check.js`, `pages.js`, `pages2.js` (no build step, no libraries) |
| `site/demo_data.py` | fake data for trying and testing |
| `deploy/` | systemd units (web server, daily update + timer) and `install-pi.sh` |
| `tests/test_site.py` | builds from simulated data, checks API files against the data, the server, and every page in a headless browser (desktop + phone, scope check, XSS) |

`tests/test_site.py` needs Playwright only for its browser part (it is skipped with a note when Playwright is missing).

## If the first run went wrong (wiping and starting again)

The data folders are the memory of the project, so after a bad first run (for example a crash that left almost everything rejected) start clean:
```bash
sudo systemctl stop bb-domains-update.timer
rm -rf data history state site/public
bash deploy/install-pi.sh
```


## Added in 1.1.0
- Targets page: an **APIs** tab (the `apis` overlay list).
- Program page: an **All** tab (every asset type in one searchable list) and `programs/<slug>/all.txt`; an `apis` tab derived from the program's hosts and urls.
- API page: the URL builder offers the out-of-scope lists (`out-of-scope/<asset>.txt`, `out-of-scope/master.txt`).
- Insights page: **Programs worth a look** (programs with no testable target, possible duplicates) and `insights/programs-to-review.txt`.
- One program is one entry: the collector merges the different spellings of a program (url forms, `www.`, name variants) from all sources.

## Added in 1.2.0
- Targets page: an **All** tab (every asset type except the `apis` overlay and the `maybe` guesses, one searchable list, each row tagged with its type).
- `data/review-removed.txt` has a new last column `why_removed`: "program no longer listed by any source today" (made private, paused, closed, or every source lost it) versus "program still listed by <sources> but this value is no longer in its scope". The Changes page shows it under "Why removed".

## Added in 1.4.0
- Changes page: a **Programs** tab with the program events of the day (appeared, left, came back, shrank, grew). `api/v1/program-events.json` has the latest 1500 events, newest first, with the program's page slug.
- Program page: a **History** block (that program's events) and, for a company page merged into its platform program, **Also self-hosted**. `programs/<slug>.json` carries `events` and `self_urls`.
- `api/v1/assets/all.txt`: every asset type in one list, the same list as the Targets page All tab.
- Sources page: project size and free disk space.

## Added in 1.5.0
- `api/v1/archive/<asset>-ever.txt` and `-gone.txt` from `history/all-time.tsv`; Sources page shows the all-time database counts; `stats.json` has an `archive` block.
