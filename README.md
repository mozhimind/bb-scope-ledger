# bb-domains

Version: see the [`VERSION`](VERSION) file (shown on the website's Sources page and in `data/stats.json`). Unzipped folder and zip are named `bb-domains-v<version>`. Bump `VERSION` (MAJOR.MINOR.PATCH) with every change you hand over; it is separate from `PARSER_VERSION`, which only controls baseline days.

Daily automated collection of public bug bounty scope: apex domains, subdomains, wildcards and IPs,
with a list of what is new each day.

**New: a website and a static API** (works on a phone, runs on a Raspberry Pi, no third-party service): programs, targets, daily changes, "is this host in scope?", source health, and URLs such as `/api/v1/assets/subdomains-paying.txt` that you can pipe into `httpx`, `nuclei` or `subfinder`. See [`site/README.md`](site/README.md) for the pages, the API list and the Raspberry Pi setup (`bash deploy/install-pi.sh`, standalone: the Pi collects the data itself, no GitHub needed).

## Sources (9 mirrors and aggregators, plus 9 direct sources)
| # | Name in the code | Download | What it gives |
|---|---|---|---|
| 1 | `arkadiyt-domains` | [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) → [`data/domains.txt`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/domains.txt) | Flat list of in-scope hosts from all platforms (incl. Federacy). No bounty flag. |
| 2 | `arkadiyt-wildcard` | same repo → [`data/wildcards.txt`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/wildcards.txt) | Wildcard bases. No bounty flag. |
| 3 | `arkadiyt-hackerone` | same repo → [`data/hackerone_data.json`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/hackerone_data.json) | Program scope with a real bounty flag (`offers_bounties`, `eligible_for_bounty`) |
| 4 | `arkadiyt-bugcrowd` | same repo → [`data/bugcrowd_data.json`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/bugcrowd_data.json) | Scope; paying if `max_payout` > 0 |
| 5 | `arkadiyt-intigriti` | same repo → [`data/intigriti_data.json`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/intigriti_data.json) | Scope; paying if `max_bounty` > 0 and not "No Bounty" |
| 6 | `arkadiyt-yeswehack` | same repo → [`data/yeswehack_data.json`](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/yeswehack_data.json) | Scope; paying if `max_bounty` > 0 |
| 7 | `projectdiscovery` | [projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) → [`dist/data.json`](https://github.com/projectdiscovery/public-bugbounty-programs/blob/main/dist/data.json) (generated from [`src/data.yaml`](https://github.com/projectdiscovery/public-bugbounty-programs/blob/main/src/data.yaml), which is read instead if the JSON is missing) | Program domains and a `bounty` flag |
| 8 | `diodb` | [disclose/diodb](https://github.com/disclose/diodb) → [`program-list.json`](https://github.com/disclose/diodb/blob/master/program-list.json) | Registrable domains of program pages. Leads, not confirmed scope. |
| 9 | `immunefi-direct` | [immunefi.com/public-api/bounties.json](https://immunefi.com/public-api/bounties.json) | Web assets of paying programs, plus GitHub assets |

### Direct from the platforms and your own list (rows 10-18, optional)
Same pipeline, same files; their names in the files end in `-direct`. They are read by [`scripts/directsources.py`](scripts/directsources.py) straight from the platforms, so they are fresher than the mirrors and keep working if a mirror stops. A platform can be listed twice (mirror and direct); "paying" simply wins when two sources disagree.

| # | Name in the code | Where it reads | Login needed |
|---|---|---|---|
| 10 | `hackerone-direct` | HackerOne website, public GraphQL (`hackerone.com/graphql`, program directory + each program's structured scope) | none |
| 11 | `hackerone-api` | [HackerOne Hacker API](https://api.hackerone.com/getting-started-hacker-api/): `/v1/hackers/programs`, then `/v1/hackers/programs/<handle>/structured_scopes`. The only way to see programs you were invited to | username + API token (HackerOne → Settings → API Token) |
| 12 | `bugcrowd-direct` | [bugcrowd.com/engagements.json](https://bugcrowd.com/engagements.json?category=bug_bounty), each program's brief page (the element `data-react-class="ResearcherEngagementBrief"` points to the scope document), then that scope document. Paying when its reward table has a maximum above 0 | none |
| 13 | `intigriti-direct` | [Intigriti researcher API](https://api.intigriti.com/external/researcher) when `INTIGRITI_TOKEN` is set, otherwise the public website: the program directory is an Algolia search index with a public search-only key, scope from `app.intigriti.com/api/core/public/programs/<company>/<program>` | token optional (Intigriti → Settings → API) |
| 14 | `yeswehack-direct` | [api.yeswehack.com/programs](https://api.yeswehack.com/programs) and `/programs/<slug>` | optional token |
| 15 | `hackenproof-direct` | the JSON the site itself loads (`/bug-bounty-programs-list`, then `/bug-bounty-programs-list/<slug>`); if that is refused, the HTML pages `/programs` and `/programs/<slug>` | none (optional partner key in the secret `HACKENPROOF`) |
| 16 | `self-hosted-manual` | your own file [`config/self-hosted-programs.tsv`](config/self-hosted-programs.tsv): scope of programs a company runs itself (Google, Microsoft, Zoho ...), see "Self-hosted programs" below | none |
| 17 | `self-hosted-pages` | **automatic**: you list the program pages once in [`config/self-hosted-pages.tsv`](config/self-hosted-pages.tsv); the run downloads them every day and reads the scope out of the text | none |
| 18 | `self-hosted-text` | **paste**: for pages a script cannot read (drawn by JavaScript, like bughunters.google.com): paste the page text into `config/self-hosted-text/<name>.txt` | none |

`immunefi-direct` (row 9) was already a direct source. Federacy is not read directly: arkadiyt's own crawler has it switched off, so its hosts only arrive through the arkadiyt flat lists, if at all.

**Set up the tokens (all optional).** In the repository: Settings → Secrets and variables → Actions → New repository secret. Names: `H1_USERNAME`, `H1_TOKEN`, `INTIGRITI_TOKEN`, `YWH_TOKEN`, `HACKENPROOF` (the last one only if HackenProof starts refusing its JSON; the HTML fallback works without it). A source without its secret shows as `skipped` in `stats.txt` and is not an error.

**Public programs only, by default.** The authenticated APIs also list programs you were invited to, and their scope is usually under NDA. Only public programs are read unless you set `BB_INCLUDE_PRIVATE: "1"` in the workflow. Do that only if the repository is **private**.

**These parsers are not yet verified against the live platforms.** They follow the documented / publicly observed formats and are tested with fixtures. When a platform answers in a format the parser does not know, the source is reported in `stats.txt` ("Sources today" and "Warnings") with the start of the answer, the last good copy is kept, and the run stays green. Fix the parser from that sample. `BB_DIRECT_STRICT=1` makes such a breakage turn the run red instead. `BB_DIRECT=0` switches all direct sources off.

Branches tried: the arkadiyt files `main` then `master`; diodb `master` then `main`; projectdiscovery `main` only (JSON, then YAML); immunefi-direct has one URL. Each source is kept in `state/<name>.tsv`;
if a download fails, that copy is used and the run is marked failed.

### What `NON_SCOPE` in the script is
Only diodb and immunefi-direct use it. Their data contains links that are not scope: a program's policy page on a bounty platform
(`hackerone.com/x`), a contact form on a SaaS tool (`typeform.com`, `zendesk.com`), a social page (`twitter.com`), a contract on a block
explorer (`etherscan.io`). Turning those into apexes would put the platform or vendor into your lists. A link is skipped when its host,
or its registrable domain, is in the set. The five platform files and projectdiscovery do not use it, so a program that really has
`zendesk.com` in scope still gets it from them. When you see noise from diodb or immunefi-direct in `review-by-source.txt`, add its domain.

## Start here each day
All three are tab-separated review files with the columns `bounty, assets, host, sources, programs, program_urls, raw_entries`
(`assets` is the asset type, `programs` and `program_urls` say whose scope the entry came from, `raw_entries` is how the source wrote it).
| File | What it is |
|---|---|
| [`review-new-paying.txt`](data/review-new-paying.txt) | New today (any asset type) with bounty paying or unknown. Test these first. |
| [`review-new.txt`](data/review-new.txt) | Everything new today, paying first |
| [`review-removed.txt`](data/review-removed.txt) | Everything that disappeared since the previous snapshot, with where it came from (`last_seen_in` is the snapshot date; the context comes from `state/context-DATE.tsv`) |
| [`failed-sources.txt`](data/failed-sources.txt) | Empty on a good day. Otherwise says which source failed and what was done about it |

The per-asset files (`apex-new.txt`, `ips-new.txt`, ...) are plain lists that other tools can read.

## All files in `data/` (latest run)
Thirteen asset types, and every asset type has the same four files: `<asset>.txt` (everything), `<asset>-paying.txt` (bounty status paying, or unknown, see "Bounty flag"),
`<asset>-new.txt` and `<asset>-removed.txt` (difference to the previous snapshot).

| Asset type | What it holds |
|---|---|
| `apex` | Registrable domains (Public Suffix List: `www.bbc.co.uk` gives `bbc.co.uk`): the ones a source lists plus the ones derived from a listed subdomain |
| `subdomains` | Hosts below an apex, including wildcard bases that are not apexes (`corp.example.com`) |
| `wildcards` | Wildcard bases (`*.example.com` is stored as `example.com`). Also present in apex or subdomains. |
| `urls` | Addresses **with a path**, written `scheme://host[:port]/path` (no scheme given = `https`; query and fragment dropped; a trailing `/*` is removed because a url already means "and everything below"). Example: HackerOne's Kubernetes program lists `https://storage.googleapis.com/kubernetes-release/`: only that bucket is in scope, so it goes here and `storage.googleapis.com` is **not** added to apex/subdomains. A bare host, `host/` or `host/*` is still a host. Internal hosts and IPs with a path stay in `internal-hosts` / `ips`. |
| `apis` | An **overlay**, not a new scope: every host / wildcard / url that the platform itself typed as an API (rule `declared-api`) or whose address says so (`api.x.com`, `yahooapis.com`, `/api/`, `/graphql`, `/v1/`). The same values are also in `subdomains` or `urls`, so the list is left out of totals and counted once. Use it to feed API-focused tools. |
| `ips` | IPs and CIDR ranges found in scope |
| `asn` | Autonomous system numbers written `AS16314` (from `AS16314`, `ASN 16314`, `AS6720 1/2`, ...) |
| `github` | In-scope GitHub projects (`https://github.com/org/repo`, or `https://github.com/org` for a whole org) |
| `repos-other` | In-scope repos on GitLab, Bitbucket, Codeberg, SourceForge |
| `apps` | Store URLs (App Store, Google Play, TestFlight, Chrome Web Store, Atlassian Marketplace, ...) and package ids such as `com.example.app` |
| `patterns` | Wildcards and templates that cannot become one plain host: `api-*.example.com`, `{tenant}.example.com`. The real domain at the end is added to the normal lists. |
| `internal-hosts` | Well-formed hosts and IPs that are not on the public internet: `.internal`, `.local`, unknown TLDs, `10.x`, `192.168.x`. For reference only. |
| `maybe` | Hosts, IPs and ASNs found inside free text ("... (NCSC.ch)"). The program did not state them as scope outright, so this is a guess: check by hand. |

Links for all asset types: for example [`apex.txt`](data/apex.txt), [`apex-paying.txt`](data/apex-paying.txt), [`apex-new.txt`](data/apex-new.txt), [`apex-removed.txt`](data/apex-removed.txt); the same pattern works for `subdomains`, `wildcards`, `urls`, `apis`, `ips`, `asn`, `github`, `repos-other`, `apps`, `patterns`, `internal-hosts`, `maybe` in [`data/`](data/).

| Other files | Description |
|---|---|
| [`master.txt`](data/master.txt) | Every distinct host, IP, URL or pattern of every asset type, once: the host column of `review-by-source.txt` without repeats. `stats.txt` shows the sum. |
| [`review-by-source.txt`](data/review-by-source.txt) | One line per (host, asset type) with bounty status, the sources that list it, and `hosting` (`platform`, `self-hosted`, `both` or `unknown`, see below) |
| `program-out-of-scope.tsv` | What each program EXCLUDES (`id`, asset type or `text`, value): exclusions the sources state as assets (HackerOne, Bugcrowd, Intigriti, YesWeHack, HackenProof) are understood like scope entries; sentences such as "social engineering" are kept as text. Never part of any target list; the website shows them as "Out of scope" and the scope check uses them. |
| [`programs.txt`](data/programs.txt) | One line per program page: `hosting`, `bounty`, `program`, `program_url`, `hosts` (how many values it lists), `sources`, `also_on` (platform programs that share a host with a self-hosted one) |
| [`recovered.txt`](data/recovered.txt) | Audit trail of every repaired or guessed entry: `rule, source, raw, assets, result` |
| [`rejected.txt`](data/rejected.txt) | What fits no asset type, with the reason: `placeholder`, `free-text`, `single-label`, `public-suffix`, `file-ext`, `numeric-tld`, `bad-chars`, `bad-label`, `bad-ip`, `ip-too-broad`, `not-a-project`, `store-host` |
| [`stats.txt`](data/stats.txt) | A one-line headline, counts of the review files, "Sources today" (status, rows, rejected and seconds per source), a table of total / paying / new / removed per asset type, and how each number is counted |

### Self-hosted programs (Google, Microsoft, Zoho ...)
Some companies run their bug bounty on their own website instead of HackerOne, Bugcrowd and the other platforms. How to find them:
- Open [`programs.txt`](data/programs.txt) and look at the first column. `self-hosted` = the program page is **not** on a known platform
  (the platform domains are in `PLATFORM_DOMAINS` in `update_bb_domains.py`; add one if a platform is missing). `platform` = it is.
  `both` = a self-hosted program whose domains also appear in a platform program (the `also_on` column names that program).
- The last column of [`review-by-source.txt`](data/review-by-source.txt), `hosting`, says the same for every host, so
  `awk -F'\t' '$5=="self-hosted"' data/review-by-source.txt` lists the assets of self-hosted programs only.
- Where the data comes from: `diodb` (the disclose.io database) knows many self-hosted programs, but only gives the program's own
  domain, not its scope. Nobody publishes the scope of a self-hosted program as data, so for the ones you care about, write it down once in
  [`config/self-hosted-programs.tsv`](config/self-hosted-programs.tsv) (program, program URL, paying or not, scope entry; one line per entry,
  tab-separated). It becomes the source `self-hosted-manual` and goes through the normal parser, so wildcards, IPs and so on land in the right files.

#### Automating self-hosted programs (easiest first)
1. **Paste (works for every page, 1 minute per program).** Open the program page (for example bughunters.google.com), press Ctrl+A, Ctrl+C, and paste into a new file `config/self-hosted-text/google-vrp.txt`. Put three optional lines on top:
   `# program: Google VRP`, `# url: https://bughunters.google.com/`, `# bounty: paying`. The run reads the text exactly like an asset description (see below): lists under "in scope" become targets, lists under "out of scope" become exclusions. Re-paste only when the page changes.
2. **Download (fully automatic, only for pages that contain the scope as plain HTML).** Add one line per program to `config/self-hosted-pages.tsv`: `program <TAB> program url <TAB> paying|non-paying|unknown <TAB> page url [<TAB> more page urls]`. If a page is drawn by JavaScript the Sources table says "no scope found on ...": switch that program to method 1.
3. **One line per entry** in `config/self-hosted-programs.tsv` (the old manual way) stays available for exact control.

#### Descriptions are read too (why Yahoo had so few assets)
Programs often list one broad asset and write the real list into that asset's description (the "expand asset" text on the platform page). Earlier versions only read the asset name. Now every direct source (HackerOne `instruction`, Intigriti asset `description`, YesWeHack, Bugcrowd and HackenProof descriptions, Immunefi) is also searched by [`scripts/textscope.py`](scripts/textscope.py): list items and table rows become targets (rule `from-description`), an "out of scope" section becomes exclusions, and hosts only mentioned inside a sentence go to `maybe.txt` for a human look. Intigriti assets of type "other" or unknown are no longer skipped. Parser version changed, so the first run is a baseline day (no "new" flood).

### Other folders
- [`state/`](state/): memory between runs. `<source>.tsv` is the last good copy of each source (used when a download fails); `context-DATE.tsv` holds programs and raw entries of every value for the last three days, so `review-removed.txt` can say where a removed host came from.
- [`history/daily/DATE/`](history/daily/): a small snapshot per day, the last 30 days stay in the working tree (git history keeps all of them). It holds the 12 asset lists (`apex.txt`, ... `maybe.txt`: tomorrow's diff base), the three `review-*` files (that day's changelog with context), `failed-sources.txt` and `stats.txt`. The `-paying`, `-new`, `-removed` files and `master.txt` are not copied there: the review files already contain every new/removed value with more detail, and paying/master can be rebuilt from the lists.
- [`history/monthly/YYYY-MM/`](history/monthly/): running unions for the month, updated in place (no new files per day): `<asset>.txt` and `<asset>-paying.txt` for all asset types plus `master.txt`. This is "everything seen at any point this month", the only place that remembers values that appeared and then vanished.

## How the daily run works
1. Download each source with retries. A source that errors, comes back empty, or shrinks below 50 % of its
   last good copy is replaced by that last good copy. Nothing is falsely reported as removed, and the run
   is marked failed after the data is committed, so GitHub emails you.
2. Clean every entry (lowercase, punycode, junk out, TLD must exist) and classify it with the Public Suffix List.
3. Merge. A host's bounty flag is the best any source says: `paying`, else `unknown`, else `non-paying`.
4. Diff against the latest earlier folder in `history/daily`. A skipped day, a late run or a re-run on the same day
   all give the right diff. The first run has no diffs.
5. Write the files, the history snapshot, the monthly unions and a step summary on the Actions run page.

## How a raw entry is understood ([`scripts/scopeparse.py`](scripts/scopeparse.py))
Scope entries are messy. Instead of dropping what does not look like a clean hostname, every entry is tried in this order,
and the first match wins:

| What the entry looks like | Where it goes | Logged as repair? |
|---|---|---|
| `https://Example.com:8443`, `user@host`, trailing dot, IDN | `apex.txt` / `subdomains.txt` | no (normal clean-up) |
| `https://Example.com:8443/api/v1/?x=1` (a real path) | `urls.txt` as `https://example.com:8443/api/v1` | no (normal clean-up); the host is not also listed |
| `*.example.com`, `*.example.com/*`, `.example.com`, `(*.)example.com` | `wildcards.txt` and the lists | only the odd forms |
| defanged `hxxps://evil[.]example[.]com`, markdown `[x](url)` / `**x**`, `(host)`, `host)`, `"host",`, `http//host`, `a..b.com`, `mail@host` | the lists | yes |
| lists: `a.com, b.com`, `a.com and b.org`, two URLs separated by a space | each host to the lists | yes (`multi-entry`) |
| `example.com (main site)`, `host - web app`, `host: REST API` | the host to the lists | yes (`comment-stripped`) |
| short-form choices: `*.olaplex.{cl,fi,co.jp}`, `(se\|fi\|uk).bingo.com`, `www.doctolib.(fr\|de)`, `[it \| fr \| …].louisvuitton.com` (written out one host per choice; `…` / `etc` in the list becomes `*`; at most 64 results, only when the brackets touch a dot and hold a `,` or `\|`) | each result to the lists | yes (`alternatives`, `ellipsis-wildcard`) |
| IPv4 / IPv6, CIDR, ports, `1.2.3.*`, `1.2.3.0-255`, `1.2.3.4 - 1.2.3.20` (turned into CIDR blocks) | `ips.txt` | ranges and stars |
| `AS16314`, `ASN 16314`, `AS6720 1/2`, `AS123 (Example Corp)` (written back as `AS<number>`) | `asn.txt` | only with a comment |
| private / loopback / link-local IPs | `internal-hosts.txt` | |
| App Store / Play / marketplace URLs, package ids (`com.example.app`, or anything a platform marks as ios/android) | `apps.txt` | |
| GitHub project or org URLs (`.git`, branches and file paths are cut) | `github.txt` | |
| other code hosts | `repos-other.txt` | |
| `api-*.example.com`, `{tenant}.example.com` | `patterns.txt` + the real domain at the end to the lists | yes (`pattern`, `pattern-tail`) |
| valid-looking hosts with a TLD that does not exist (`.internal`, `.local`, typos) | `internal-hosts.txt` | |
| sentences that contain a host, IP or ASN | `maybe.txt` (never the main lists) | yes (`text-extract`) |
| everything else | `rejected.txt` | |

Package ids keep their upper/lower case. A host is only accepted into the main lists when its TLD exists
(Public Suffix List). Apps, repos, patterns, internal hosts and maybe-hosts appear in `review-by-source.txt` and
`review-new.txt` too (column `assets`), and [`github-new.txt`](data/github-new.txt) / [`apps-new.txt`](data/apps-new.txt) list what is new each day.

## Bounty flag
A host is `paying` if any source says so, else `non-paying` if any source says so, else `unknown`.
- HackerOne: program `offers_bounties` and the asset's `eligible_for_bounty`
- Bugcrowd: `max_payout` above 0
- Intigriti: `max_bounty` above 0 and the asset's impact is not "No Bounty"
- YesWeHack: `max_bounty` above 0
- projectdiscovery: `bounty` (if the file used lacks that field the host is `unknown`); diodb: `offers_bounty`; immunefi-direct: always paying

The flat arkadiyt lists have no flag. Hosts that only they cover (for example Federacy) stay `unknown` and still count
as paying by default so nothing disappears from the `*-paying` files. Set `BB_UNKNOWN_PAYING=0` in the workflow to keep
only confirmed paying hosts. The `bounty` column in the review files always shows the real status.
App-store links, repository links (GitHub/GitLab with a path), free-text targets and Atlassian Marketplace listings from the
platform files are skipped.

## Apex rules (Public Suffix List)
Apex = registrable domain from the ICANN part of the [Public Suffix List](https://publicsuffix.org/list/), so `foo.github.io` and `x.s3.amazonaws.com` collapse to `github.io` and
`amazonaws.com` (platform tenants are not separate apexes). Where the list lacks a second level that registries really use
(`co.br`, `co.nl`, `com.be`, `com.nz`, `com.ru`, `com.de`), `com./co./org./net./gov./edu./ac./or./ne./go.` plus a 2-letter country code
is also treated as a suffix, so `transunion.co.br` stays its own apex. Underscore labels (`_dmarc.example.com`) are now accepted; the old script rejected them.

## Denylist
[`config/denylist.txt`](config/denylist.txt) is off by default (everything commented out), as before. Entries you uncomment are removed,
with everything below them, from all lists.

## When parsing rules change
Changing how entries are understood (for example in `scopeparse.py`) moves some entries around, and that one-off change should not
show up as "new" and "removed" hosts. Bump `PARSER_VERSION` at the top of `scripts/update_bb_domains.py` in the same change. The next
run sees that it differs from `state/parser-version.txt`, writes the data but no diffs that day (also if you re-run it the same day),
and says so in `stats.txt`. You can still force the same thing by hand: run the workflow with **baseline** ticked.

## For maintainers (and for any AI you hand this project to)
- **One run, in order:** `scripts/update_bb_domains.py` reads the 18 sources, `scripts/scopeparse.py` turns each raw entry into zero or more typed values, the `Collector` merges them, the script diffs against the latest earlier folder in `history/daily`, then writes `data/`, `history/` and `state/`. The module docstring at the top of the script has the same overview plus the key rules and why they exist.
- **Asset type:** one category of value with its own family of files. The names are the keys of `ASSETS` in the script. Inside the code each also has a short "kind" code (`sub`, `ip`, `app`, ...) that scopeparse uses; `ASSETS` maps one to the other.
- **Add an asset type:** add it to `ASSETS`, make scopeparse produce a hit with that kind, add a case to `tests/test_parse.py`, and add a row to the table above. Every file of the family, the stats table and the history copies follow automatically.
- **Add a direct platform source:** a function in `scripts/directsources.py` (raise `Skip` when not configured, `ShapeError` for an unknown answer), one line in `main()`, fixture answers in `tests/simulate.py`.
- **Add a source:** a `src_xxx()` function that returns `(raw entry, bounty status, program name, program url)` rows, plus one line in the `sources` list in `main()`.
- **Change how entries are understood:** only `scopeparse.py`; the table in `tests/test_parse.py` says what must come out.
- **After changing parsing rules** bump `PARSER_VERSION` (see "When parsing rules change"); no manual baseline run is needed.
- **Tests:** `tests/test_parse.py` (parser table), `tests/simulate.py` (a multi-day offline run with fake sources) and `tests/test_site.py` (website and API). All run without internet.
- **Website / API:** `site/` (`build_site.py` writes `site/public/api/v1/*`, `ui/` is the front end, `serve.py` the server) and `deploy/` (Pi setup). They only read `data/` and `history/`; the daily run does not depend on them.
- **`scripts/bbclean.py`** is an older stand-alone cleaner; the daily run only borrows three constants from it.

## Running locally
Python 3.8 or newer, standard library only (the tests are run on 3.8 and on the newest version).
```bash
python3 scripts/update_bb_domains.py         # needs internet
python3 tests/test_parse.py                  # table of ~100 raw entries and what each must become
python3 tests/simulate.py                    # offline multi-day checks with fake sources, no internet
python3 tests/test_site.py                   # website + API: build, server, every page in a headless browser (browser part needs playwright)
python3 site/build_site.py && python3 site/serve.py   # the website at http://localhost:8080
```
Settings are environment variables, all optional (set them in the `env:` of the workflow step or in front of the command):

| Variable | Default | Meaning |
|---|---|---|
| `BB_BASELINE` | empty | `1` = write today's data but no new/removed diffs (the workflow's **baseline** checkbox sets it) |
| `BB_MIN_RATIO` | `50` | a source that returns fewer than this % of its last good row count is treated as broken and the last good copy is used |
| `BB_UNKNOWN_PAYING` | `1` | `1` = hosts with unknown bounty status also appear in the `*-paying` files; `0` = only confirmed paying |
| `BB_RETAIN_DAYS` | `30` | days of `history/daily` kept in the working tree |
| `BB_TZ` | `Asia/Kolkata` | time zone that decides today's date |
| `BB_DATE` | today | force the run date (`YYYY-MM-DD`), used by the tests |
| `BB_DIRECT` | `1` | `0` switches off the six direct platform sources |
| `BB_INCLUDE_PRIVATE` | empty | `1` = direct sources also read PRIVATE programs of the token owners (only in a private repository) |
| `BB_DIRECT_STRICT` | empty | `1` = a broken direct source fails the run instead of only warning |
| `BB_DIRECT_WORKERS` | `6` | how many program pages of one platform are read at the same time (`1` = one after the other, the slow old way) |
| `BB_DIRECT_BUDGET` | `600` | seconds one direct source may take; when it runs out the partial data is discarded and the last good copy is used |
| `BB_DISABLE` | empty | comma-separated source names to retire (e.g. `arkadiyt-domains,arkadiyt-hackerone`); they are not downloaded and the run is not red because of them |
| `BB_STALE_DAYS` | per source | `0` switches off the "mirror unchanged for N days" warning, a number replaces the default limits (3 days for the `arkadiyt-domains` and `arkadiyt-wildcard` lists, 7 for the other mirrors) |
| `BB_DIRECT_DELAY` | `0.3` | pause in seconds between requests to the same platform |
| `H1_USERNAME`, `H1_TOKEN`, `INTIGRITI_TOKEN`, `YWH_TOKEN`, `HACKENPROOF` | empty | API credentials, set as repository secrets |
| `BB_ROOT` | the project folder | where `data/`, `state/`, `history/`, `config/` live, used by the tests |

## TODO
- Check the six direct sources against the live platforms after the first runs (see `stats.txt`, "Sources today" and "Warnings") and correct any parser the platforms disagree with
- More direct platforms: Standoff365, Zerocopter, BugBase and others listed on [disclose.io](https://disclose.io/platforms/); Federacy once a public endpoint is known
- More sources: [disclose/bug-bounty-platforms](https://github.com/disclose/bug-bounty-platforms), [disclose.io platforms](https://disclose.io/platforms/), and other programs published anywhere on the internet
- Make adding a source easy. Today a source is a small function in [`update_bb_domains.py`](scripts/update_bb_domains.py) that returns `(raw entry, bounty status, program name, program url)` rows and is added to the `sources` list; `scopeparse` already copes with messy entries, so only the download and the field names differ per source. Idea: a `config/sources.txt` for the simple cases (plain-text lists, and JSON with a given path to the entries and to the bounty flag)
- Notifications (Discord / Telegram / Slack / email), deliberately left out for now so that no third-party service is needed with the contents of `data/review-new-paying.txt`

## Changes in 1.3.0
- **Unreadable programs are kept, not "removed".** If a platform page cannot be read today (for example a Bugcrowd engagement page whose layout differs, or throttling), the direct source keeps that program's rows from the last good run, for up to 7 days in a row (`state/<source>.carry` counts the days). The Sources table says "N programs could not be read today, their hosts from the last good run are kept". Failed pages are retried up to three times with longer pauses.
- **Apps inside app names.** `app:Klarna iOS App (com.klarna.app)` now gives `com.klarna.app` (rule `app-extracted`); store links inside the text are kept too. A bare app name with no id is still not an asset.
- **Fewer duplicate self-hosted programs.** The same company listed by two mirrors with two different pages of its site is one program.
- **self-hosted-pages** explains in its warning why a page gave nothing (drawn by JavaScript: paste the text instead).

## Changes in 1.4.0
- **Program history** (`scripts/proghistory.py`): the run remembers every program (`state/programs-seen.tsv`) and logs what happened to it in `history/program-events.tsv`: **appeared**, **left** (missing on two runs in a row; the note says whether every source that listed it answered today, i.e. it was really dropped, or a source had a problem), **returned**, **shrank** (values at half or less) and **grew** (doubled). The website shows them on the Changes page (tab "Programs", per day), on every program page (History) and in `api/v1/program-events.json`. The first run after the upgrade only seeds the memory (no events), and so does every baseline day.
- **One program, one entry** on the site: a company page and the platform program of the same name (hosting "both") are shown once, with "Also self-hosted" and the values of both.
- **Targets page, All tab** has its own list file `api/v1/assets/all.txt`.
- **Disk**: `BB_RETAIN_MONTHS` (12) prunes old monthly unions, `BB_MIN_FREE_MB` (300) stops a run when the disk is nearly full, the Sources page shows the project size and the free space, and `deploy/backup.sh` makes a compressed backup of config, state and history (about 10 MB) and keeps the newest 7.

### What to put on GitHub
The GitHub version and the Pi version are the same project. Upload everything, including `.github/workflows/daily.yml`, which runs the job daily and commits `data/`, `history/` and `state/` itself. Only `deploy/install-pi.sh` is Pi-only: you simply do not run it on GitHub. Earlier notes said the repository would grow by gigabytes a year and that `data/` should not be uploaded. That was wrong. Measured on real data, the context files change about 292 of 65k lines a day (about 4.5 KB compressed), so growth is small. The Pi and the GitHub run are independent (each has its own history), and both fire around 03:00 IST.

## Changes in 1.5.0
- **All-time database** (`scripts/archive.py`): `history/all-time.tsv` holds every value that was ever in scope: asset, value, first_seen, gone_on, bounty (best status ever) and up to three programs. Rows are never deleted. A value that disappears gets a `gone_on` date and a returning value is cleared again. Nothing is marked gone on baseline days or on days when a source was unavailable. For values already there when the archive starts, first_seen is that first day.
- **API**: `api/v1/archive/<asset>-ever.txt` (everything ever seen) and `<asset>-gone.txt` (gone values with their date); the Sources page shows the totals.
- **Keep forever**: `BB_RETAIN_MONTHS` now defaults to 0 (never prune monthly unions); programs and program events are never forgotten. `history/daily` still keeps 30 days because the all-time file replaces it.
