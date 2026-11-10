#!/usr/bin/env python3
"""directsources - read bug bounty scope DIRECTLY from the platforms themselves (standard library only).

WHY THIS FILE EXISTS
    update_bb_domains.py already reads the platforms' scope through mirrors (arkadiyt/bounty-targets-data, projectdiscovery,
    diodb). This module adds the same platforms straight from their own sites: fresher than a mirror, and one
    source less that can break or stop being maintained. Rows from here go through exactly the same pipeline as
    every other source (scopeparse, merge, diffs), and "paying" always wins when two sources disagree.

WHAT EACH PLATFORM NEEDS (summary; details are in each function)
    hackerone   public GraphQL endpoint of the website (the same one arkadiyt/bounty-targets crawls), no login
    hackerone_api   (separate source "hackerone-api") official Hacker API with username + API token; the only way to
                see programs you were invited to; skipped without a token
    intigriti   with a personal access token: official researcher API. Without a token: the public endpoints of the
                website (less certain, see intigriti_public)
    yeswehack   public program API; a personal access token is optional (only needed for private programs)
    bugcrowd    public JSON endpoints used by the website itself, no login
    hackenproof public web pages (no API exists that we know of), parsed as HTML, no login

PRIVATE PROGRAMS (important)
    The authenticated APIs also list programs you were invited to. Their scope is usually under NDA. By default only
    PUBLIC programs are read. BB_INCLUDE_PRIVATE=1 includes private ones: do that only if the repository is PRIVATE.

HOW THE FUNCTIONS ARE CALLED
    Each function returns rows [(raw entry, bounty status, program name, program url)] like every src_* in
    update_bb_domains.py. `fetch` is passed in (instead of imported) so the tests can replace it with fake data.
    Signature of fetch: fetch(url, headers=None, min_bytes=100, data=None, with_headers=False) -> bytes
    (a POST when `data` is given; with_headers=True returns (bytes, response headers)); raises on HTTP errors.
    Raises:
      Skip         the source is not configured (no token): not an error, the source is just not used today
      ShapeError   the platform answered, but not in the shape we know: the message shows the start of the answer
                   so the parser can be corrected
      TimeoutError the time budget for this source ran out (a half-read platform must not look like removed hosts)

IMPORTANT HONESTY NOTE
    These parsers follow the platforms' documented / publicly observed formats. They could not be run against the
    live platforms when they were written, only against test fixtures (tests/simulate.py). If a platform changes or
    differs from the assumption, the run reports it in "Sources today" of data/stats.txt, keeps the last good copy,
    and logs the start of the unexpected answer. Fix the parser from that sample.
"""
from __future__ import annotations

import base64
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import quote, urlparse

import textscope          # entries hidden in description / instruction texts (see textscope.py)

# Shared with update_bb_domains.py (same meaning as for the arkadiyt per-platform files).
H1_APP_TYPES = {"APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "TESTFLIGHT", "OTHER_APK", "OTHER_IPA",
                "WINDOWS_APP_STORE_APP_ID", "DOWNLOADABLE_EXECUTABLES"}
H1_SKIP_TYPES = {"HARDWARE", "SMART_CONTRACT"}
OOS = "out-of-scope"     # row status of an asset the program EXCLUDES; the daily run lists these separately (data/program-out-of-scope.tsv), never as targets


class Skip(Exception):
    """The source is not configured (missing token ...). Not a failure."""


class ShapeError(RuntimeError):
    """The platform answered in a format this parser does not know."""


class Budget:
    """Wall-clock limit for one source. check() raises TimeoutError when it is used up. `name` is the source's name in
    update_bb_domains.py; it is the key under which _each() leaves its note in NOTES."""

    def __init__(self, seconds: float, name: str = ""):
        self.deadline = time.monotonic() + seconds
        self.name = name

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError("time budget for this source ran out (partial data is discarded, last good copy is used)")


# ----------------------------------------------------------------------------- small helpers
def _t(v) -> str:
    """A free text field as it is (line breaks kept: textscope reads it line by line); "" when missing / not a string."""
    return v if isinstance(v, str) else ""


def _s(v) -> str:
    """Trimmed text of a field that may be missing / null / not a string."""
    return re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else ""


def _json(fetch, url: str, headers=None):
    """GET + parse JSON. A non-JSON answer raises ShapeError that shows the start of what came back."""
    raw = fetch(url, headers=headers, min_bytes=2)
    try:
        return json.loads(raw)
    except ValueError:
        raise ShapeError(f"not JSON from {url}; starts with {raw[:200]!r}") from None


def _list(obj, key: str, url: str):
    """obj[key] must be a list, otherwise ShapeError (names the keys that are there)."""
    val = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(val, list):
        keys = sorted(obj)[:12] if isinstance(obj, dict) else type(obj).__name__
        raise ShapeError(f"expected a list under '{key}' in the answer of {url}; found {keys}")
    return val


def _pause(delay: float) -> None:
    if delay > 0:
        time.sleep(delay)


# ----------------------------------------------------------------------------- doing many requests at once
# WHY: every program of a platform needs its own request (its scope page). Done one after the other that is 300-700
# requests of 1-2 seconds each: the first real run needed 7 to 16 minutes, and HackerOne even ran out of its time budget.
# Several workers at once make the same work take a few minutes. Each worker still pauses `delay` seconds after each of
# its requests, so we stay polite; BB_DIRECT_WORKERS=1 gives the old one-at-a-time behaviour.
WORKERS = max(1, int(os.environ.get("BB_DIRECT_WORKERS", "6") or 6))

# Short notes about harmless partial problems ("3 of 210 programs skipped ..."), keyed by source name. update_bb_domains.py
# takes the note after the source finished and shows it under "Warnings" in stats.txt.
NOTES: dict = {}
# Names of sources whose note is MINOR (a handful of programs, at most 2 %, were skipped, e.g. one invitation-only brief page):
# the note is still shown in the "Sources today" table, but it does not count as a warning, so a permanent harmless
# oddity does not keep the headline at "warnings: 1" forever.
MINOR: set = set()


# CARRY[source] = program urls whose pages could NOT be read today (after the retries). The collector keeps the last good rows of
# exactly those programs, so a page that fails today does not turn all of its hosts into "removed" (see update_bb_domains.run_source).
CARRY: dict = {}


def _each(items, work, budget: Budget, what: str, delay: float, key=None) -> set:
    """Run work(item) -> iterable of rows for every item with WORKERS threads; return all rows as one set.

    One broken program must not throw away a whole platform, so a failing item (HTTP error such as a 403 for one
    program, an unexpected page shape, ...) is retried once after all others finished, and if it fails again it is
    SKIPPED and mentioned in NOTES. But if more than a quarter of the items (and more than 3) fail, or all of them, the
    problem is not one program but the platform or our parser: ShapeError, so the source counts as broken and the last good
    copy is kept. A TimeoutError (budget used up) always ends the whole source: half-read data must never look like
    removed hosts.
    """
    items = list(items)
    rows: set = set()
    if not items:
        return rows

    def one(item):
        budget.check()
        try:
            return work(item)
        finally:
            _pause(delay)

    def sweep(batch):
        failed = []
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = {pool.submit(one, it): it for it in batch}
            try:
                for fut in as_completed(futures):
                    try:
                        rows.update(fut.result())
                    except TimeoutError:
                        raise
                    except (RuntimeError, ValueError, KeyError, TypeError, AttributeError) as e:   # ShapeError is a RuntimeError
                        failed.append((futures[fut], str(e)[:160]))
            except BaseException:
                for f in futures:                                   # stop queued work (shutdown(cancel_futures=) needs Python 3.9), then re-raise
                    f.cancel()
                raise
        return failed

    bad = sweep(items)
    for wait in (3, 12):                                            # up to two more chances, with a longer pause each time (a throttled site recovers)
        if not bad:
            break
        time.sleep(wait)
        bad = sweep([it for it, _ in bad])
    if bad and (len(bad) == len(items) or (len(bad) > 3 and len(bad) * 4 > len(items))):
        raise ShapeError(f"{len(bad)} of {len(items)} {what} failed; first problem: {bad[0][1]}")
    if bad:
        if key is not None:
            CARRY[budget.name] = {k for k in (key(it) for it, _ in bad) if k}
        NOTES[budget.name] = (f"{len(bad)} of {len(items)} {what} could not be read today, their hosts from the last good run are kept ({bad[0][1]})"
                              if key is not None else f"{len(bad)} of {len(items)} {what} skipped, their hosts are missing today ({bad[0][1]})")
        if len(bad) <= max(3, len(items) // 50):
            MINOR.add(budget.name)
    return rows


# ----------------------------------------------------------------------------- HackerOne (public GraphQL, no login)
H1_SITE = "https://hackerone.com"
# These two queries are copied in shape from arkadiyt/bounty-targets (lib/bounty-targets/hackerone.rb), which has crawled
# this endpoint for years: the directory is filtered ON THE SERVER to programs that accept reports now (submission_state
# open, not sandboxed / soft_launched, not an "external program"). Without that filter the directory also lists every
# closed and invitation-only team, which is several times more programs to read: that is why our first version ran out of
# its time budget. HackerOne answers lists as `nodes` (we also accept the Relay form `edges { node }`).
_H1_DIRECTORY = ("query($after: String) { teams(first: 50, after: $after, secure_order_by: {started_accepting_at: {_direction: DESC}}, "
                 "where: { _and:[ { _or: [ {submission_state:{_eq:open}}, {external_program:{}} ]}, {_not:{external_program:{}}}, "
                 "{_or:[ {_and:[ {state:{_neq:sandboxed}}, {state:{_neq:soft_launched}} ]}, {external_program:{}} ]} ]}) "
                 "{ pageInfo { endCursor hasNextPage } nodes { handle name offers_bounties state submission_state url } } }")
_H1_SCOPE = ("query($handle: String!, $after: String) { team(handle: $handle) { structured_scopes(first: 100, after: $after, "
             "archived: false) { pageInfo { endCursor hasNextPage } nodes { asset_identifier asset_type "
             "eligible_for_bounty eligible_for_submission instruction } } } }")
# Same query without the free-text field: used automatically if HackerOne ever refuses "instruction" (the GraphQL schema is not documented).
_H1_SCOPE_PLAIN = _H1_SCOPE.replace(" instruction }", " }")


def _nodes(conn) -> list:
    """The items of a GraphQL list: `nodes: [...]` (what HackerOne sends) or Relay `edges: [{node: ...}]`."""
    if not isinstance(conn, dict):
        return []
    if isinstance(conn.get("nodes"), list):
        return conn["nodes"]
    return [e.get("node") or {} for e in conn.get("edges") or [] if isinstance(e, dict)]


def hackerone(fetch, budget: Budget, delay: float = 0.2) -> list:
    """The public GraphQL endpoint that hackerone.com itself uses for its program directory; no account needed.
    This is also how arkadiyt/bounty-targets crawls HackerOne. Steps:
      1. GET /directory/programs: the answer sets a session cookie and contains <meta name="csrf-token" content="...">;
         both must be sent with every GraphQL call.
      2. POST /graphql  teams(first, after) -> handle, name, offers_bounties, state, submission_state  (pageInfo cursor)
      3. POST /graphql  team(handle) { structured_scopes } -> asset_identifier, asset_type, eligible_for_bounty,
         eligible_for_submission  (eligible_for_submission false = out of scope, skipped)
    Programs whose submission_state is paused/disabled, or whose state is sandboxed/soft_launched, are skipped.
    An empty scope node means HackerOne timed out on that program: that program is retried and, if it still fails,
    skipped with a note (see _each); the source only fails as a whole when many programs fail. Note: HackerOne may refuse traffic from some data-centre addresses.
    """
    body, headers = fetch(f"{H1_SITE}/directory/programs", with_headers=True)
    cookies = "; ".join(c.split(";", 1)[0] for c in (headers.get_all("Set-Cookie") or [])) if hasattr(headers, "get_all") else ""
    m = re.search(rb'name="csrf-token"\s+content="([^"]+)"', body)
    if not m:
        raise ShapeError("no csrf-token on hackerone.com/directory/programs; the site layout changed or the request was blocked")
    hdr = {"Content-Type": "application/json", "Accept": "application/json", "Cookie": cookies, "X-Csrf-Token": m.group(1).decode()}

    def gql(query: str, variables: dict) -> dict:
        budget.check()
        raw = fetch(f"{H1_SITE}/graphql", headers=hdr, data=json.dumps({"query": query, "variables": variables}).encode(), min_bytes=2)
        try:
            doc = json.loads(raw)
        except ValueError:
            raise ShapeError(f"not JSON from hackerone.com/graphql; starts with {raw[:200]!r}") from None
        if not isinstance(doc, dict) or doc.get("errors") or not isinstance(doc.get("data"), dict):
            raise ShapeError(f"GraphQL error from hackerone.com/graphql: {str(doc)[:300]}")
        return doc["data"]

    teams, after = [], None
    for _ in range(400):
        conn = (gql(_H1_DIRECTORY, {"after": after}).get("teams") or {})
        teams += _nodes(conn)
        info = conn.get("pageInfo") or {}
        if not info.get("hasNextPage"):
            break
        after = info.get("endCursor")
        _pause(delay)
    if not teams:
        raise ShapeError("hackerone.com/graphql returned no programs")

    use_instruction = [True]

    def program(t) -> set:
        """All scope rows of one program (follows the scope pages of that program)."""
        rows = set()
        handle, offers = _s(t.get("handle")), bool(t.get("offers_bounties"))
        name, purl = _s(t.get("name")) or handle, f"{H1_SITE}/{handle}"
        after = None
        for _ in range(100):
            # HackerOne sometimes answers a scope page with EMPTY entries ("Some scopes timed out", arkadiyt retries
            # this too): ask the same page again a few times before giving the program up.
            for attempt in range(4):
                try:
                    team = gql(_H1_SCOPE if use_instruction[0] else _H1_SCOPE_PLAIN, {"handle": handle, "after": after}).get("team") or {}
                except ShapeError as e:
                    if use_instruction[0] and "instruction" in str(e):     # field refused: carry on without descriptions
                        use_instruction[0] = False
                        print("[!] hackerone: the 'instruction' field was refused; asset descriptions are not read", file=sys.stderr)
                        continue
                    raise
                conn = team.get("structured_scopes") or {}
                nodes = _nodes(conn)
                if all(nodes):
                    break
                _pause(2)
            else:
                raise ShapeError(f"empty scope entries for {handle} (HackerOne timed out on it)")
            for node in nodes:
                raw, typ = _s(node.get("asset_identifier")), node.get("asset_type")
                if not raw or typ in H1_SKIP_TYPES:
                    continue
                if typ in H1_APP_TYPES:
                    raw = "app:" + raw
                elif typ == "API":
                    raw = "api:" + raw                               # the platform itself calls it an API
                if node.get("eligible_for_submission") is False:     # excluded by the program: kept as an out-of-scope row
                    rows.add((raw, OOS, name, purl))
                    continue
                paying = offers and node.get("eligible_for_bounty") is not False
                st = "paying" if paying else "non-paying"
                rows.add((raw, st, name, purl))
                # the asset's own instruction text often lists more targets (and exclusions): read it too
                rows.update(textscope.rows_from_text(_t(node.get("instruction")), st, name, purl))
            info = conn.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                break
            after = info.get("endCursor")
        return rows

    live = [t for t in teams if _s(t.get("handle")) and t.get("submission_state") not in ("paused", "disabled")
            and t.get("state") not in ("sandboxed", "soft_launched")]
    rows = _each(live, program, budget, "HackerOne programs", delay, key=lambda t: f"{H1_SITE}/{_s(t.get('handle'))}")
    return sorted(rows)


# ----------------------------------------------------------------------------- HackerOne (official Hacker API, token)
H1_API = "https://api.hackerone.com/v1/hackers"


def hackerone_api(fetch, user: str, token: str, include_private: bool, budget: Budget, delay: float = 0.2) -> list:
    """GET /v1/hackers/programs (every program the account can see), then
    GET /v1/hackers/programs/<handle>/structured_scopes for each one. Basic auth: username + API token.

    Program fields read (attributes): handle, name, offers_bounties, state ("public_mode" = public).
    Scope fields read (attributes): asset_identifier, asset_type, eligible_for_bounty, eligible_for_submission
    (false = out of scope, skipped). Pagination: links.next. Rate limit of the API is generous (hundreds per minute).
    """
    if not (user and token):
        raise Skip("needs H1_USERNAME and H1_TOKEN (HackerOne -> Settings -> API Token)")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    hdr = {"Authorization": f"Basic {auth}", "Accept": "application/json"}

    programs, url = [], f"{H1_API}/programs?page%5Bsize%5D=100"
    while url:
        budget.check()
        page = _json(fetch, url, hdr)
        programs += _list(page, "data", url)
        url = (page.get("links") or {}).get("next")
        _pause(delay)

    def program(a) -> set:
        rows = set()
        handle, offers = _s(a.get("handle")), bool(a.get("offers_bounties"))
        name, purl = _s(a.get("name")) or handle, f"https://hackerone.com/{handle}"
        url = f"{H1_API}/programs/{quote(handle)}/structured_scopes?page%5Bsize%5D=100"
        while url:
            budget.check()
            page = _json(fetch, url, hdr)
            for item in _list(page, "data", url):
                at = item.get("attributes") if isinstance(item, dict) else None
                raw, typ = _s((at or {}).get("asset_identifier")), at.get("asset_type") if at else None
                if not raw or typ in H1_SKIP_TYPES:
                    continue
                if typ in H1_APP_TYPES:
                    raw = "app:" + raw
                elif typ == "API":
                    raw = "api:" + raw
                if at.get("eligible_for_submission") is False:       # excluded by the program: kept as an out-of-scope row
                    rows.add((raw, OOS, name, purl))
                    continue
                paying = offers and at.get("eligible_for_bounty") is not False
                st = "paying" if paying else "non-paying"
                rows.add((raw, st, name, purl))
                rows.update(textscope.rows_from_text(_t(at.get("instruction")), st, name, purl))
            url = (page.get("links") or {}).get("next")
        return rows

    live = []
    for p in programs:
        a = p.get("attributes") if isinstance(p, dict) else None
        if not a or not _s(a.get("handle")):
            continue
        if not include_private and a.get("state") not in (None, "public_mode"):
            continue                                             # invited / soft-launched = private
        live.append(a)
    rows = _each(live, program, budget, "HackerOne programs", delay, key=lambda a: f"https://hackerone.com/{_s(a.get('handle'))}")
    return sorted(rows)


# ----------------------------------------------------------------------------- Intigriti (official researcher API)
INTIGRITI_API = "https://api.intigriti.com/external/researcher/v1"


def intigriti(fetch, token: str, include_private: bool, budget: Budget, delay: float = 0.2) -> list:
    """GET /v1/programs?limit&offset (list), GET /v1/programs/<id> (detail with the domains). Bearer token.

    List fields: id, name, handle, status.value ("Open"), confidentialityLevel (value "Public" / id 4), maxBounty.value.
    Domains: detail["domains"]["content"] = [{type.value, endpoint, tier.value}]; when the detail only carries a
    version id, GET /v1/programs/<id>/domains/<versionId> is read instead.
    Paying: program maxBounty.value > 0 and the domain tier is not "No Bounty".
    """
    if not token:
        return intigriti_public(fetch, budget, delay)
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    records, offset = [], 0
    while True:
        budget.check()
        url = f"{INTIGRITI_API}/programs?limit=100&offset={offset}"
        page = _json(fetch, url, hdr)
        batch = _list(page, "records", url)
        records += batch
        offset += len(batch)
        if not batch or offset >= int(page.get("maxCount") or 0):
            break
        _pause(delay)

    def program(p) -> set:
        rows = set()
        pays = ((p.get("maxBounty") or {}).get("value") or 0) > 0
        name = _s(p.get("name")) or _s(p.get("handle")) or str(p["id"])
        purl = _s(((p.get("webLinks") or {}).get("detail"))) or (f"https://app.intigriti.com/researcher/programs/{p['handle']}" if p.get("handle") else "")
        detail = _json(fetch, f"{INTIGRITI_API}/programs/{quote(str(p['id']))}", hdr)
        for d in _intigriti_domains(fetch, hdr, p["id"], detail):
            raw = _s(d.get("endpoint"))
            typ = _s((d.get("type") or {}).get("value") if isinstance(d.get("type"), dict) else d.get("type")).lower()
            tier = _s((d.get("tier") or {}).get("value") if isinstance(d.get("tier"), dict) else d.get("tier")).lower()
            if not raw and not _t(d.get("description")):
                continue
            if typ in ("android", "ios"):
                raw = "app:" + raw
            # device / other / unknown types are NOT skipped any more: the name may still be a host or URL (scopeparse decides),
            # and the description of the asset (the text behind "expand asset") often holds the real list of targets.
            st = "paying" if pays and tier != "no bounty" else "non-paying"
            if tier == "out of scope":
                if raw:
                    rows.add((raw, OOS, name, purl))
                rows.update(r for r in textscope.rows_from_text(_t(d.get("description")), st, name, purl) if r[1] == OOS)
                continue
            if raw:
                rows.add((raw, st, name, purl))
            rows.update(textscope.rows_from_text(_t(d.get("description")), st, name, purl))
        return rows

    live = []
    for p in records:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        status = p.get("status") if isinstance(p.get("status"), dict) else {}
        level = p.get("confidentialityLevel") if isinstance(p.get("confidentialityLevel"), dict) else {}
        if status.get("value") and _s(status["value"]).lower() != "open":
            continue
        if not include_private and level and not (_s(level.get("value")).lower() == "public" or level.get("id") == 4):
            continue
        live.append(p)
    rows = _each(live, program, budget, "Intigriti programs", delay,
                 key=lambda p: _s(((p.get("webLinks") or {}).get("detail"))) or (f"https://app.intigriti.com/researcher/programs/{p['handle']}" if p.get("handle") else ""))
    return sorted(rows)




# The directory of the Intigriti website is an Algolia search index; the key below is the PUBLIC, search-only key that the
# website's own JavaScript sends to every visitor (arkadiyt/bounty-targets uses the same). If Intigriti rotates it the
# source warns; BB_INTIGRITI_ALGOLIA_KEY overrides it without a code change.
INTIGRITI_ALGOLIA = "https://aazuksyar4-dsn.algolia.net/1/indexes/*/queries"
_ALGOLIA_APP = "AAZUKSYAR4"
_ALGOLIA_KEY = os.environ.get("BB_INTIGRITI_ALGOLIA_KEY", "").strip() or "70d8a3400477311f27ce002ec953aeb0"
# Numbers used by the Intigriti web app (same tables as arkadiyt/bounty-targets); the position in the list is the id.
_INTI_STATUS = ["_", "wizard", "draft", "open", "suspended", "closing", "closed", "archived"]
_INTI_CONFIDENTIALITY = ["_", "inviteonly", "application", "registered", "public"]
_INTI_TYPE = ["_", "url", "android", "ios", "iprange", "device", "other", "wildcard"]
_INTI_TIER = ["", "No Bounty", "Tier 3", "Tier 2", "Tier 1", "Out of scope"]
UNKNOWN_TYPES: set = set()      # Intigriti type numbers not in _INTI_TYPE (reported by the main script, so the table can be extended)


def intigriti_public(fetch, budget: Budget, delay: float = 0.2) -> list:
    """Without a token: what the Intigriti website itself uses (same approach as arkadiyt/bounty-targets).
      1. POST the Algolia index "programs_prod" (page by page) -> programId, companyHandle, handle, name, status (number),
         confidentialityLevel (number), tacRequired, twoFactorRequired, maxBounty {value, currency}.
         Kept: status "open", confidentiality "public", and no terms-acceptance / two-factor requirement.
      2. GET app.intigriti.com/api/core/public/programs/<companyHandle>/<handle> -> assetsCollection: a list of versions
         of the scope, each {createdAt, content: {assetsAndGroups}}; the NEWEST version is the current one. An entry
         is an asset {typeId, name, bountyTierId} or a group {assets: [...]}.
    typeId 1 url / 7 wildcard / 4 iprange, 2 android / 3 ios become apps. 5 device / 6 other / unknown numbers are kept too
    (their name is tried as a host or URL), and EVERY asset's description is searched for more entries (textscope.py).
    bountyTierId 5 means "Out of scope" (skipped), 1 "No Bounty" is non-paying, tiers 2 to 4 are paying (if the program's
    maxBounty is above 0). If this breaks, set INTIGRITI_TOKEN and the official API is used instead.
    """
    programs, page_no, size = [], 0, 100
    while page_no < 200:
        budget.check()
        body = {"requests": [{"indexName": "programs_prod", "hitsPerPage": size, "page": page_no, "query": ""}]}
        raw = fetch(f"{INTIGRITI_ALGOLIA}?x-algolia-api-key={_ALGOLIA_KEY}&x-algolia-application-id={_ALGOLIA_APP}",
                    headers={"Referer": "https://www.intigriti.com/", "Content-Type": "application/json", "Accept": "application/json"},
                    data=json.dumps(body).encode(), min_bytes=2)
        try:
            doc = json.loads(raw)
            hits = doc["results"][0]["hits"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ShapeError(f"unexpected Algolia answer for the Intigriti directory; starts with {raw[:200]!r}") from None
        programs += [h for h in hits if isinstance(h, dict)]
        page_no += 1
        if len(hits) < size:
            break
        _pause(delay)

    def pick(table, i):
        return table[i] if isinstance(i, int) and 0 <= i < len(table) else ""

    live = [h for h in programs
            if h.get("handle") and h.get("companyHandle") and pick(_INTI_STATUS, h.get("status")) == "open"
            and pick(_INTI_CONFIDENTIALITY, h.get("confidentialityLevel")) == "public"
            and not h.get("tacRequired") and not h.get("twoFactorRequired")]
    if programs and not live:
        raise ShapeError("Intigriti directory has programs but none is open and public; the numbering may have changed")

    def program(h) -> set:
        rows = set()
        url = f"https://app.intigriti.com/api/core/public/programs/{quote(str(h['companyHandle']), safe='')}/{quote(str(h['handle']), safe='')}"
        detail = _json(fetch, url, {"Accept": "application/json"})
        versions = detail.get("assetsCollection") if isinstance(detail, dict) else None
        if not isinstance(versions, list):
            raise ShapeError(f"no assetsCollection in the Intigriti program answer; starts with {str(detail)[:200]!r}")
        versions = [v for v in versions if isinstance(v, dict)]
        newest = max(versions, key=lambda v: v.get("createdAt") or 0) if versions else {}
        entries = ((newest.get("content") or {}).get("assetsAndGroups")) or []
        assets = []
        for e in entries:
            if isinstance(e, dict):
                assets += [a for a in e["assets"] if isinstance(a, dict)] if isinstance(e.get("assets"), list) else [e]
        mb = h.get("maxBounty") if isinstance(h.get("maxBounty"), dict) else {}
        pays_at_all = (mb.get("value") or 0) > 0
        name = _s(h.get("name")) or str(h["handle"])
        purl = f"https://app.intigriti.com/programs/{h['companyHandle']}/{h['handle']}/detail"
        for a in assets:
            raw, typ, tier = _s(a.get("name")), pick(_INTI_TYPE, a.get("typeId")), pick(_INTI_TIER, a.get("bountyTierId"))
            desc = _t(a.get("description"))
            if not raw and not desc:
                continue
            if not typ:                                          # a type number we do not know: keep going, and say so once
                UNKNOWN_TYPES.add(a.get("typeId"))
            if typ in ("android", "ios") and raw:
                raw = "app:" + raw
            st = "paying" if pays_at_all and tier in ("Tier 1", "Tier 2", "Tier 3") else "non-paying"
            if tier == "Out of scope":                           # excluded by the program: kept as an out-of-scope row
                if raw:
                    rows.add((raw, OOS, name, purl))
                rows.update(r for r in textscope.rows_from_text(desc, st, name, purl) if r[1] == OOS)
                continue
            # NOT skipped any more: types device / other / unknown. The name may still be a host or URL (scopeparse decides),
            # and the description (the text behind "expand asset" on the program page) often lists the real targets: Yahoo's
            # "*.yahoo.com"-style assets carry hundreds of hosts, URL paths and API endpoints only there.
            if raw:
                rows.add((raw, st, name, purl))
            rows.update(textscope.rows_from_text(desc, st, name, purl))
        return rows

    return sorted(_each(live, program, budget, "Intigriti programs", delay,
                        key=lambda h: f"https://app.intigriti.com/programs/{h['companyHandle']}/{h['handle']}/detail"))


def _intigriti_domains(fetch, hdr, program_id, detail) -> list:
    """The domain entries of one Intigriti program detail answer (several shapes are accepted)."""
    dom = detail.get("domains") if isinstance(detail, dict) else None
    if isinstance(dom, list):
        return [d for d in dom if isinstance(d, dict)]
    if isinstance(dom, dict):
        content = dom.get("content")
        if isinstance(content, list):
            return [d for d in content if isinstance(d, dict)]
        if dom.get("id"):                                        # only a version id: fetch that version
            doc = _json(fetch, f"{INTIGRITI_API}/programs/{quote(str(program_id))}/domains/{quote(str(dom['id']))}", hdr)
            items = doc.get("content") if isinstance(doc, dict) else doc
            return [d for d in (items or []) if isinstance(d, dict)]
    if isinstance(detail, dict) and detail.get("id"):
        return []                                                # a program without domains is legal
    raise ShapeError(f"unexpected Intigriti program detail; starts with {str(detail)[:200]!r}")


# ----------------------------------------------------------------------------- YesWeHack (public API, token optional)
YWH_API = "https://api.yeswehack.com"


def yeswehack(fetch, token: str, include_private: bool, budget: Budget, delay: float = 0.2) -> list:
    """GET /programs?page=N (list, public) and GET /programs/<slug> (detail with scopes). Bearer token optional.

    List fields: items[].slug, title, public, disabled, bounty; pagination.nb_pages.
    Detail fields: scopes[].scope (the target text), scope_type ("web-application", "api", "mobile-application-ios", ...).
    Paying: program "bounty" is true (or a max reward above 0).
    """
    hdr = {"Accept": "application/json"}
    if token:
        hdr["Authorization"] = f"Bearer {token}"

    items, page_no, pages = [], 1, 1
    while page_no <= pages and page_no <= 100:
        budget.check()
        url = f"{YWH_API}/programs?page={page_no}"
        page = _json(fetch, url, hdr)
        items += _list(page, "items", url)
        pages = int((page.get("pagination") or {}).get("nb_pages") or 1)
        page_no += 1
        _pause(delay)

    def program(p) -> set:
        rows = set()
        url = f"{YWH_API}/programs/{quote(str(p['slug']))}"
        detail = _json(fetch, url, hdr)
        scopes = _list(detail, "scopes", url)
        pays = bool(detail.get("bounty", p.get("bounty"))) or (detail.get("bounty_reward_max") or 0) > 0
        name = _s(detail.get("title")) or _s(p.get("title")) or str(p["slug"])
        purl = f"https://yeswehack.com/programs/{p['slug']}"
        for s in scopes:
            raw = _s(s.get("scope")) if isinstance(s, dict) else ""
            typ = _s(s.get("scope_type")).lower() if isinstance(s, dict) else ""
            if not isinstance(s, dict) or not raw or typ in ("hardware", "iot"):
                continue
            if typ.startswith("mobile"):
                raw = "app:" + raw
            elif typ == "api":
                raw = "api:" + raw                          # the platform calls this scope an API
            rows.add((raw, "paying" if pays else "non-paying", name, purl))
            # an optional description of the scope entry may list more targets (field names are assumptions, harmless if absent)
            for key in ("description", "scope_description", "asset_description"):
                rows.update(textscope.rows_from_text(_t(s.get(key)), "paying" if pays else "non-paying", name, purl))
        oos = detail.get("out_of_scope")                    # the program's exclusions: strings or {scope: ...} records (shape not verified live)
        for s in (oos if isinstance(oos, list) else []):
            raw = _s(s.get("scope")) if isinstance(s, dict) else _s(s)
            if raw:
                rows.add((raw, OOS, name, purl))
        return rows

    live = [p for p in items if isinstance(p, dict) and p.get("slug") and not p.get("disabled")
            and not (p.get("public") is False and not include_private)]
    rows = _each(live, program, budget, "YesWeHack programs", delay, key=lambda p: f"https://yeswehack.com/programs/{p['slug']}")
    return sorted(rows)


# ----------------------------------------------------------------------------- Bugcrowd (public JSON used by the site)
BUGCROWD = "https://bugcrowd.com"


class _BriefFinder(HTMLParser):
    """Finds the element that carries the scope document path:
        <div data-react-class="ResearcherEngagementBrief" data-api-endpoints="{...json...}">   (today; what arkadiyt reads)
    The older spelling class="react-component-researcher-engagement-brief" is still accepted. Our first version knew only
    the old class name, which is why every one of the 518 Bugcrowd pages failed in the real run."""

    def __init__(self):
        super().__init__()
        self.endpoints = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        known = a.get("data-react-class") == "ResearcherEngagementBrief" or "react-component-researcher-engagement-brief" in (a.get("class") or "").split()
        if known and a.get("data-api-endpoints"):
            self.endpoints = a["data-api-endpoints"]


def bugcrowd(fetch, budget: Budget, delay: float = 0.4) -> list:
    """Three steps, all without login (this is what the website itself does):
      1. GET /engagements.json?category=<c>&sort_by=promoted&sort_direction=desc&page=N
             -> engagements[].briefUrl, paginationMeta.{totalCount, limit}.  c = bug_bounty (paying), vdp (non-paying)
      2. GET <briefUrl> (HTML) -> the attribute data-api-endpoints of the "engagement brief" element is JSON whose
             engagementBriefApi.getBriefVersionDocument is the path of the scope document
      3. GET <that path>.json -> data.scope[] = groups {inScope, targets[{name, uri, ipAddress, category}]}
    There is no per-target bounty flag: the engagement category decides (bug_bounty = paying, vdp = non-paying).
    The vdp category is optional: if the site rejects it only that part is skipped.
    """
    todo, seen = [], set()           # engagements still to read: (brief url, name, paying?)
    for category, pays in (("bug_bounty", True), ("vdp", False)):
        briefs, page_no, pages = [], 1, 1
        while page_no <= pages and page_no <= 200:
            budget.check()
            url = f"{BUGCROWD}/engagements.json?category={category}&sort_by=promoted&sort_direction=desc&page={page_no}"
            try:
                page = _json(fetch, url)
                engagements = _list(page, "engagements", url)
            except (ShapeError, RuntimeError):
                if category == "bug_bounty":
                    raise                                      # the main listing must work
                break                                          # the optional vdp listing may not
            meta = page.get("paginationMeta") or {}
            limit = int(meta.get("limit") or len(engagements) or 1)
            pages = math.ceil(int(meta.get("totalCount") or len(engagements)) / limit)
            briefs += [(e.get("briefUrl"), _s(e.get("name"))) for e in engagements if isinstance(e, dict) and e.get("briefUrl")]
            page_no += 1
            _pause(delay)
        todo += [(u, n, pays) for u, n in briefs if not (u in seen or seen.add(u))]

    def program(item) -> set:
        """One engagement: brief page -> scope document path -> scope document."""
        brief_url, name, pays = item
        rows = set()
        purl = BUGCROWD + brief_url
        finder = _BriefFinder()
        try:
            html = fetch(purl, min_bytes=100).decode("utf-8", "replace")
        except RuntimeError as e:
            if "HTTP 403" in str(e) or "HTTP 404" in str(e):      # invitation-only / gone: arkadiyt skips these silently too
                return rows
            raise
        finder.feed(html)
        if not finder.endpoints:
            raise ShapeError(f"no engagement-brief element in {purl}; the page layout changed")
        try:
            path = json.loads(finder.endpoints)["engagementBriefApi"]["getBriefVersionDocument"]
        except (ValueError, KeyError, TypeError):
            raise ShapeError(f"unexpected data-api-endpoints in {purl}: {finder.endpoints[:200]!r}") from None
        doc = _json(fetch, BUGCROWD + path + ".json")
        groups = (doc.get("data") or {}).get("scope") if isinstance(doc, dict) else None
        if not isinstance(groups, list):
            raise ShapeError(f"unexpected scope document for {purl}; starts with {str(doc)[:200]!r}")
        # arkadiyt/bounty-targets decides "paying" from the reward table: rewardRangeData["1"]["max"] of any in-scope
        # group above 0 means the program pays. We use that as well, because a "bug_bounty" engagement can pay nothing
        # (and a VDP never shows a reward). Without any reward data the category (bug_bounty / vdp) decides, as before.
        def reward(g) -> float:
            try:
                return float(((g.get("rewardRangeData") or {}).get("1") or {}).get("max") or 0)
            except (TypeError, ValueError, AttributeError):
                return 0.0
        in_groups = [g for g in groups if isinstance(g, dict) and g.get("inScope")]
        if any(reward(g) > 0 for g in in_groups):
            pays = True
        elif any(isinstance(g.get("rewardRangeData"), dict) and g["rewardRangeData"] for g in in_groups):
            pays = False                    # the table is there and every maximum is 0: nothing is paid
        pname = name or brief_url.strip("/").split("/")[-1]
        st = "paying" if pays else "non-paying"

        def target_values(t) -> list:
            """Every field of a target that can hold an address: name, uri and ipAddress are all read (the first version read
            only the first one that was filled in, so a target named "Main site" with uri "www.x.com" was lost)."""
            vals = []
            for key in ("name", "uri", "ipAddress"):
                v = _s(t.get(key))
                if v and v not in vals and (key == "name" or not re.search(r"\s", v)):
                    vals.append(v)
            return vals

        for g in in_groups:
            # the group's own description (markdown) can list targets and exclusions too
            rows.update(textscope.rows_from_text(_t(g.get("description")), st, pname, purl))
            for t in g.get("targets") or []:
                if not isinstance(t, dict):
                    continue
                cat = _s(t.get("category")).lower()
                if cat in ("hardware", "iot"):
                    continue
                for raw in target_values(t):
                    tag = "app:" if cat in ("android", "ios") else ("api:" if cat == "api" else "")
                    rows.add((tag + raw, st, pname, purl))
                rows.update(textscope.rows_from_text(_t(t.get("description")), st, pname, purl))
        for g in groups:                                    # groups the program marks inScope: false = its exclusions
            if not isinstance(g, dict) or g.get("inScope"):
                continue
            for t in g.get("targets") or []:
                if not isinstance(t, dict):
                    continue
                if _s(t.get("category")).lower() not in ("hardware", "iot"):
                    for raw in target_values(t):
                        rows.add((raw, OOS, pname, purl))
        return rows

    # A brief page without the scope element (a program that is closed, invitation-only, or has a different layout, for
    # example the one that stopped the first real run) is skipped by _each; only many failures fail the source.
    rows = _each(todo, program, budget, "Bugcrowd engagements", delay, key=lambda it: BUGCROWD + it[0])
    return sorted(rows)


# ----------------------------------------------------------------------------- HackenProof (HTML pages, no API known)
HACKENPROOF = "https://hackenproof.com"


class _Links(HTMLParser):
    """All href values of a page."""

    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


class _Rows(HTMLParser):
    """Flattens a page into table rows + loose text: rows = [[cell text nodes...], ...], text = all text nodes."""

    def __init__(self):
        super().__init__()
        self.rows, self.text, self._row, self._cell = [], [], None, None
        self.row_mode = []                 # which heading ("in" / "out") was last seen when each row started
        self._mode = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._row = []
            self.row_mode.append(self._mode)
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
            self._row.append(self._cell)

    def handle_endtag(self, tag):
        if tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = self._cell = None
        elif tag in ("td", "th"):
            self._cell = None

    def handle_data(self, data):
        t = " ".join(data.split())
        if not t:
            return
        self.text.append(t)
        if self._cell is not None:
            self._cell.append(t)
        elif t.lower() == "in scope":
            self._mode = "in"
        elif t.lower() == "out of scope":
            self._mode = "out"


def _hackenproof_json(fetch, budget: Budget, delay: float) -> list:
    """The JSON the HackenProof website itself loads (arkadiyt/bounty-targets used it until it needed a partner key):
      /bug-bounty-programs-list?page=N      -> programs[] {slug, title, state, max_bounty}, next_page (null at the end)
      /bug-bounty-programs-list/<slug>      -> scopes[] {target, title (type), out_of_scope, reward_type}
    Much faster than reading HTML. If the site refuses it (a partner key may be required: set HACKENPROOF to it) or answers
    something else, the caller falls back to the HTML pages."""
    hdr = {"Accept": "application/json"}
    if os.environ.get("HACKENPROOF"):
        hdr["hp-partners-bypass"] = os.environ["HACKENPROOF"]
    programs, page_no = [], 1
    while page_no < 100:
        budget.check()
        doc = _json(fetch, f"{HACKENPROOF}/bug-bounty-programs-list?page={page_no}", hdr)
        programs += [p for p in _list(doc, "programs", "hackenproof program list") if isinstance(p, dict)]
        if not doc.get("next_page"):
            break
        page_no += 1
        _pause(delay)
    live = [p for p in programs if p.get("slug") and p.get("state") != "archived" and not p.get("private")]
    if not live:
        raise ShapeError("HackenProof JSON list has no active programs")

    def program(p) -> set:
        rows, slug = set(), p["slug"]
        purl, name = f"{HACKENPROOF}/programs/{slug}", _s(p.get("title")) or slug
        doc = _json(fetch, f"{HACKENPROOF}/bug-bounty-programs-list/{quote(slug)}", hdr)
        for sc in _list(doc, "scopes", slug):
            if not isinstance(sc, dict):
                continue
            raw, typ = _s(sc.get("target")), _s(sc.get("title")).lower()
            if not raw or any(w in typ for w in ("smart contract", "blockchain", "hardware", "contract")):
                continue
            if any(w in typ for w in ("mobile", "android", "ios")):
                raw = "app:" + raw
            elif re.search(r"\bapi\b", typ):
                raw = "api:" + raw
            desc = _t(sc.get("target_description")) or _t(sc.get("description"))     # free text of the target: may list more targets
            if sc.get("out_of_scope"):
                rows.add((raw, OOS, name, purl))
                rows.update(r for r in textscope.rows_from_text(desc, "unknown", name, purl) if r[1] == OOS)
                continue
            st = "paying" if _s(sc.get("reward_type")).lower() == "bounty" else "unknown"
            rows.add((raw, st, name, purl))
            rows.update(textscope.rows_from_text(desc, st, name, purl))
        return rows

    return sorted(_each(live, program, budget, "HackenProof programs", delay, key=lambda p: f"{HACKENPROOF}/programs/{p.get('slug')}"))


def hackenproof(fetch, budget: Budget, delay: float = 0.5) -> list:
    """First the JSON the site uses (_hackenproof_json: fast); when that is refused or in an unknown shape, the HTML pages.
    HackenProof has no documented public API, so the public web pages can be read (the fallback):
      1. /programs?page=N lists programs (links of the form /programs/<slug>)
      2. /programs/<slug> has a scope table: columns Target | Type | Severity. A row with severity "None" belongs to the
         out-of-scope table and is skipped (a row without a severity column uses the nearest "In scope"/"Out of scope"
         heading instead). Smart contract / hardware targets are skipped; mobile types get the "app:" prefix.
    Bounty: "Up to: $N" on the program page with N > 0 -> paying; otherwise "unknown".
    HTML is fragile: if the layout changes, the run reports it and keeps the last good copy.
    """
    try:
        return _hackenproof_json(fetch, budget, delay)
    except (RuntimeError, ValueError, KeyError, TypeError):          # quietly use the HTML pages; TimeoutError (budget) is not caught here
        pass
    slugs, page_no = [], 1
    while page_no <= 30:
        budget.check()
        url = f"{HACKENPROOF}/programs?page={page_no}"
        links = _Links()
        links.feed(fetch(url, min_bytes=100).decode("utf-8", "replace"))
        found = []
        for h in links.hrefs:
            u = urlparse(h)
            if u.netloc and re.sub(r"^www\.", "", u.netloc.lower()) != "hackenproof.com":
                continue
            m = re.fullmatch(r"/programs/([A-Za-z0-9][A-Za-z0-9_.-]*)/?", u.path)
            if m and m.group(1) not in slugs and m.group(1) not in found:
                found.append(m.group(1))
        if not found:
            break
        slugs += found
        page_no += 1
        _pause(delay)
    if not slugs:
        raise ShapeError("no program links found on hackenproof.com/programs; the page layout changed")

    def program(slug) -> set:
        rows = set()
        purl = f"{HACKENPROOF}/programs/{slug}"
        page = _Rows()
        page.feed(fetch(purl, min_bytes=100).decode("utf-8", "replace"))
        blob = " ".join(page.text)
        m = re.search(r"Up to:?\s*\$\s*([\d][\d,.]*)", blob, re.I)
        amount = float(m.group(1).replace(",", "").rstrip(".") or 0) if m else 0
        status = "paying" if amount > 0 else "unknown"
        for r, mode in zip(page.rows, page.row_mode):
            cells = [[x for x in c if x.lower() != "copy"] for c in r]
            if len(cells) < 2 or not cells[0] or cells[0][0].lower() == "target":
                continue
            severity = " ".join(cells[2]).lower() if len(cells) > 2 else None
            excluded = severity == "none" or (severity is None and mode == "out")
            raw, typ = cells[0][0], " ".join(cells[1]).lower()
            if any(w in typ for w in ("smart contract", "blockchain", "hardware", "contract")):
                continue
            if any(w in typ for w in ("mobile", "android", "ios")):
                raw = "app:" + raw
            rows.add((raw, OOS if excluded else status, slug, purl))
        return rows

    rows = _each(slugs, program, budget, "HackenProof programs", delay, key=lambda slug: f"{HACKENPROOF}/programs/{slug}")
    return sorted(rows)
