#!/usr/bin/env python3
"""Offline simulation of several days of the daily run (no network). Run:  python3 tests/simulate.py

How it works: the script is run in a temporary project folder (BB_ROOT) with BB_DATE set to a chosen day, and
update_bb_domains.fetch() is replaced by fake_fetch(), which serves the fixture text below (BASE = a normal day,
`cfg` = what each fake source returns today). Between runs the fixtures are changed to create situations:
new / removed hosts, a source that is down, a source that collapses, a skipped day, a re-run, a baseline run,
projectdiscovery JSON broken (YAML fallback), pruning of old history. After each run `check(label, condition)` prints PASS/FAIL.
Exit code 1 if any check fails. Add a check here whenever you change behaviour."""
import importlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
TMP = Path(tempfile.mkdtemp(prefix="bbsim_"))
(TMP / "config").mkdir()
shutil.copy(REPO / "config" / "public_suffix_list.dat", TMP / "config")
shutil.copy(REPO / "config" / "denylist.txt", TMP / "config")
os.environ["BB_ROOT"] = str(TMP)
os.environ.pop("GITHUB_STEP_SUMMARY", None)
# credentials for the direct platform sources (fake values; fake_fetch checks that they are sent)
os.environ.update({"H1_USERNAME": "tester", "H1_TOKEN": "h1-secret", "INTIGRITI_TOKEN": "inti-secret", "BB_DIRECT_DELAY": "0", "BB_STALE_DAYS": "0"})
os.environ.pop("YWH_TOKEN", None)
os.environ.pop("BB_INCLUDE_PRIVATE", None)
os.environ.pop("BB_DIRECT_STRICT", None)

ARK = ["transunion.co.br", "co.nl", "vdp.bc-example.com", "data-api.coindesk.com", "a.example.com", "example.com", "www.bbc.co.uk", "co.uk", "10.0.0.1", "34.120.0.9", "1.2.3.0/24", "api-*.pattern-example.com", "8x8hosts.internal", "Swiss Center (NCSC.ch)", "security@mail.example.com", "http//scheme.example.com", "(*.)wild.example.org", "App.Example.com (main app)", "page.html",
       "com.example.myapp", "Shop.Example.ORG", "bücher.de", "http://api.vdp-only.io:8443/x"]
BASE = {
    "arkadiyt": "\n".join(ARK) + "\n" + "\n".join(f"filler{i}.example.net" for i in range(20)),
    "arkadiyt-wildcard": "corp.example.com\n*.tenant.co.uk\nbigco.com\n",
    "chaos": json.dumps({"programs": [
        {"name": "p1", "bounty": True, "domains": ["paid.example.org", "api.paid.example.org"] + [f"c{i}.paid.example.org" for i in range(20)]},
        {"name": "p2", "bounty": False, "domains": ["vdp.example.org"]},
        {"name": "p3-no-flag", "domains": ["nokey.example.org"]}]}),
    "diodb": json.dumps([
        {"program_name": "x", "policy_url": "https://accenture.responsibledisclosure.com/hc/en-us", "offers_bounty": "no"},
        {"program_name": "y", "policy_url": "https://www.company.com.au/security", "offers_bounty": "yes"},
        {"program_name": "z", "policy_url": "https://hackerone.com/z", "offers_bounty": "yes"}]),
    "immunefi": json.dumps([{"assets": [{"url": "https://app.defi.xyz"}, {"url": "https://etherscan.io/address/0x1"},
                                         {"url": "https://github.com/defi-org/contracts/blob/main/a.sol"}],
                              "websiteUrl": "https://defi.xyz", "githubUrl": "https://github.com/defi"}]),
}

# Platform files in the shapes of the real arkadiyt files (samples from the user)
BASE["hackerone"] = json.dumps([
    {"handle": "verisk_vdp", "offers_bounties": False, "targets": {"in_scope": [
        {"asset_identifier": "*.verisk-vdp.com", "asset_type": "WILDCARD", "eligible_for_bounty": False}], "out_of_scope": []}},
    {"handle": "omarchy", "name": "Omarchy Program", "url": "https://hackerone.com/omarchy", "offers_bounties": True, "targets": {"in_scope": [
        {"asset_identifier": "AS16314", "asset_type": "OTHER", "eligible_for_bounty": True},
        {"asset_identifier": "AS6720 1/2", "asset_type": "OTHER", "eligible_for_bounty": True},
        {"asset_identifier": "https://github.com/omacom/omarchy", "asset_type": "SOURCE_CODE", "eligible_for_bounty": True},
        {"asset_identifier": "https://github.com/OmaCom/Omarchy-Docs.git", "asset_type": "SOURCE_CODE", "eligible_for_bounty": True},
        {"asset_identifier": "https://gitlab.com/x/y", "asset_type": "SOURCE_CODE", "eligible_for_bounty": True},
        {"asset_identifier": "https://github.com/about", "asset_type": "OTHER", "eligible_for_bounty": True},
        {"asset_identifier": "*.h1paid.com", "asset_type": "WILDCARD", "eligible_for_bounty": True},
        {"asset_identifier": "noeligible.h1paid.com", "asset_type": "URL", "eligible_for_bounty": False},
        {"asset_identifier": "https://apps.apple.com/br/app/clear/id6447694643", "asset_type": "APPLE_STORE_APP_ID", "eligible_for_bounty": True}],
        "out_of_scope": [{"asset_identifier": "oos.h1paid.com", "asset_type": "URL"}]}}])
BASE["intigriti"] = json.dumps([
    {"handle": "adac", "max_bounty": {"value": 0, "currency": "EUR"}, "targets": {"in_scope": [
        {"type": "url", "endpoint": "www.adac-vdp.de/mein", "impact": "No Bounty"},
        {"type": "iprange", "endpoint": "193.30.38.0/24", "impact": "No Bounty"}], "out_of_scope": []}},
    {"handle": "aikido", "max_bounty": {"value": 2500, "currency": "EUR"}, "targets": {
        "in_scope": [{"type": "url", "endpoint": "app.aikido.dev", "impact": "Tier 2"},
                     {"type": "url", "endpoint": "nobounty.aikido.dev", "impact": "No Bounty"},
                     {"type": "url", "endpoint": "all", "impact": "Tier 2"}],
        "out_of_scope": [{"type": "wildcard", "endpoint": "*.oosaikido.dev", "impact": "Out of scope"}]}}])
BASE["yeswehack"] = json.dumps([
    {"id": "atg", "name": "ATG", "url": "https://yeswehack.com/programs/atg", "max_bounty": 4000, "targets": {"in_scope": [
        {"target": "*.atg.se", "type": "other"}, {"target": "www.atg.se", "type": "web-application"},
        {"target": "https://apps.apple.com/se/app/atg/id1434660322", "type": "mobile-application-ios"},
        {"target": "Any resource created or accessed with the Cloud on eu-west-2", "type": "other"},
        {"target": "https://github.com/ywh-org", "type": "source-code"}],
        "out_of_scope": [{"target": "shop.atg.se (external supplier)", "type": "other"}]}},
    {"id": "outscale", "max_bounty": 0, "targets": {"in_scope": [{"target": "https://vdp.ywh-example.com/", "type": "api"}], "out_of_scope": []}}])
BASE["bugcrowd"] = json.dumps([
    {"name": "CoinDesk", "max_payout": 7500, "targets": {"in_scope": [
        {"type": "api", "target": "http://data-api.coindesk.com/", "uri": "http://data-api.coindesk.com/", "ipAddress": ""},
        {"type": "website", "target": "https://marketplace.atlassian.com/apps/1218391/x?hosting=cloud", "ipAddress": None},
        {"type": "network", "target": "", "ipAddress": "34.120.0.77"},
        {"type": "code", "target": "https://github.com/bc-org/bc-repo", "ipAddress": ""}], "out_of_scope": [
        {"type": "website", "target": "https://www.coindesk.com/"}]}},
    {"name": "VDP", "max_payout": 0, "targets": {"in_scope": [{"type": "website", "target": "https://vdp.bc-example.com", "ipAddress": ""}], "out_of_scope": []}}])
cfg = {k: v for k, v in BASE.items()}
broken = set()


def to_yaml(chaos_json: str) -> str:
    """Same data in the layout of src/data.yaml (inline [] for empty lists, list items under domains:)."""
    out = ["programs:"]
    for p in json.loads(chaos_json)["programs"]:
        out += [f"  - name: {p['name']}", f"    url: https://example.com/{p['name']}"]
        if "bounty" in p:
            out.append(f"    bounty: {str(p['bounty']).lower()}")
        out.append("    swag: true  # comment")
        if p["domains"]:
            out += ["    domains:"] + [f"      - {d}" for d in p["domains"]]
        else:
            out.append("    domains: []")
    return "\n".join(out) + "\n"



# ---------------------------------------------------------------------------- direct platform fixtures
# Shapes follow what the platforms document / what their sites serve. They were NOT checked against the live
# platforms (no network in the sandbox this was written in); they only prove that our parsers do what they claim.
PAD = " " * 120


def _j(obj) -> bytes:
    return json.dumps(obj).encode()


def direct_fixture(url: str, headers: dict, data=None):
    """Fake answers of the five direct platform sources. Returns bytes, or None when `url` is not one of theirs."""
    if url == "https://hackerone.com/directory/programs":
        return f'<html><head><meta name="csrf-token" content="csrf-xyz"/></head><body>{PAD}</body></html>'.encode()
    if url == "https://hackerone.com/graphql":
        assert headers.get("X-Csrf-Token") == "csrf-xyz" and "_h1_session=abc" in headers.get("Cookie", ""), "GraphQL call without csrf token / cookie"
        query = json.loads(data)["query"]
        if "teams(" in query:
            assert "submission_state:{_eq:open}" in query, "directory query without the server-side filter on open programs"
            return _j({"data": {"teams": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [      # `nodes` like the real answer
                {"handle": "dirpub", "name": "Direct Public", "offers_bounties": True, "state": "public_mode", "submission_state": "open", "url": "https://hackerone.com/dirpub"},
                {"handle": "dirpriv", "name": "Private Co", "offers_bounties": True, "state": "soft_launched", "submission_state": "open"},
                {"handle": "dirpaused", "name": "Paused Co", "offers_bounties": True, "state": "public_mode", "submission_state": "paused"}]}}})
        assert '"handle": "dirpub"' in data.decode() or "dirpub" in data.decode(), "scope query for an unexpected program"
        return _j({"data": {"team": {"structured_scopes": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": [
            {"node": {"asset_identifier": "gql-h1.example.com", "asset_type": "URL", "eligible_for_bounty": True, "eligible_for_submission": True,
                      "instruction": "Targets:\n* instr-h1.example.com\n* https://instr-h1.example.com/v2/\nNot in scope:\n* instr-oos.example.com"}},
            {"node": {"asset_identifier": "gql-oos.example.com", "asset_type": "URL", "eligible_for_bounty": False, "eligible_for_submission": False}},
            {"node": {"asset_identifier": "com.gql.h1app", "asset_type": "GOOGLE_PLAY_APP_ID", "eligible_for_bounty": True, "eligible_for_submission": True}}]}}}})
    if url.startswith("https://aazuksyar4-dsn.algolia.net/1/indexes/*/queries"):
        assert headers.get("Referer") == "https://www.intigriti.com/" and "x-algolia-application-id=AAZUKSYAR4" in url, "Algolia call without Referer / app id"
        return _j({"results": [{"hits": [
            {"programId": "a1", "companyHandle": "co", "handle": "pubprog", "name": "Public Inti", "status": 3, "confidentialityLevel": 4, "tacRequired": False, "twoFactorRequired": False, "maxBounty": {"value": 500, "currency": "EUR"}},
            {"programId": "a2", "companyHandle": "co", "handle": "closed", "name": "Closed Inti", "status": 6, "confidentialityLevel": 4, "maxBounty": {"value": 500}},
            {"programId": "a3", "companyHandle": "co", "handle": "invite", "name": "Invite Inti", "status": 3, "confidentialityLevel": 1, "maxBounty": {"value": 500}},
            {"programId": "a4", "companyHandle": "co", "handle": "tac", "name": "Tac Inti", "status": 3, "confidentialityLevel": 4, "tacRequired": True, "maxBounty": {"value": 500}}]}]})
    if url == "https://app.intigriti.com/api/core/public/programs/co/pubprog":
        return _j({"assetsCollection": [
            {"createdAt": 100, "content": {"assetsAndGroups": [{"typeId": 1, "name": "old-version-inti.example.com", "bountyTierId": 4}]}},
            {"createdAt": 200, "content": {"assetsAndGroups": [
                {"typeId": 1, "name": "pubinti.example.com", "bountyTierId": 4},
                {"assets": [{"typeId": 1, "name": "pubinti-nobounty.example.com", "bountyTierId": 1},
                            {"typeId": 7, "name": "*.pubinti-wild.example.com", "bountyTierId": 3},
                            {"typeId": 2, "name": "com.pubinti.app", "bountyTierId": 4}]},
                {"typeId": 1, "name": "pubinti-oos.example.com", "bountyTierId": 5},
                {"typeId": 5, "name": "pubinti-device", "bountyTierId": 4},
                # Yahoo style: a broad asset whose DESCRIPTION ("expand asset" on the program page) holds the real list
                {"typeId": 7, "name": "*.yahoo-demo.example.com", "bountyTierId": 4, "description":
                 "<p>In scope:</p><ul><li>tw.bid.yahoo-demo.example.com/api/</li><li>https://tw.ews.mall.yahooapis.example.com/</li>"
                 "<li>/apis</li></ul>"
                 "<p>You may also try guess.yahoo-demo.example.net if you find a link to it. See https://hackerone.com/x.</p>"
                 "<p>Out of scope:</p><ul><li>legacy.yahoo-demo.example.com</li></ul>"},
                # type "other" is no longer skipped: its name is a host here
                {"typeId": 6, "name": "other-type.yahoo-demo.example.com", "bountyTierId": 3}]}}]})
    if url.startswith("https://hackenproof.com/bug-bounty-programs-list"):
        raise RuntimeError("simulated 403: JSON endpoint needs a partner key")     # the HTML pages are used instead
    if "api.hackerone.com" in url:
        assert headers.get("Authorization", "").startswith("Basic "), "H1 call without basic auth"
        if "/structured_scopes" in url:
            if "/dirpub/" in url:
                return _j({"data": [
                    {"attributes": {"asset_identifier": "direct-h1.example.com", "asset_type": "URL", "eligible_for_bounty": True, "eligible_for_submission": True}},
                    {"attributes": {"asset_identifier": "oos-h1.example.com", "asset_type": "URL", "eligible_for_bounty": False, "eligible_for_submission": False}},
                    {"attributes": {"asset_identifier": "nobounty-h1.example.com", "asset_type": "URL", "eligible_for_bounty": False, "eligible_for_submission": True}},
                    {"attributes": {"asset_identifier": "com.direct.h1app", "asset_type": "GOOGLE_PLAY_APP_ID", "eligible_for_bounty": True, "eligible_for_submission": True}}], "links": {}})
            return _j({"data": [{"attributes": {"asset_identifier": "private-h1.example.com", "asset_type": "URL", "eligible_for_bounty": True, "eligible_for_submission": True}}], "links": {}})
        return _j({"data": [
            {"id": "1", "type": "program", "attributes": {"handle": "dirpub", "name": "Direct Public", "offers_bounties": True, "state": "public_mode"}},
            {"id": "2", "type": "program", "attributes": {"handle": "dirpriv", "name": "Private Co", "offers_bounties": True, "state": "soft_launched"}}], "links": {}})
    if "bugcrowd.com/engagements.json" in url:
        if "category=bug_bounty" in url:
            return _j({"paginationMeta": {"totalCount": 1, "limit": 24}, "engagements": [{"briefUrl": "/engagements/direct-bc", "name": "Direct BC"}]})
        return _j({"paginationMeta": {"totalCount": 1, "limit": 24}, "engagements": [{"briefUrl": "/engagements/direct-bc-vdp", "name": "Direct VDP"}]})
    if "bugcrowd.com/engagements/" in url:
        if url.endswith("/changelog/abc.json"):
            return _j({"data": {"scope": [
                {"inScope": True, "targets": [{"name": "direct-bc.example.com", "category": "website"}, {"name": "", "uri": "", "ipAddress": "1.2.3.4", "category": "api"}]},
                {"inScope": False, "targets": [{"name": "oos-bc.example.com", "category": "website"}]}]}})
        if url.endswith("/changelog/def.json"):
            return _j({"data": {"scope": [{"inScope": True, "targets": [{"name": "vdp-bc.example.com", "category": "website"}]}]}})
        ident = "abc" if url.endswith("/direct-bc") else "def"
        react = "ResearcherEngagementBrief" if ident == "abc" else "x"           # (nested quotes inside an f-string need Python 3.12)
        klass = "" if ident == "abc" else "react-component-researcher-engagement-brief"
        return (f'<html><body><div data-react-class="{react}" class="{klass}" data-api-endpoints="'
                f'{{&quot;engagementBriefApi&quot;:{{&quot;getBriefVersionDocument&quot;:&quot;/engagements/direct-bc/changelog/{ident}&quot;}}}}"></div>{PAD}</body></html>').encode()
    if "api.intigriti.com" in url:
        assert headers.get("Authorization") == "Bearer inti-secret", "Intigriti call without bearer token"
        if "/domains/v9" in url:
            return _j({"content": [{"type": {"value": "Url"}, "endpoint": "versioned-inti.example.com", "tier": {"value": "Tier 2"}}]})
        if "/programs/p1" in url:
            return _j({"id": "p1", "domains": {"id": "v1", "content": [
                {"type": {"value": "Url"}, "endpoint": "direct-inti.example.com", "tier": {"value": "Tier 1"}},
                {"type": {"value": "Url"}, "endpoint": "nobounty-inti.example.com", "tier": {"value": "No Bounty"}},
                {"type": {"value": "Android"}, "endpoint": "com.direct.intiapp", "tier": {"value": "Tier 1"}}]}})
        if "/programs/p5" in url:
            return _j({"id": "p5", "domains": {"id": "v9"}})
        if "/programs/p2" in url:
            return _j({"id": "p2", "domains": {"content": [{"type": {"value": "Url"}, "endpoint": "private-inti.example.com", "tier": {"value": "Tier 1"}}]}})
        return _j({"maxCount": 4, "records": [
            {"id": "p1", "name": "Inti Public", "handle": "intipub", "status": {"id": 3, "value": "Open"}, "confidentialityLevel": {"id": 4, "value": "Public"}, "maxBounty": {"value": 1000, "currency": "EUR"}},
            {"id": "p2", "name": "Inti Private", "status": {"value": "Open"}, "confidentialityLevel": {"id": 2, "value": "Application"}, "maxBounty": {"value": 500}},
            {"id": "p3", "name": "Inti Closed", "status": {"value": "Closed"}, "confidentialityLevel": {"value": "Public"}},
            {"id": "p5", "name": "Inti Versioned", "status": {"value": "Open"}, "confidentialityLevel": {"value": "Public"}, "maxBounty": {"value": 0}}]})
    if "api.yeswehack.com" in url:
        assert "Authorization" not in headers, "YWH token was not configured, none must be sent"
        if "/programs/ywhpub" in url:
            return _j({"title": "YWH Public", "slug": "ywhpub", "bounty": True, "scopes": [
                {"scope": "direct-ywh.example.com", "scope_type": "web-application"},
                {"scope": "com.direct.ywhapp", "scope_type": "mobile-application-android"}]})
        if "/programs/ywhpriv" in url:
            return _j({"title": "YWH Private", "slug": "ywhpriv", "bounty": True, "scopes": [{"scope": "private-ywh.example.com", "scope_type": "web-application"}]})
        return _j({"items": [{"slug": "ywhpub", "title": "YWH Public", "public": True, "disabled": False, "bounty": True},
                             {"slug": "ywhpriv", "title": "YWH Private", "public": False, "bounty": True}], "pagination": {"page": 1, "nb_pages": 1}})
    if "hackenproof.com" in url:
        if "/programs?page=1" in url:
            return (f'<html><a href="/programs">all</a><a href="/programs/hp-one">One</a><a href="https://hackenproof.com/programs/hp-two">Two</a>'
                    f'<a href="/audit-programs">x</a>{PAD}</html>').encode()
        if "/programs?page=" in url:
            return f"<html><body>no more programs{PAD}</body></html>".encode()
        if url.endswith("/programs/hp-one"):
            return (f"<html><body><p>Up to: $50,000</p><h3>In scope</h3><table><tr><th>Target</th><th>Type</th><th>Severity</th></tr>"
                    "<tr><td>direct-hp.example.com<br>Copy</td><td>Web</td><td>Critical</td></tr>"
                    "<tr><td>*.wild-hp.example.com<br>Copy</td><td>API</td><td>High</td></tr>"
                    "<tr><td>0xAbCdEf0123456789<br>Copy</td><td>Smart Contract</td><td>Critical</td></tr></table>"
                    "<h3>Out of scope</h3><table><tr><th>Target</th><th>Type</th><th>Severity</th></tr>"
                    f"<tr><td>oos-hp.example.com<br>Copy</td><td>Web</td><td>None</td></tr></table>{PAD}</body></html>").encode()
        return (f"<html><body><h3>In scope</h3><table><tr><td>vdp-hp.example.com<br>Copy</td><td>Web</td><td>Medium</td></tr></table>{PAD}</body></html>").encode()
    return None

SELF_PAGES = {
    "https://selfpage.example.com/scope": "<html><body><h1>Scope</h1><ul><li>*.selfpage-example.com</li><li>https://selfpage-example.com/portal/api</li></ul>"
                                          "<h2>Out of scope</h2><ul><li>blog.selfpage-example.com</li></ul></body></html>",
    "https://selfjs.example.com/": "<html><body><div id='app'></div><script>boot()</script></body></html>",   # drawn by JavaScript: no text
}


def fake_fetch(url: str, headers=None, min_bytes=100, data=None, with_headers=False):
    headers = headers or {}
    for key in broken:
        if key in url:
            raise RuntimeError(f"simulated 404 for {url}")
    if url in SELF_PAGES:                         # self-hosted program pages (config/self-hosted-pages.tsv)
        return SELF_PAGES[url].encode()
    direct = direct_fixture(url, headers, data)
    if direct is not None:
        if with_headers:
            import email.message
            msg = email.message.Message()
            msg.add_header("Set-Cookie", "_h1_session=abc; path=/; HttpOnly")
            return direct, msg
        return direct
    if "publicsuffix.org" in url:
        return (REPO / "config" / "public_suffix_list.dat").read_bytes()
    for plat in ("hackerone", "intigriti", "yeswehack", "bugcrowd"):
        if f"{plat}_data.json" in url:
            return cfg[plat].encode()
    if "wildcards.txt" in url:
        return cfg["arkadiyt-wildcard"].encode()
    if "domains.txt" in url:
        return cfg["arkadiyt"].encode()
    if "public-bugbounty-programs" in url:
        if url.endswith("src/data.yaml"):
            return to_yaml(cfg["chaos"]).encode()
        return cfg["chaos"].encode()
    if "diodb" in url:
        return cfg["diodb"].encode()
    if "immunefi" in url:
        return cfg["immunefi"].encode()
    raise RuntimeError("unexpected url " + url)


def run(date: str, baseline: bool = False, version: str = ""):
    os.environ["BB_DATE"] = date
    os.environ["BB_BASELINE"] = "1" if baseline else ""
    import update_bb_domains as m
    m = importlib.reload(m)
    m.fetch = fake_fetch
    if version:
        m.PARSER_VERSION = version
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = m.main()
    assert rc == 0
    return buf.getvalue()


def lines(name):
    p = TMP / "data" / name
    return [l for l in p.read_text().splitlines() if l]


ok = True


def check(label, cond, extra=""):
    global ok
    print(("PASS  " if cond else "FAIL  ") + label + (f"   {extra}" if extra and not cond else ""))
    ok = ok and bool(cond)


# ---- day 1: baseline
run("2026-11-01")
apex, subs, wild, ips = lines("apex.txt"), lines("subdomains.txt"), lines("wildcards.txt"), lines("ips.txt")
check("apex uses PSL: www.bbc.co.uk -> bbc.co.uk", "bbc.co.uk" in apex)
check("bare suffix co.uk is not an apex", "co.uk" not in apex)
check("wildcard base tenant.co.uk -> apex tenant.co.uk", "tenant.co.uk" in apex and "tenant.co.uk" in wild)
check("wildcard base corp.example.com kept as wildcard and as sub", "corp.example.com" in wild and "corp.example.com" in subs)
check("punycode / lowercase handled", "shop.example.org" in subs and "xn--bcher-kva.de" in apex)
check("public IPs and CIDR kept in ips.txt", "34.120.0.9" in ips and "1.2.3.0/24" in ips)
check("IPs are in master but not in domain lists", "34.120.0.9" in lines("master.txt") and "34.120.0.9" not in apex + subs)
rej = (TMP / "data" / "rejected.txt").read_text()
check("junk rejected with reasons (file-ext, public-suffix)", all(x in rej for x in ("file-ext", "public-suffix")))
_urls = lines("urls.txt")
check("url with port/path becomes a url entry (scheme kept, query dropped) and its host is NOT added as a host",
      "http://api.vdp-only.io:8443/x" in _urls and "api.vdp-only.io" not in subs and "vdp-only.io" not in apex)
check("diodb: policy host not scope, own domain kept as apex", "company.com.au" in apex and "accenture.responsibledisclosure.com" not in subs)
check("diodb/immunefi: platform & explorer/github hosts skipped", not any(h in apex + subs for h in ("hackerone.com", "etherscan.io", "github.com")))
check("immunefi: project hosts present", "app.defi.xyz" in subs and "defi.xyz" in apex)
check("baseline run has empty diffs", not lines("apex-new.txt") and not lines("subdomains-new.txt"))
bounty = {l.split("\t")[2]: l.split("\t")[0] for l in lines("review-by-source.txt")[1:]}
check("bounty: projectdiscovery paying host is paying, its vdp is non-paying, arkadiyt-domains is unknown",
      bounty.get("api.paid.example.org") == "paying" and bounty.get("vdp.example.org") == "non-paying" and bounty.get("a.example.com") == "unknown")
check("bounty: paying beats non-paying (company.com.au via diodb yes)", bounty.get("company.com.au") == "paying")
check("*-paying lists include unknown (default) and not non-paying", "a.example.com" in lines("subdomains-paying.txt") and "vdp.example.org" not in lines("subdomains-paying.txt"))

# ---- platform files: real bounty flags
check("H1: wildcard from paying program is paying", bounty.get("h1paid.com") == "paying")
check("H1: asset not eligible for bounty is non-paying", bounty.get("noeligible.h1paid.com") == "non-paying")
check("H1: VDP program is non-paying", bounty.get("verisk-vdp.com") == "non-paying" or bounty.get("*.verisk-vdp.com") == "non-paying")
check("H1: source-code / app-store / out_of_scope entries are not listed", not any(h in apex + subs for h in ("github.com", "apps.apple.com", "oos.h1paid.com")))
check("Intigriti: tiered asset is paying, 'No Bounty' asset is non-paying",
      bounty.get("app.aikido.dev") == "paying" and bounty.get("nobounty.aikido.dev") == "non-paying")
check("Intigriti: out_of_scope wildcard is NOT listed", "oosaikido.dev" not in apex + subs + wild)
check("Intigriti: an endpoint with a path is a url entry, VDP so non-paying", bounty.get("https://www.adac-vdp.de/mein") == "non-paying" and "www.adac-vdp.de" not in subs)
check("Intigriti: IP range goes to ips.txt", "193.30.38.0/24" in ips)
check("YesWeHack: wildcard + host under paying program are paying", bounty.get("www.atg.se") == "paying" and "atg.se" in wild)
check("YesWeHack: free-text target and app-store link skipped, out_of_scope not listed",
      not any("resource" in h or "apps.apple" in h or "shop.atg.se" in h for h in apex + subs))
check("YesWeHack: program with max_bounty 0 is non-paying", bounty.get("vdp.ywh-example.com") == "non-paying")
check("Bugcrowd: payout > 0 is paying, URL scheme/slash stripped", bounty.get("data-api.coindesk.com") == "paying")
check("Bugcrowd: Atlassian marketplace listing skipped, out_of_scope not listed", "marketplace.atlassian.com" not in apex + subs and "www.coindesk.com" not in subs)
# ---- out of scope: understood, kept apart from every target list, written per program
_oos = [l.split("\t") for l in lines("program-out-of-scope.tsv")[1:]]
_names = {l.split("\t")[7]: l.split("\t")[2] for l in lines("programs.txt")[1:]}
_oosv = {(c[1], c[2]) for c in _oos}
_master = set(lines("master.txt"))
check("out of scope: file has the header and every id is a program of programs.txt",
      lines("program-out-of-scope.tsv")[0] == "id\tasset\tvalue" and _oos and all(c[0] in _names for c in _oos))
check("out of scope: HackerOne mirror (URL entry) and Intigriti mirror (wildcard entry) are read",
      ("subdomains", "oos.h1paid.com") in _oosv and ("wildcards", "oosaikido.dev") in _oosv, str(sorted(_oosv)[:12]))
check("out of scope: direct sources (HackerOne GraphQL + API) keep their excluded assets",
      {("subdomains", "gql-oos.example.com"), ("subdomains", "oos-h1.example.com")} <= _oosv, str(sorted(_oosv)[:20]))
check("out of scope: nothing excluded is a target anywhere", not ({v for _a, v in _oosv} & _master - {"atg.se"}) or all(v not in _master for _a, v in _oosv if v.startswith(("oos", "gql-oos", "pubinti-oos"))))
check("out of scope: free text is kept as text, attributed to its program",
      any("shop.atg.se" in c[2] and _names[c[0]] for c in _oos), str([c for c in _oos if "atg" in c[2]]) + str(sorted(_oosv)))
check("Bugcrowd: ipAddress used when target is empty", "34.120.0.77" in ips)
check("Bugcrowd: payout 0 is non-paying", bounty.get("vdp.bc-example.com") == "non-paying")
check("definite flag beats unknown (host in arkadiyt AND a platform file)", bounty.get("vdp.bc-example.com") == "non-paying" and bounty.get("data-api.coindesk.com") == "paying")
check("non-paying platform hosts stay out of *-paying lists", "vdp.bc-example.com" not in lines("subdomains-paying.txt") and "noeligible.h1paid.com" not in lines("subdomains-paying.txt"))

# ---- github.txt, PSL gaps, projectdiscovery without flag, diodb tenants
gh = lines("github.txt")
check("github.txt: projects from H1, Bugcrowd, YesWeHack, immunefi-direct assets (normalised, lowercase, .git and paths stripped)",
      gh == sorted(["https://github.com/omacom/omarchy", "https://github.com/omacom/omarchy-docs", "https://github.com/bc-org/bc-repo",
                    "https://github.com/ywh-org", "https://github.com/defi-org/contracts"]), str(gh))
check("github.txt: immunefi-direct githubUrl field, gitlab and github.com/about are not scope", not any(x in gh for x in ("https://github.com/defi", "https://github.com/about")) and not any("gitlab" in x for x in gh))
check("github projects are not in domain lists", not any("github" in h for h in apex + subs))
check("PSL gap: transunion.co.br keeps its own apex, bare co.nl rejected", "transunion.co.br" in apex and "co.br" not in apex and "co.nl" not in apex)
check("projectdiscovery program without bounty key -> unknown, not non-paying", bounty.get("nokey.example.org") == "unknown")

# ---- recovery tiers
internal, apps, pats, maybe = lines("internal-hosts.txt"), lines("apps.txt"), lines("patterns.txt"), lines("maybe.txt")
rec = (TMP / "data" / "recovered.txt").read_text()
check("private IP and .internal host go to internal-hosts.txt, not ips/master", "10.0.0.1" in internal and "8x8hosts.internal" in internal and "10.0.0.1" not in ips)
check("package id and store URLs go to apps.txt (H1 store link, Bugcrowd marketplace listing, YWH ios link, com.example.myapp)",
      "com.example.myapp" in apps and "https://apps.apple.com/app/id6447694643" in apps
      and "https://marketplace.atlassian.com/apps/1218391/x" in apps and "https://apps.apple.com/app/id1434660322" in apps, str(apps))
check("pattern kept verbatim in patterns.txt, its real tail becomes a domain", "api-*.pattern-example.com" in pats and "pattern-example.com" in apex)
check("host hidden in text goes to maybe.txt only", "ncsc.ch" in maybe and "ncsc.ch" not in apex + subs)
check("repairs land in the real lists and are logged in recovered.txt",
      "mail.example.com" in subs and "scheme.example.com" in subs and "wild.example.org" in wild and "app.example.com" in subs
      and all(x in rec for x in ("email", "scheme-typo", "comment-stripped", "pattern-tail", "text-extract")))
check("non-GitHub repo goes to repos-other.txt; github.com/about and free text are rejected with reasons",
      "https://gitlab.com/x/y" in lines("repos-other.txt") and "not-a-project" in rej and "free-text" in rej)

# ---- no duplicate lines in any written file; master adds up
import collections as _c
dups = []
for f in sorted((TMP / "data").glob("*.txt")):
    if f.name == "stats.txt":
        continue
    rows = f.read_text(encoding="utf-8").splitlines()
    if f.name in ("review-by-source.txt", "review-new.txt", "review-new-paying.txt", "review-removed.txt", "rejected.txt", "recovered.txt"):
        rows = rows[1:]                                  # header line
    d = [k for k, v in _c.Counter(rows).items() if v > 1]
    if d or any(not r.strip() for r in rows):
        dups.append((f.name, d[:2]))
check("no data file has a duplicate or blank line", not dups, str(dups))
M_, A_, S_, I_ = set(lines("master.txt")), set(lines("apex.txt")), set(lines("subdomains.txt")), set(lines("ips.txt"))
ALL_ = set()
for _k in ("apex", "subdomains", "urls", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"):
    ALL_ |= set(lines(_k + ".txt"))
check("master = union of every kind's list (once each); apex and subdomains never overlap",
      M_ == ALL_ and not (A_ & S_) and A_ <= M_ and S_ <= M_ and I_ <= M_)
_st = (TMP / "data" / "stats.txt").read_text()
check("stats.txt has the table and the explanation", "kind" in _st and "How the numbers are counted" in _st and "listed by a source +" in _st)
check("every kind has -paying, -new and -removed files",
      all((TMP / "data" / f"{k}-{s}.txt").is_file() for k in ("apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe") for s in ("paying", "new", "removed")))
check("no file from the old naming scheme is left", not any((TMP / "data" / n).exists() for n in ("new-apex.txt", "removed-apps.txt", "new-subdomains.txt")))
check("ASN entries (incl. 'AS6720 1/2') go to asn.txt, not to rejected", lines("asn.txt") == ["AS16314", "AS6720"] and "AS16314" not in (TMP / "data" / "rejected.txt").read_text())
_ctx = [l for l in next((TMP / "state").glob("context-*.tsv")).read_text().splitlines() if l.startswith("asn\tAS6720\t")]
check("context file keeps program + raw entry for an ASN", _ctx and "Omarchy Program" in _ctx[0] and "AS6720 1/2" in _ctx[0], str(_ctx))
check("daily snapshot has the 11 lists + review files and none of the per-asset new/removed files",
      (TMP / "history" / "daily" / "2026-11-01" / "asn.txt").is_file() and (TMP / "history" / "daily" / "2026-11-01" / "review-removed.txt").is_file()
      and not (TMP / "history" / "daily" / "2026-11-01" / "apex-new.txt").exists() and not (TMP / "history" / "daily" / "2026-11-01" / "master.txt").exists())
# ---- stats.txt shape (golden-style): headline, sections, one row per asset type and per source, numbers add up
import re as _re
_st = (TMP / "data" / "stats.txt").read_text().splitlines()
_ASSETS = ("apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe")
_SOURCES = ("arkadiyt-domains", "arkadiyt-wildcard", "arkadiyt-hackerone", "arkadiyt-bugcrowd", "arkadiyt-intigriti", "arkadiyt-yeswehack", "projectdiscovery", "diodb", "immunefi-direct")
check("stats: line 1 is the headline", bool(_re.match(r"\d{4}-\d{2}-\d{2} \| ", _st[0])) and "failed sources:" in _st[0])
check("stats: all sections present", all(any(x in l for l in _st) for x in ("Sources today", "Diffs:", "Explanation / logic", "How the numbers are counted")))
_rows = {l.split()[0]: l.split() for l in _st if l.split() and l.split()[0] in _ASSETS + _SOURCES + ("total",)}
check("stats: one row for each of the 12 asset types and the 9 sources", all(k in _rows for k in _ASSETS + _SOURCES))
check("stats: the total row is the sum of the asset rows", int(_rows["total"][1]) == sum(int(_rows[a][1]) for a in _ASSETS))
check("stats: source rows say ok and have a row count", all(_rows[x][1] == "ok" and _rows[x][2].isdigit() for x in _SOURCES))
# ---- direct platform sources (day 1: all tokens set)
_rbs = {l.split("\t")[2]: l.split("\t") for l in (TMP / "data" / "review-by-source.txt").read_text().splitlines()[1:] if l.split("\t")[1] in ("apex", "subdomains", "ips")}
def _flag(h):
    return _rbs[h][0] if h in _rbs else None
_all_master = set(lines("master.txt"))
check("direct: in-scope hosts of every direct platform arrive",
      all(h in _all_master for h in ("direct-h1.example.com", "direct-bc.example.com", "direct-inti.example.com", "versioned-inti.example.com", "direct-ywh.example.com", "direct-hp.example.com", "1.2.3.4", "gql-h1.example.com")))
check("direct: out-of-scope, private and smart-contract targets are left out",
      not any(h in _all_master for h in ("oos-h1.example.com", "private-h1.example.com", "oos-bc.example.com", "private-inti.example.com", "private-ywh.example.com", "oos-hp.example.com", "gql-oos.example.com", "0xAbCdEf0123456789", "0xabcdef0123456789")))
check("direct: bounty flags (H1 eligible, Bugcrowd category, Intigriti tier / maxBounty, YWH bounty, HackenProof 'Up to')",
      [_flag(h) for h in ("direct-h1.example.com", "nobounty-h1.example.com", "direct-bc.example.com", "vdp-bc.example.com", "direct-inti.example.com", "nobounty-inti.example.com", "versioned-inti.example.com", "direct-ywh.example.com", "direct-hp.example.com", "vdp-hp.example.com")]
      == ["paying", "non-paying", "paying", "non-paying", "paying", "non-paying", "non-paying", "paying", "paying", "unknown"],
      str([_flag(h) for h in ("direct-h1.example.com", "nobounty-h1.example.com", "direct-bc.example.com", "vdp-bc.example.com", "direct-inti.example.com", "nobounty-inti.example.com", "versioned-inti.example.com", "direct-ywh.example.com", "direct-hp.example.com", "vdp-hp.example.com")]))
check("direct: mobile apps go to apps.txt, wildcard of HackenProof to wildcards.txt",
      all(a in lines("apps.txt") for a in ("com.direct.h1app", "com.gql.h1app", "com.direct.intiapp", "com.direct.ywhapp")) and "wild-hp.example.com" in lines("wildcards.txt"))
check("direct: sources are named in the review file", "hackerone-api" in _rbs["direct-h1.example.com"][3] and "hackerone-direct" in _rbs["gql-h1.example.com"][3] and "bugcrowd-direct" in _rbs["direct-bc.example.com"][3])
check("direct: program name and link reach the context file", any("Direct Public\thttps://hackerone.com/dirpub" in l for l in next((TMP / "state").glob("context-*.tsv")).read_text().splitlines() if "direct-h1.example.com" in l))
_SRC14 = ("hackerone-direct", "hackerone-api", "bugcrowd-direct", "intigriti-direct", "yeswehack-direct", "hackenproof-direct")
_stt = (TMP / "data" / "stats.txt").read_text().splitlines()
check("direct: all six show status ok in 'Sources today'", all(any(l.split()[:2] == [s, "ok"] for l in _stt if l.split()) for s in _SRC14))
check("no failures on a clean day", not lines("failed-sources.txt"))

# ---- day 2: one new subdomain, one removed
cfg["arkadiyt"] = BASE["arkadiyt"].replace("a.example.com", "b.example.com")
run("2026-11-02")
check("day 2: new subdomain detected", lines("subdomains-new.txt") == ["b.example.com"], str(lines("subdomains-new.txt")))
check("day 2: removed subdomain detected", lines("subdomains-removed.txt") == ["a.example.com"])
check("day 2: review-new carries kind, bounty and source", any(l.startswith("unknown\tsubdomains\tb.example.com\tarkadiyt") for l in lines("review-new.txt")))
check("day 2: review-new-paying lists it (unknown counts as paying by default)", any(l.split("\t")[2] == "b.example.com" for l in lines("review-new-paying.txt")[1:]))
check("day 2: review-removed says where a.example.com was listed", any(l.split("\t")[2] == "a.example.com" and l.split("\t")[3] == "arkadiyt-domains" and l.split("\t")[-1] for l in lines("review-removed.txt")[1:]), str(lines("review-removed.txt")))
check("day 2: review-removed explains WHY (program gone vs value dropped from a program that is still listed)",
      lines("review-removed.txt")[0].endswith("why_removed") and all(("program" in l.split("\t")[-1]) or ("no program" in l.split("\t")[-1]) for l in lines("review-removed.txt")[1:]),
      str(lines("review-removed.txt")))

# ---- day 3: arkadiyt down -> carried forward, no fake removals
broken.add("arkadiyt/bounty-targets-data")
run("2026-11-03")
check("day 3: source down -> carried forward, no diffs", not lines("subdomains-new.txt") and not lines("subdomains-removed.txt") and not lines("apex-removed.txt"))
check("day 3: failure recorded", any("arkadiyt-domains" in l for l in lines("failed-sources.txt")))
check("day 3: data still complete", "b.example.com" in lines("subdomains.txt") and len(lines("apex.txt")) >= 10)
broken.clear()

# ---- day 4: projectdiscovery collapses to 1 row (below 50 %) -> treated as broken
good_chaos = cfg["chaos"]
cfg["chaos"] = json.dumps({"programs": [{"name": "p1", "bounty": True, "domains": ["paid.example.org"]}]})
run("2026-11-04")
check("day 4: collapsed source carried forward", "c3.paid.example.org" in lines("subdomains.txt") and not lines("subdomains-removed.txt"))
check("day 4: collapse recorded", any("projectdiscovery" in l and "shrank" in l for l in lines("failed-sources.txt")))
cfg["chaos"] = good_chaos

# ---- day 5 skipped; day 6: real change, diff must be against day 4 (latest earlier folder)
cfg["arkadiyt"] = cfg["arkadiyt"] + "\nnew.example.com"
run("2026-11-06")
check("day 6 (day 5 skipped): diff = exactly the new host", lines("subdomains-new.txt") == ["new.example.com"], str(lines("subdomains-new.txt")))
check("day 6: nothing falsely removed", not lines("subdomains-removed.txt") and not lines("apex-removed.txt"))
first = lines("subdomains-new.txt")

# ---- re-run the same day: same diff (does not compare against itself)
run("2026-11-06")
check("re-run same day gives the same diff", lines("subdomains-new.txt") == first)

# ---- baseline flag
cfg["arkadiyt"] = cfg["arkadiyt"] + "\nanother.example.com"
run("2026-11-07", baseline=True)
check("BB_BASELINE=1: no diffs", not lines("subdomains-new.txt"))
run("2026-11-08")
check("day after baseline: diff vs baseline day is empty", not lines("subdomains-new.txt"))

# ---- merged-list collapse guard (all sources 'fine' but result tiny): simulate by emptying denylist effect
(TMP / "config" / "denylist.txt").write_text("example.com\nexample.org\nexample.net\n")
run("2026-11-09")
check("merged collapse: diffs skipped and flagged", not lines("apex-removed.txt") and any("collapsed" in l for l in lines("failed-sources.txt")))
(TMP / "config" / "denylist.txt").write_text("")

# ---- projectdiscovery: dist/data.json broken -> src/data.yaml gives the same rows and flags
run("2026-11-10")                                   # normal day first (the run before had a denylist on)
before = {"\t".join(l.split("\t")[:4]) for l in lines("review-by-source.txt")[1:] if "projectdiscovery" in l.split("\t")[3]}
broken.add("dist/data.json")
run("2026-11-11")
after = {"\t".join(l.split("\t")[:4]) for l in lines("review-by-source.txt")[1:] if "projectdiscovery" in l.split("\t")[3]}
check("projectdiscovery: YAML fallback gives the same hosts and bounty flags as JSON", before == after and len(after) > 20, f"{len(before)} vs {len(after)}")
check("projectdiscovery: fallback used without any failure recorded", not lines("failed-sources.txt"), str(lines("failed-sources.txt")))
broken.clear()

# ---- a changed PARSER_VERSION is an automatic baseline (also for a re-run on the same day), the day after is normal
cfg["arkadiyt"] = BASE["arkadiyt"] + "\nvnew1.example.com\n"
run("2026-11-12", version="test-v2")
check("parser version change: no diffs that day, reason says so",
      not lines("subdomains-new.txt") and "parser version changed" in (TMP / "data" / "stats.txt").read_text())
run("2026-11-12", version="test-v2")
check("parser version change: a re-run on the same day is still a baseline", not lines("subdomains-new.txt") and not lines("subdomains-removed.txt"))
_hl = (TMP / "data" / "stats.txt").read_text().splitlines()[0]
check("parser version change: the re-run headline does not say 'X -> X'", "changed earlier today" in _hl and "test-v2 -> test-v2" not in _hl, _hl)
cfg["arkadiyt"] = BASE["arkadiyt"] + "\nvnew1.example.com\nvnew2.example.com\n"
run("2026-11-13", version="test-v2")
check("parser version change: the next day diffs normally", lines("subdomains-new.txt") == ["vnew2.example.com"], str(lines("subdomains-new.txt")))

# ---- direct sources: not configured -> skipped (green); broken -> warning (green) unless strict; private only on request
for k in ("H1_USERNAME", "H1_TOKEN", "INTIGRITI_TOKEN"):
    os.environ.pop(k)
run("2026-11-14")
_stt = (TMP / "data" / "stats.txt").read_text()
check("direct: without tokens the HackerOne API is 'skipped' (not failed) and Intigriti falls back to its public endpoints",
      any(l.split()[:2] == ["hackerone-api", "skipped"] for l in _stt.splitlines() if l.split())
      and any(l.split()[:2] == ["intigriti-direct", "ok"] for l in _stt.splitlines() if l.split())
      and "pubinti.example.com" in lines("subdomains.txt") and "old-version-inti.example.com" not in lines("master.txt")
      and "pubinti-oos.example.com" not in lines("master.txt") and "com.pubinti.app" in lines("apps.txt") and "pubinti-wild.example.com" in lines("wildcards.txt")
      and not lines("failed-sources.txt"))

# ---- descriptions: the Yahoo problem (a broad asset whose description holds the real list), and the apis overlay
_oosp = {l.split("\t")[2] for l in lines("program-out-of-scope.tsv")[1:]}
check("descriptions: hosts, wildcards and URLs listed in an asset description are collected",
      "tw.ews.mall.yahooapis.example.com" in lines("subdomains.txt") and "tw.bid.yahoo-demo.example.com/api" in "\n".join(lines("urls.txt")).replace("https://", "")
      and "other-type.yahoo-demo.example.com" in lines("subdomains.txt"), str([l for l in lines("urls.txt") if "yahoo" in l]))
check("descriptions: an 'out of scope' section of the description is an exclusion, never a target",
      "legacy.yahoo-demo.example.com" not in lines("master.txt") and "legacy.yahoo-demo.example.com" in _oosp)
check("descriptions: a host only mentioned in a sentence is a guess (maybe.txt), not a target",
      "guess.yahoo-demo.example.net" in lines("maybe.txt") and "guess.yahoo-demo.example.net" not in lines("subdomains.txt")
      and not any("hackerone.com/x" in l for l in lines("master.txt")), str(lines("maybe.txt")[:8]))
check("apis: the overlay list holds addresses that name an API, has its four files, and is not counted in the total",
      "tw.ews.mall.yahooapis.example.com" in lines("apis.txt") and "tw.bid.yahoo-demo.example.com/api" in "\n".join(lines("apis.txt")).replace("https://", "")
      and all((TMP / "data" / f"apis{x}.txt").is_file() for x in ("-paying", "-new", "-removed")) and "pubinti.example.com" not in lines("apis.txt"))

os.environ.update({"H1_USERNAME": "tester", "H1_TOKEN": "h1-secret", "INTIGRITI_TOKEN": "inti-secret"})
broken.add("api.intigriti.com")
run("2026-11-15")
_stt = (TMP / "data" / "stats.txt").read_text()
check("direct: a broken direct source is a warning, the run stays green, the last good copy is kept",
      not lines("failed-sources.txt") and "warnings: 1" in _stt.splitlines()[0] and "intigriti-direct" in _stt and "pubinti.example.com" in lines("subdomains.txt"))  # day 14 stored the public-endpoint copy
os.environ["BB_DIRECT_STRICT"] = "1"
run("2026-11-16")
check("direct: BB_DIRECT_STRICT=1 turns the same breakage into a failed source", any("intigriti-direct" in l for l in lines("failed-sources.txt")))
os.environ.pop("BB_DIRECT_STRICT")
broken.clear()
os.environ["BB_INCLUDE_PRIVATE"] = "1"
# the public-endpoint copy of intigriti-direct (many rows: its descriptions are read) must not trip the "shrank below 50%" guard
# against the five rows the token API gives in this fixture; that guard has its own tests
for _f in (TMP / "state").glob("intigriti-direct.*"):
    _f.unlink()
run("2026-11-17")
check("direct: BB_INCLUDE_PRIVATE=1 adds private programs (and only then)",
      all(h in lines("master.txt") for h in ("private-h1.example.com", "private-inti.example.com", "private-ywh.example.com")),
      str([h for h in ("private-h1.example.com", "private-inti.example.com", "private-ywh.example.com") if h not in lines("master.txt")]) + str([l for l in (TMP / "data" / "stats.txt").read_text().splitlines() if "intigriti" in l or "[!]" in l])[:900])
os.environ.pop("BB_INCLUDE_PRIVATE")
run("2026-11-18")

# ---- a mirror that silently stops publishing: unchanged content for days -> warning; BB_DISABLE retires a source
os.environ.pop("BB_STALE_DAYS")  # the frozen test fixtures would otherwise warn on every day
run("2026-11-19")
_stt = (TMP / "data" / "stats.txt").read_text()
check("stale mirror: arkadiyt unchanged for days is reported as a warning (run stays green)",
      "arkadiyt-domains: content unchanged for" in _stt and not lines("failed-sources.txt") and "warnings: " in _stt.splitlines()[0])
os.environ["BB_DISABLE"] = "diodb,hackenproof-direct"
run("2026-11-20")
_stt = (TMP / "data" / "stats.txt").read_text().splitlines()
check("BB_DISABLE: retired sources are listed as disabled and not downloaded",
      any(l.split()[:2] == ["diodb", "disabled"] for l in _stt if l.split()) and any(l.split()[:2] == ["hackenproof-direct", "disabled"] for l in _stt if l.split()))
os.environ.pop("BB_DISABLE")
run("2026-11-21")

# ---- Bugcrowd: the reward table decides "paying" (as in arkadiyt/bounty-targets), the category only when there is no table
def _bc_fetch(reward_groups):
    def f(url, headers=None, min_bytes=100, data=None, with_headers=False):
        if "engagements.json" in url:
            if "category=bug_bounty" in url:
                return json.dumps({"engagements": [{"briefUrl": "/engagements/rw", "name": "RW"}], "paginationMeta": {"totalCount": 1, "limit": 25}}).encode()
            return json.dumps({"engagements": [], "paginationMeta": {"totalCount": 0, "limit": 25}}).encode()
        if url.endswith("/engagements/rw"):
            ep = json.dumps({"engagementBriefApi": {"getBriefVersionDocument": "/briefs/rw"}}).replace('"', "&quot;")
            return f'<html><div data-react-class="ResearcherEngagementBrief" data-api-endpoints="{ep}"></div>{PAD}</html>'.encode()
        if url.endswith("/briefs/rw.json"):
            return json.dumps({"data": {"scope": reward_groups}}).encode()
        raise RuntimeError("unexpected url " + url)
    return f
import directsources as _ds0
_tg = [{"name": "rw.example.com", "category": "website"}]
_zero = _ds0.bugcrowd(_bc_fetch([{"inScope": True, "rewardRangeData": {"1": {"max": 0}}, "targets": _tg}]), _ds0.Budget(60, "bc"), 0)
_paid = _ds0.bugcrowd(_bc_fetch([{"inScope": True, "rewardRangeData": {"1": {"max": 5000}}, "targets": _tg}]), _ds0.Budget(60, "bc"), 0)
_none = _ds0.bugcrowd(_bc_fetch([{"inScope": True, "targets": _tg}]), _ds0.Budget(60, "bc"), 0)
check("bugcrowd: reward table max > 0 = paying, table with only zeros = non-paying, no table = category decides",
      [r[1] for r in _paid] == ["paying"] and [r[1] for r in _zero] == ["non-paying"] and [r[1] for r in _none] == ["paying"], str((_paid, _zero, _none)))

# ---- _each(): parallel reading with tolerance for single broken programs
import directsources as _ds
_ds.WORKERS = 4
def _work_factory(bad):
    def work(i):
        if i in bad:
            raise RuntimeError(f"HTTP 403 Forbidden for item {i}")
        return {(f"h{i}.example.com", "paying", "p", "u")}
    return work
_b = _ds.Budget(60, "unit")
_r = _ds._each(range(20), _work_factory({3}), _b, "programs", 0)
check("_each: all good items are read in parallel, one broken program is skipped with a note",
      len(_r) == 19 and "1 of 20 programs skipped" in _ds.NOTES.pop("unit", ""))
try:
    _ds._each(range(20), _work_factory(set(range(10))), _b, "programs", 0)
    _many = False
except _ds.ShapeError:
    _many = True
check("_each: when many programs fail the whole source fails (platform or parser problem)", _many)
try:
    _ds._each(range(5), lambda i: (_ for _ in ()).throw(TimeoutError("budget")), _b, "programs", 0)
    _to = False
except TimeoutError:
    _to = True
check("_each: a used-up time budget ends the source (never half data)", _to)

# ---- renamed sources: old state files are picked up under the new name
(TMP / "state" / "arkadiyt-domains.tsv").rename(TMP / "state" / "arkadiyt.tsv")
run("2026-11-22")
check("rename: state/arkadiyt.tsv is moved to arkadiyt-domains.tsv and the run is clean",
      (TMP / "state" / "arkadiyt-domains.tsv").is_file() and not (TMP / "state" / "arkadiyt.tsv").exists() and not lines("failed-sources.txt"))

# ---- _each(): a couple of skipped programs is a MINOR note (no warning), many is not
def _minor_case(n_bad, n_total):
    ds = _ds0
    ds.NOTES.clear(); ds.MINOR.clear()
    def work(i):
        if i < n_bad:
            raise ds.ShapeError("no brief")
        return {(f"h{i}.example.com", "paying", "P", "https://p")}
    try:
        ds._each(list(range(n_total)), work, ds.Budget(60, "x"), "things", 0)
    except ds.ShapeError:
        return "broken"
    return "minor" if "x" in ds.MINOR else ("note" if "x" in ds.NOTES else "clean")
check("direct: 3 of 518 skipped = minor note, 30 of 100 = whole source broken, 0 = clean",
      (_minor_case(3, 518), _minor_case(30, 100), _minor_case(0, 10)) == ("minor", "broken", "clean"), str((_minor_case(3, 518), _minor_case(30, 100))))

# ---- program ids, program-scope.tsv and stats.json (used by the web UI in site/)
run("2026-11-22")
_pl = [l.split("\t") for l in lines("programs.txt")[1:]]
_ids = {c[7] for c in _pl}
_ps = [l.split("\t") for l in lines("program-scope.tsv")[1:]]
check("programs.txt has a unique id column", lines("programs.txt")[0].endswith("\tid") and len(_ids) == len(_pl) and all(len(c[7]) == 10 for c in _pl))
check("program-scope.tsv: every id is a program of programs.txt, values and bounty present",
      lines("program-scope.tsv")[0] == "id\tasset\tvalue\tbounty" and _ps and all(c[0] in _ids and c[3] in ("paying", "non-paying", "unknown") for c in _ps))
_sj = json.loads((TMP / "data" / "stats.json").read_text())
check("stats.json: assets, sources, files and the snapshot copy", len(_sj["assets"]) == 13 and _sj["sources"] and _sj["files"]["programs"] == len(_pl)
      and (TMP / "history" / "daily" / "2026-11-22" / "stats.json").is_file())

# ---- self-hosted programs: config/self-hosted-programs.tsv, hosting column, data/programs.txt
run("2026-11-23")
_plat = [l.split("\t") for l in lines("programs.txt")[1:] if l.split("\t")[0] == "platform" and l.split("\t")[4] != "0"]
check("programs.txt exists with a header and platform programs", lines("programs.txt")[0].startswith("hosting\tbounty\tprogram\tprogram_url\thosts") and len(_plat) > 3)
_rbs0 = {l.split("\t")[2]: l.split("\t") for l in lines("review-by-source.txt")[1:]}
_shared = next(h for h, c in _rbs0.items() if c[4] == "platform" and c[1] == "subdomains")   # a host only platform programs list
(TMP / "config" / "self-hosted-programs.tsv").write_text(
    "# comment line\n\n"
    "Selfco VRP\thttps://selfco-example.com/security\tpaying\t*.selfco-example.com\n"
    "Selfco VRP\thttps://selfco-example.com/security\tpaying\tapi.selfco-example.com, 5.6.7.8\n"
    f"Twinco VRP\thttps://twinco-example.com/vrp\tnon-paying\t{_shared}\n")
run("2026-11-24")
_pr = {l.split("\t")[2]: l.split("\t") for l in lines("programs.txt")[1:]}
_rbs1 = {l.split("\t")[2]: l.split("\t") for l in lines("review-by-source.txt")[1:]}
check("self-hosted: manual source is ok and its hosts are in the lists",
      "selfco-example.com" in lines("apex.txt") and "api.selfco-example.com" in lines("subdomains.txt") and "5.6.7.8" in lines("ips.txt") and not lines("failed-sources.txt"))
check("self-hosted: programs.txt says self-hosted, with host count and source", _pr["Selfco VRP"][0] == "self-hosted" and _pr["Selfco VRP"][1] == "paying"
      and _pr["Selfco VRP"][4] != "0" and _pr["Selfco VRP"][5] == "self-hosted-manual", str(_pr.get("Selfco VRP")))
check("self-hosted: a self-hosted program that shares a host with a platform program is 'both' and names it",
      _pr["Twinco VRP"][0] == "both" and _pr["Twinco VRP"][6] != "", str(_pr.get("Twinco VRP")))
check("self-hosted: hosting column of review-by-source (self-hosted / both / platform)",
      _rbs1["api.selfco-example.com"][4] == "self-hosted" and _rbs1[_shared][4] == "both" and _rbs1["5.6.7.8"][4] == "self-hosted")
(TMP / "config" / "self-hosted-programs.tsv").write_text(
    "Spacey Corp  https://spacey-example.com/bb/info  paying  *.spacey-example.com\n"
    "Spacey Corp  https://spacey-example.com/bb/info  paying  spacey-ulaa.com\n")
run("2026-11-24")
check("self-hosted: lines with spaces instead of tabs are read too",
      "spacey-example.com" in lines("apex.txt") and "spacey-example.com" in lines("wildcards.txt") and "spacey-ulaa.com" in lines("apex.txt") and not lines("failed-sources.txt"))
(TMP / "config" / "self-hosted-programs.tsv").write_text("Bad line without tabs\n")
run("2026-11-25")
check("self-hosted: a malformed line warns, run stays green, last good copy is used",
      not lines("failed-sources.txt") and "spacey-ulaa.com" in lines("apex.txt") and "self-hosted-manual" in "\n".join(lines("stats.txt")))
(TMP / "config" / "self-hosted-programs.tsv").unlink()
run("2026-11-26")
check("self-hosted: without the file the source is 'skipped' and nothing is wrong",
      any(l.split()[:2] == ["self-hosted-manual", "skipped"] for l in lines("stats.txt") if l.split()) and not lines("failed-sources.txt"))

# ---- self-hosted pages (downloaded and read every day) and pasted page text (for pages a script cannot read)
(TMP / "config" / "self-hosted-pages.tsv").write_text(
    "Pagey VRP\thttps://selfpage.example.com/\tpaying\thttps://selfpage.example.com/scope\n"
    "JS VRP\thttps://selfjs.example.com/\tunknown\n")
(TMP / "config" / "self-hosted-text").mkdir(exist_ok=True)
(TMP / "config" / "self-hosted-text" / "pasted.txt").write_text(
    "# program: Pasted VRP\n# url: https://pasted.example.org/vrp\n# bounty: paying\n"
    "In scope\n- *.pasted-example.org\n- 93.184.216.0/24\n\nOut of scope\n- old.pasted-example.org\n")
run("2026-11-27")
check("self-hosted pages: a downloaded page gives targets (wildcard, url) and its out-of-scope list is an exclusion",
      "pagey-example-placeholder" not in lines("master.txt") and "selfpage-example.com" in lines("wildcards.txt") + lines("apex.txt")
      and any("selfpage-example.com/portal/api" in l for l in lines("urls.txt")) and "blog.selfpage-example.com" not in lines("master.txt"),
      str(lines("urls.txt")))
check("self-hosted pages: a page without readable text is a note on the source, not a failure",
      not lines("failed-sources.txt") and any("self-hosted-pages" in l and "JavaScript" in l for l in lines("stats.txt")), "\n".join(lines("stats.txt"))[:600])
check("self-hosted text: pasted page text is read with its header (program, bounty) and its exclusions",
      "pasted-example.org" in lines("wildcards.txt") + lines("apex.txt") and "93.184.216.0/24" in lines("ips.txt")
      and "old.pasted-example.org" not in lines("master.txt") and "Pasted VRP" in (TMP / "data" / "programs.txt").read_text(),
      str([l for l in lines("stats.txt") if "self-hosted" in l] + lines("rejected.txt") + lines("maybe.txt")))
for f in ("self-hosted-pages.tsv",):
    (TMP / "config" / f).unlink()
(TMP / "config" / "self-hosted-text" / "pasted.txt").unlink()

check("version: stats.json carries the project version from the VERSION file",
      json.loads((TMP / "data" / "stats.json").read_text()).get("version") == (REPO / "VERSION").read_text().strip())

# ---- one program = one entry, however the sources spell it
import update_bb_domains as _u
_reg = _u.ProgramRegistry()
for _n, _l in [("Yahoo", "https://hackerone.com/yahoo"), ("Yahoo", "https://hackerone.com/yahoo/policy_scopes"), ("Yahoo!", "https://www.hackerone.com/yahoo/"),
               ("Yahoo", "https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail"), ("Yahoo Bug Bounty", "https://www.intigriti.com/programs/yahoo/yahoobugbounty"),
               ("Yahoo Bug Bounty", ""), ("Other Co", "https://bugcrowd.com/engagements/other-co"), ("Other Co", "https://bugcrowd.com/other-co")]:
    _reg.see(_n, _l)
_reg.finish()
_c = {_reg.canon(_n, _l) for _n, _l in [("Yahoo", "https://hackerone.com/yahoo"), ("Yahoo!", "https://www.hackerone.com/yahoo/"), ("Yahoo", "https://hackerone.com/yahoo/policy_scopes")]}
_ci = {_reg.canon(_n, _l) for _n, _l in [("Yahoo", "https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail"), ("Yahoo Bug Bounty", ""), ("Yahoo Bug Bounty", "https://www.intigriti.com/programs/yahoo/yahoobugbounty")]}
check("programs: spellings of one program (url forms, www, slash, name variants, name-only rows) become ONE entry; two platforms stay two",
      len(_c) == 1 and len(_ci) == 1 and _c != _ci and len({_reg.canon("Other Co", "https://bugcrowd.com/engagements/other-co"), _reg.canon("Other Co", "https://bugcrowd.com/other-co")}) == 1,
      str((_c, _ci)))

# ---- a program that cannot be read today keeps its rows from the last good run (so it is not reported as "removed"), for a limited time
import directsources as _ds
_u = importlib.reload(_u)
_u.STATE.mkdir(parents=True, exist_ok=True)
_old = [("a.carry-example.com", "paying", "Carry Co", "https://carry.example/p1"), ("b.carry-example.com", "paying", "Fine Co", "https://carry.example/p2")]
_u.save_state("carrytest", _old)


def _partial_day():                                              # today only p2 could be read; p1 failed (and is named in CARRY)
    _ds.CARRY["carrytest"] = {"https://carry.example/p1"}
    _ds.NOTES["carrytest"] = "1 of 2 programs could not be read today"
    return [("b.carry-example.com", "paying", "Fine Co", "https://carry.example/p2")]


_w: list = []
_rows = _u.run_source("carrytest", _partial_day, [], [], optional=True, warnings=_w)
check("carry-over: the rows of a program that could not be read today are kept", len(_rows) == 2 and any(r[0] == "a.carry-example.com" for r in _rows), str(_rows))
check("carry-over: the day counter is stored", _u.load_carry("carrytest") == {"https://carry.example/p1": 1}, str(_u.load_carry("carrytest")))
for _day in range(_u.CARRY_DAYS):                                 # after CARRY_DAYS days in a row the program counts as removed
    _rows = _u.run_source("carrytest", _partial_day, [], [], optional=True, warnings=[])
check("carry-over: after too many days in a row the program is released (counts as removed)", all(r[0] != "a.carry-example.com" for r in _rows), str(_rows))
_u.save_carry("carrytest", {})

# ---- program history: appeared / left (after two runs) / returned / shrank / grew, silent on the first and on baseline runs
import proghistory as _ph
_sp, _ep = TMP / "hist-seen.tsv", TMP / "hist-events.tsv"
P = lambda k, n, c, srcs=("s1",): {"key": k, "id": "id" + k, "name": "Prog " + k, "url": "https://x.example/" + k, "count": c, "sources": srcs}   # noqa: E731
_ph.update(_sp, _ep, [P("a", 0, 100), P("b", 0, 5)], "2026-12-01", False, [])
check("history: the first run is silent (memory only)", not _ep.read_text().splitlines()[1:] if _ep.is_file() else True)
_e = _ph.update(_sp, _ep, [P("a", 0, 100), P("b", 0, 5), P("c", 0, 7)], "2026-12-02", False, [])
check("history: a new program 'appeared'", [x["event"] for x in _e] == ["appeared"] and _e[0]["id"] == "idc", str(_e))
_e = _ph.update(_sp, _ep, [P("a", 0, 30), P("c", 0, 7)], "2026-12-03", False, ["s1"])
check("history: one missing run is not yet 'left'; a drop to under half is 'shrank'", [x["event"] for x in _e] == ["shrank"], str(_e))
_e = _ph.update(_sp, _ep, [P("a", 0, 30), P("c", 0, 7)], "2026-12-03", False, ["s1"])
check("history: a second run on the same day changes nothing", _e == [], str(_e))
_e = _ph.update(_sp, _ep, [P("a", 0, 30), P("c", 0, 7)], "2026-12-04", False, ["s1"])
check("history: missing on two runs = 'left', and a source that did not answer is named", [x["event"] for x in _e] == ["left"] and "did not answer" in _e[0]["note"], str(_e))
_e = _ph.update(_sp, _ep, [P("a", 0, 30), P("b", 0, 5), P("c", 0, 7)], "2026-12-05", False, [])
check("history: a program that left and is listed again 'returned'", [x["event"] for x in _e] == ["returned"], str(_e))
_e = _ph.update(_sp, _ep, [P("a", 0, 90), P("b", 0, 5), P("c", 0, 7)], "2026-12-06", True, [])
check("history: baseline runs write no events", _e == [])
_e = _ph.update(_sp, _ep, [P("a", 0, 200), P("b", 0, 5), P("c", 0, 7)], "2026-12-07", False, [])
check("history: doubling is 'grew' (compared with the last run, even a baseline one)", [x["event"] for x in _e] == ["grew"], str(_e))
check("history: the event log is readable", len(_ph.read_events(_ep)) == 5 and _ph.read_events(_ep)[0]["event"] == "appeared", str(_ph.read_events(_ep)))

# ---- the all-time database
_arch = (TMP / "history" / "all-time.tsv").read_text().splitlines()
check("all-time database: written by the daily run, with every asset type and a header", _arch[0].startswith("asset\tvalue\tfirst_seen\tgone_on") and len(_arch) > 10)
check("all-time database: a value that disappeared stays, with the day it was gone", any(len(l.split("\t")) >= 6 and l.split("\t")[3] for l in _arch[1:]), "no row with a gone_on day")
import archive as _ar
_ap = TMP / "arch-test.tsv"
_ar.update(_ap, {("subdomains", "x.t.com"): ("non-paying", "P1"), ("apex", "t.com"): ("paying", "P1")}, "2026-12-01", False)
_ar.update(_ap, {("apex", "t.com"): ("paying", "P1")}, "2026-12-02", False)
_ar.update(_ap, {("apex", "t.com"): ("paying", "P1")}, "2026-12-03", False)
_ar.update(_ap, {("apex", "t.com"): ("paying", "P1"), ("subdomains", "x.t.com"): ("paying", "P2")}, "2026-12-04", False)
_ar.update(_ap, {}, "2026-12-05", True)
_rows = {tuple(l.split("\t")[:2]): l.split("\t")[2:] for l in _ap.read_text().splitlines()[1:]}
check("all-time database: first_seen kept, 'gone' cleared when a value returns, best bounty kept, nothing marked gone on a quiet run",
      _rows[("subdomains", "x.t.com")] == ["2026-12-01", "", "paying", "P2"] and _rows[("apex", "t.com")][1] == "", str(_rows))
_ar.update(_ap, {("apex", "t.com"): ("paying", "P1")}, "2026-12-06", False)
check("all-time database: a value missing on a normal run gets its gone_on day, and is never deleted",
      {tuple(l.split("\t")[:2]): l.split("\t")[3] for l in _ap.read_text().splitlines()[1:]}[("subdomains", "x.t.com")] == "2026-12-06")

# ---- old monthly unions are pruned (disk space), the current and previous month never
_u = importlib.reload(_u)
check("monthly pruning is OFF by default (a database of everything is kept forever)", _u.RETAIN_MONTHS == 0 and _u.prune_monthly() == 0)
_u.RETAIN_MONTHS = 12
for _mname in ("2020-01", "2025-06", "2026-10"):
    (_u.HIST / "monthly" / _mname).mkdir(parents=True, exist_ok=True)
(_u.HIST / "monthly" / "2020-01" / "x.txt").write_text("x")
_n = _u.prune_monthly()
check("monthly pruning: a folder older than the limit is deleted, recent ones stay", _n >= 1 and not (_u.HIST / "monthly" / "2020-01").exists() and (_u.HIST / "monthly" / "2026-10").exists(),
      str(sorted(p.name for p in (_u.HIST / "monthly").iterdir())))

# ---- a nearly full disk stops the run before anything is touched; stats.json reports the disk
_u = importlib.reload(_u)
_u.MIN_FREE_MB = 10 ** 9
check("disk guard: with too little free disk the run stops with exit code 1 and changes nothing", _u.main() == 1)
check("stats.json: reports the disk usage", set(json.loads((TMP / "data" / "stats.json").read_text()).get("disk", {})) == {"project_mb", "free_mb"})

# ---- a crashing parser must stop the run before anything is written (this happened on a Pi with Python 3.8: str.removeprefix)
import io
from contextlib import redirect_stdout
os.environ["BB_DATE"] = "2026-11-28"
os.environ["BB_BASELINE"] = ""
import update_bb_domains as m_crash
m_crash = importlib.reload(m_crash)
m_crash.fetch = fake_fetch
def _boom(raw, psl):
    raise AttributeError("'str' object has no attribute 'removeprefix'")
m_crash.scopeparse.parse_entry = _boom
_buf = io.StringIO()
with redirect_stdout(_buf):
    rc_crash = m_crash.main()
check("parser crash: the run stops (exit 1) with the cause named", rc_crash == 1 and "STOPPED" in _buf.getvalue() and "removeprefix" in _buf.getvalue(), _buf.getvalue()[-300:])
check("parser crash: nothing was written for that day", not (TMP / "history" / "daily" / "2026-11-28").exists())
importlib.reload(sys.modules["scopeparse"])                      # undo the patch for the following runs

# ---- monthly unions + pruning
check("monthly union written", (TMP / "history" / "monthly" / "2026-11" / "subdomains.txt").is_file() and (TMP / "history" / "monthly" / "2026-11" / "asn-paying.txt").is_file() and not list((TMP / "history" / "monthly" / "2026-11").glob("all-*")))
os.environ["BB_RETAIN_DAYS"] = "3"
run("2026-12-20")
left = sorted(p.name for p in (TMP / "history" / "daily").iterdir())
check("pruning keeps recent folders (newest two always)", "2026-12-20" in left and len(left) <= 3, str(left))

print("\nALL PASS" if ok else "\nSOME CHECKS FAILED")
if os.environ.get("SIM_KEEP"):                       # tests/test_site.py keeps the last project folder to build the website from it
    shutil.copytree(TMP, os.environ["SIM_KEEP"], dirs_exist_ok=True)
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0 if ok else 1)
