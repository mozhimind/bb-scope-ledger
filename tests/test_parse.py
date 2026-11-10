#!/usr/bin/env python3
"""Table-driven checks for scripts/scopeparse.py.  Run:  python3 tests/test_parse.py

CASES is a list of (raw entry, expected). Expected is either a set of (kind, value) pairs - exactly what the
parser must return, kinds as in scopeparse.Hit.kind - or a string: the reject reason. To teach the parser a new
form of entry, add a row here first (it fails), then change scopeparse.py until the whole table passes."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import scopeparse as sp  # noqa: E402
import update_bb_domains as ub  # noqa: E402

PSL = ub.PSL((REPO / "config" / "public_suffix_list.dat").read_text(encoding="utf-8"))

U, H, W, IP, GH, APP, PAT, INT, MAYBE, REPO_, ASN = "url", "host", "wildcard", "ip", "github", "app", "pattern", "internal", "maybe", "repo", "asn"

CASES = [
    # ---- URLs: a PATH is the scope, so it becomes a "url" and the host is NOT also stored as a host
    ("https://storage.googleapis.com/kubernetes-release/", {(U, "https://storage.googleapis.com/kubernetes-release")}),   # HackerOne "kubernetes": one bucket, not all of googleapis.com
    ("storage.googleapis.com/kubernetes-release", {(U, "https://storage.googleapis.com/kubernetes-release")}),            # no scheme -> https, same value (so the two spellings merge)
    ("http://app.example.com/admin", {(U, "http://app.example.com/admin")}),                                              # an explicit http is kept
    ("https://api.example.com:8443/v1/", {(U, "https://api.example.com:8443/v1")}),
    ("example.com/api/*", {(U, "https://example.com/api")}),                                                              # trailing /* = "and below", which a url already means
    ("*.example.com/path", {(U, "https://*.example.com/path")}),
    ("Example.COM/Path//Sub/", {(U, "https://example.com/Path/Sub")}),                                                    # host lowercased, path case kept, // collapsed
    ("https://example.com/{tenant}/api", {(U, "https://example.com/{tenant}/api")}),
    ("https://user@x.example.com/p", {(U, "https://x.example.com/p")}),
    ("http//x.example.com/a", {(U, "https://x.example.com/a")}),
    ("http://8.8.4.4/admin", {(U, "http://8.8.4.4/admin")}),
    ("https://www.example.com/", {(H, "www.example.com")}),                                                               # root only: still a host
    ("https://www.example.com/*", {(H, "www.example.com")}),
    ("https://example.com/?a=1", {(H, "example.com")}),
    ("https://*.example.com/*", {(W, "example.com")}),
    ("http://intranet.local/x", {(INT, "intranet.local")}),                                                               # internal hosts stay reference-only
    ("10.1.2.3/admin", {(INT, "10.1.2.3")}),
    ("https://github.com/org/repo", {(GH, "https://github.com/org/repo")}),                                               # GitHub / stores keep their own types
    # ---- clean forms (as before)
    ("example.com", {(H, "example.com")}),
    ("WWW.Example.COM.", {(H, "www.example.com")}),
    ("https://www.Example.com/path?x=1#f", {(U, "https://www.example.com/path")}),   # a path makes it a URL; query and fragment are dropped, host letter case lowered, path case kept
    ("example.com:8443", {(H, "example.com")}),
    ("example.com:*", {(H, "example.com")}),
    ("ftp://user:pass@ftp.example.com:21/dir", {(U, "ftp://ftp.example.com:21/dir")}),   # userinfo dropped, port and non-http scheme kept
    ("*.example.com", {(W, "example.com")}),
    ("*.example.com/*", {(W, "example.com")}),
    ("https://*.example.com:8080/x", {(U, "https://*.example.com:8080/x")}),
    ("bücher.de", {(H, "xn--bcher-kva.de")}),
    ("_dmarc.example.com", {(H, "_dmarc.example.com")}),
    ("www.bbc.co.uk", {(H, "www.bbc.co.uk")}),
    # ---- repairs (tier A, go into the real lists)
    ("fascc.gsa.gov)", {(H, "fascc.gsa.gov")}),
    ("(example.com)", {(H, "example.com")}),
    ('"example.com",', {(H, "example.com")}),
    ("<https://example.com/>", {(H, "example.com")}),
    ("hxxps://evil[.]example[.]com", {(H, "evil.example.com")}),
    ("api(.)example(.)com", {(H, "api.example.com")}),
    ("(*.)example.com", {(W, "example.com")}),
    ("**example.com**", {(H, "example.com")}),
    ("`example.com`", {(H, "example.com")}),
    ("[example.com](https://example.com/docs)", {(U, "https://example.com/docs")}),
    ("security@example.com", {(H, "example.com")}),
    ("@example.com", {(H, "example.com")}),
    ("http//example.com", {(H, "example.com")}),
    ("https:example.com", {(H, "example.com")}),
    ("a..example.com", {(H, "a.example.com")}),
    (".example.com", {(W, "example.com")}),
    ("example.com (main site)", {(H, "example.com")}),
    ("www.example.com - Web application", {(H, "www.example.com")}),
    ("api.example.com: REST API", {(H, "api.example.com")}),
    ("a.example.com, b.example.com", {(H, "a.example.com"), (H, "b.example.com")}),
    ("a.example.com and b.example.org", {(H, "a.example.com"), (H, "b.example.org")}),
    ("https://example.com/a https://example.org/b", {(U, "https://example.com/a"), (U, "https://example.org/b")}),
    ("*.example.com, *.example.net", {(W, "example.com"), (W, "example.net")}),
    ("Mega.co.nz", {(H, "mega.co.nz")}),
    ("transunion.co.br", {(H, "transunion.co.br")}),
    # ---- patterns and templates
    ("api-*.example.com", {(PAT, "api-*.example.com"), (H, "example.com")}),
    ("{tenant}.example.com", {(PAT, "*.example.com"), (H, "example.com")}),
    ("<customer>.app.example.com", {(PAT, "*.app.example.com"), (H, "app.example.com")}),
    ("*.api.*.example.com", {(PAT, "*.api.*.example.com"), (H, "example.com")}),
    ("*-staging.example.com", {(PAT, "*-staging.example.com"), (H, "example.com")}),
    ("example.*", {(PAT, "example.*")}),
    ("*.example.*", {(PAT, "*.example.*")}),
    # ---- ASNs
    ("AS16314", {(ASN, "AS16314")}),
    ("ASN 16314", {(ASN, "AS16314")}),
    ("AS6720 1/2", {(ASN, "AS6720")}),
    ("AS6720 IPv6 2/2", {(ASN, "AS6720")}),
    ("AS123 (Example Corp)", {(ASN, "AS123")}),
    ("AS1234, AS5678", {(ASN, "AS1234"), (ASN, "AS5678")}),
    ("AS 400 users guide", "free-text"),
    ("as1234.com", {(H, "as1234.com")}),
    ("AS0", "single-label"),
    # ---- IPs
    ("34.120.0.7", {(IP, "34.120.0.7")}),
    ("34.120.0.0/24", {(IP, "34.120.0.0/24")}),
    ("34.120.0.7:8443", {(IP, "34.120.0.7")}),
    ("https://34.120.0.7/login", {(U, "https://34.120.0.7/login")}),
    ("34.120.0.*", {(IP, "34.120.0.0/24")}),
    ("34.120.*.*", {(IP, "34.120.0.0/16")}),
    ("34.120.0.0-255", {(IP, "34.120.0.0/24")}),
    ("34.120.0.0 - 34.120.0.255", {(IP, "34.120.0.0/24")}),
    ("34.120.0.1-34.120.0.2", {(IP, "34.120.0.1"), (IP, "34.120.0.2")}),
    ("[2001:4860:4860::8888]:443", {(IP, "2001:4860:4860::8888")}),
    ("2001:4860::/32", {(IP, "2001:4860::/32")}),
    ("10.0.0.5", {(INT, "10.0.0.5")}),
    ("192.168.1.0/24", {(INT, "192.168.1.0/24")}),
    ("fd00::1", {(INT, "fd00::1")}),
    ("0.0.0.0/0", "ip-too-broad"),
    ("300.1.1.1", "bad-ip"),
    ("1.2.3.4.isp.example.com", {(H, "1.2.3.4.isp.example.com")}),
    # ---- apps, github, other repos
    ("https://play.google.com/store/apps/details?id=se.atg.live&hl=en&gl=SE", {(APP, "https://play.google.com/store/apps/details?id=se.atg.live")}),
    ("https://apps.apple.com/se/app/atg/id1434660322", {(APP, "https://apps.apple.com/app/id1434660322")}),
    ("https://marketplace.atlassian.com/apps/1218391/dependency-map?hosting=cloud", {(APP, "https://marketplace.atlassian.com/apps/1218391/dependency-map")}),
    ("app:com.Example.App", {(APP, "com.Example.App")}),
    # an app NAME with text around it: the store link or package id inside is kept; a bare name (no id) is still not an asset
    ("app:Klarna iOS App (com.klarna.app)", {(APP, "com.klarna.app")}),
    ("app:Android app - https://play.google.com/store/apps/details?id=com.coindesk.mobile", {(APP, "https://play.google.com/store/apps/details?id=com.coindesk.mobile")}),
    ("app:Cvent Mobile iOS -> https://apps.apple.com/us/app/onarrival/id680778967", {(APP, "https://apps.apple.com/app/id680778967")}),
    ("app:Roblox Client", set()),
    ("app:realestate.com.au Android App", set()),
    ("com.mtnghanar3", {(APP, "com.mtnghanar3")}),
    ("com.Example.MyApp", {(APP, "com.Example.MyApp")}),
    ("https://apps.apple.com", "store-host"),
    ("br.com.xp.carteira", {(APP, "br.com.xp.carteira")}),
    ("https://github.com/OmaCom/Omarchy-Docs.git/tree/main", {(GH, "https://github.com/omacom/omarchy-docs")}),
    ("github.com/some-org", {(GH, "https://github.com/some-org")}),
    ("https://gitlab.com/group/proj/-/tree/main", {(REPO_, "https://gitlab.com/group/proj")}),
    ("https://github.com/about", "not-a-project"),
    # ---- internal-looking hosts
    ("8x8hosts.internal", {(INT, "8x8hosts.internal")}),
    ("*.8x8hosts.internal", {(INT, "8x8hosts.internal")}),
    ("fe-maprics.tools.svc.cluster.local", {(INT, "fe-maprics.tools.svc.cluster.local")}),
    ("ahnleads-prod.aon.comcreate", {(INT, "ahnleads-prod.aon.comcreate")}),
    ("bose.xx", {(INT, "bose.xx")}),
    # ---- hosts hidden in text -> maybe (tier B)
    ("Swiss National Cyber Security Center (NCSC.ch)", {(MAYBE, "ncsc.ch")}),
    ("All subdomains of example.com are in scope", {(MAYBE, "example.com")}),
    ("Main app is app.example.com, API is api.example.org", {(MAYBE, "app.example.com"), (MAYBE, "api.example.org")}),
    # ---- real junk stays rejected
    ("all", "placeholder"),
    ("N/A", "placeholder"),
    # ---- groups of choices written in a short form (see scopeparse.expand_alternatives)
    ("*.nymhair.{com,co.uk,uk,}", {(W, "nymhair.com"), (W, "nymhair.co.uk"), (W, "nymhair.uk")}),
    ("*.olaplex.{cl,fi,nl,cz,sk,co.jp}", {(W, f"olaplex.{x}") for x in ("cl", "fi", "nl", "cz", "sk", "co.jp")}),
    ("(se|fi|uk).bingo.com", {(H, "se.bingo.com"), (H, "fi.bingo.com"), (H, "uk.bingo.com")}),
    ("*.doctolib.(fr|de|it|com|net)", {(W, f"doctolib.{x}") for x in ("fr", "de", "it", "com", "net")}),
    ("www.doctolib.(fr|de|it)", {(H, "www.doctolib.fr"), (H, "www.doctolib.de"), (H, "www.doctolib.it")}),
    ("https://www.decathlon.(hu|ro|com.tr)", {(H, "www.decathlon.hu"), (H, "www.decathlon.ro"), (H, "www.decathlon.com.tr")}),
    ("[it | fr | us | sg | …].louisvuitton.com", {(W, "louisvuitton.com")}),
    ("{a,b}.example.{com,net}", {(H, "a.example.com"), (H, "a.example.net"), (H, "b.example.com"), (H, "b.example.net")}),
    ("{tenant}.example.com", {(PAT, "*.example.com"), (H, "example.com")}),         # one name in braces = template, not choices
    ("example.com (a|b)", {(H, "example.com")}),                                     # remark after a space: not choices
    ("-", "placeholder"),
    ("co.uk", "public-suffix"),
    (".com", "single-label"),
    ("http(s).", "bad-chars"),
    ("Ember.js", "file-ext"),
    ("page.html", "file-ext"),
    ("example.123", "numeric-tld"),
    ("localhost", "single-label"),
    ("Rakuten Group, Inc.", "free-text"),
    ("NOS Comunicações S.A.", "free-text"),
    ("Any resource created or accessed with the Cloud on eu-west-2", "free-text"),
    ("U.S. Securities and Exchange Commission", "free-text"),
    ("-bad-.example.com", "bad-label"),
]

fail = 0
for raw, expected in CASES:
    p = sp.parse_entry(raw, PSL)
    if isinstance(expected, str):
        ok = (not p.hits) and p.reject == expected
        got = f"reject={p.reject!r} hits={[(h.kind, h.value) for h in p.hits]}"
    else:
        got_set = {(h.kind, h.value) for h in p.hits}
        ok = got_set == expected
        got = str(sorted(got_set)) + ("" if not p.reject else f" reject={p.reject}")
    if not ok:
        fail += 1
        print(f"FAIL  {raw!r}\n      expected {expected}\n      got      {got}")
print(f"\n{len(CASES) - fail}/{len(CASES)} parse cases passed")
sys.exit(1 if fail else 0)
