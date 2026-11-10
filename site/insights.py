"""insights.py - extra facts worked out from the data the daily run already produces (nothing new is downloaded).

Used by build_site.py, which writes the result to api/v1/insights.json and the lists to api/v1/insights/*.txt.

What it answers (each of these is something a hunter looks at when picking where to start):
  * services     which in-scope hosts (and url entries) sit on third-party hosting (S3, Heroku, GitHub Pages, Azure ...): the usual place to look for
                 dangling DNS / "subdomain takeover" and for open buckets. A host here is only a lead, not a finding.
  * tlds         which top-level domains the scope uses most
  * biggest      programs with the largest scope; wildcard_rich: programs with most wildcards (room to enumerate)
  * shared       hosts listed by two or more programs (one find may count twice, or the two programs overlap)
  * ip           how much address space the IP ranges cover; asn count
  * apps         mobile apps by store;  github: organisations with the most listed repositories
  * exclusions   programs with the most exclusions (read their rules first)
Standard library only; every function is pure (data in, data out), so tests can call it directly.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

# (id, label, kind, regex on the lowercase host, dangling-DNS lead?)
# "lead" = the service is one where an unclaimed name is often claimable by a stranger, so the host is worth a DNS check.
SERVICES: List[Tuple[str, str, str, str, bool]] = [
    ("aws-s3", "Amazon S3 (buckets)", "storage", r"(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$", True),
    ("aws-cloudfront", "Amazon CloudFront", "cdn", r"\.cloudfront\.net$", True),
    ("aws-elasticbeanstalk", "AWS Elastic Beanstalk", "paas", r"\.elasticbeanstalk\.com$", True),
    ("aws-elb", "AWS load balancers", "infra", r"\.elb(\.[a-z0-9-]+)?\.amazonaws\.com$", False),
    ("aws-apigw", "AWS API Gateway / Lambda URLs", "api", r"\.(execute-api|lambda-url)\.[a-z0-9-]+\.(on\.aws|amazonaws\.com)$", False),
    ("azure-websites", "Azure App Service", "paas", r"\.(azurewebsites|scm\.azurewebsites)\.net$", True),
    ("azure-blob", "Azure Blob / file storage", "storage", r"\.(blob|file|queue|table)\.core\.windows\.net$", True),
    ("azure-cloudapp", "Azure cloud apps / Traffic Manager", "infra", r"\.(cloudapp\.azure\.com|cloudapp\.net|trafficmanager\.net)$", True),
    ("azure-edge", "Azure Front Door / CDN", "cdn", r"\.(azurefd\.net|azureedge\.net)$", True),
    ("gcp-appspot", "Google App Engine / Cloud Run", "paas", r"\.(appspot\.com|run\.app)$", False),
    ("gcp-storage", "Google Cloud Storage", "storage", r"(^|\.)storage\.googleapis\.com$", True),
    ("firebase", "Firebase / Firebase Hosting", "paas", r"\.(firebaseapp\.com|web\.app|firebaseio\.com)$", True),
    ("heroku", "Heroku", "paas", r"\.(herokuapp\.com|herokudns\.com)$", True),
    ("github-pages", "GitHub Pages", "static", r"\.github\.io$", True),
    ("gitlab-pages", "GitLab Pages", "static", r"\.gitlab\.io$", True),
    ("netlify", "Netlify", "static", r"\.netlify\.(app|com)$", True),
    ("vercel", "Vercel", "static", r"\.vercel\.app$", False),
    ("cloudflare-pages", "Cloudflare Pages / Workers", "static", r"\.(pages|workers)\.dev$", False),
    ("digitalocean-spaces", "DigitalOcean Spaces / Apps", "storage", r"\.(digitaloceanspaces\.com|ondigitalocean\.app)$", True),
    ("shopify", "Shopify shops", "saas", r"\.myshopify\.com$", True),
    ("zendesk", "Zendesk help centres", "saas", r"\.zendesk\.com$", True),
    ("readthedocs", "Read the Docs", "static", r"\.readthedocs\.(io|org)$", True),
    ("ghost", "Ghost(Pro) blogs", "saas", r"\.ghost\.io$", True),
    ("statuspage", "Statuspage", "saas", r"\.statuspage\.io$", True),
    ("wordpress-com", "WordPress.com / WP Engine", "saas", r"\.(wordpress\.com|wpengine\.com|wpenginepowered\.com)$", True),
    ("surge", "Surge.sh", "static", r"\.surge\.sh$", True),
    ("fastly", "Fastly", "cdn", r"\.(fastly\.net|fastlylb\.net)$", True),
    ("akamai", "Akamai", "cdn", r"\.(akamaiedge|akamaized|edgekey|edgesuite)\.net$", False),
    ("salesforce", "Salesforce / Force.com", "saas", r"\.(force\.com|my\.salesforce\.com|salesforce-sites\.com)$", False),
    ("atlassian", "Atlassian cloud", "saas", r"\.(atlassian\.net|jira\.com|bitbucket\.io)$", True),
]
_COMPILED = [(i, l, k, re.compile(rx), lead) for i, l, k, rx, lead in SERVICES]
HOST_ASSETS = ("apex", "subdomains", "wildcards")


def _tld(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def _ip_numbers(values: List[str]) -> dict:
    ranges, singles, v6, total = [], 0, 0, 0
    for v in values:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            continue
        if net.version == 6:
            v6 += 1
            continue
        if net.num_addresses > 1:
            ranges.append((net.num_addresses, str(net)))
        else:
            singles += 1
        total += net.num_addresses
    ranges.sort(reverse=True)
    return {"single_ips": singles, "ranges": len(ranges), "ipv6": v6, "addresses": total,
            "largest": [{"range": r, "addresses": n} for n, r in ranges[:10]]}


def _app_store(v: str) -> str:
    s = v.lower()
    if "apps.apple.com" in s or "itunes.apple.com" in s:
        return "apple"
    if "play.google.com" in s:
        return "google"
    if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}", s):
        return "package"        # com.company.app: an Android package name or an iOS bundle id, the store is not stated
    return "other"


def compute(values: Dict[str, List[tuple]], programs: List[dict], value_programs: Dict[tuple, set], prog_oos: Dict[int, Dict[str, list]]):
    """values: asset -> [(value, bounty, hosting, sources)];  programs: the list written to programs.json (needs slug, name, platform, hosts, counts);
    value_programs: (asset, value) -> program indexes;  prog_oos: program index -> asset -> [excluded values].
    Returns (insights dict for insights.json, {relative path: [lines]} for the text files)."""
    texts: Dict[str, List[str]] = {}

    # --- top-level domains and third-party services, over every host-like value (each host counted once)
    hosts = sorted({v[0].lower() for a in HOST_ASSETS for v in values.get(a, [])})
    tlds = Counter(_tld(h) for h in hosts if _tld(h) and not _tld(h).isdigit())
    svc_hosts: Dict[str, set] = defaultdict(set)
    # (what is listed, the host to test): plain hosts, and url entries such as https://storage.googleapis.com/kubernetes-release,
    # which are exactly the "one bucket on a shared storage host" cases. The URL itself is what gets listed.
    probes = [(h, h) for h in hosts] + [(v[0], urlsplit(v[0]).hostname or "") for v in values.get("urls", [])]
    for shown, h in probes:
        for sid, _l, _k, rx, _lead in _COMPILED:
            if rx.search(h.lower()):
                svc_hosts[sid].add(shown)
                break
    services = []
    for sid, label, kind, _rx, lead in _COMPILED:
        hs = sorted(svc_hosts.get(sid, ()))
        if not hs:
            continue
        texts[f"insights/services/{sid}.txt"] = hs
        services.append({"id": sid, "name": label, "kind": kind, "lead": lead, "count": len(hs), "examples": hs[:3]})
    services.sort(key=lambda s: (-s["count"], s["name"]))
    texts["insights/services/dangling-leads.txt"] = sorted({h for sid, hs in svc_hosts.items() for h in hs if any(s[0] == sid and s[4] for s in SERVICES)})

    # --- programs
    def prog_ref(i: int) -> dict:
        p = programs[i]
        return {"slug": p["slug"], "name": p["name"], "platform": p["platform"], "bounty": p["bounty"]}
    order = sorted(range(len(programs)), key=lambda i: (-programs[i]["hosts"], programs[i]["name"]))
    biggest = [{**prog_ref(i), "assets": programs[i]["hosts"]} for i in order[:15] if programs[i]["hosts"]]
    wc_order = sorted(range(len(programs)), key=lambda i: (-programs[i]["counts"].get("wildcards", 0), programs[i]["name"]))
    wildcard_rich = [{**prog_ref(i), "wildcards": programs[i]["counts"].get("wildcards", 0)} for i in wc_order[:15] if programs[i]["counts"].get("wildcards", 0)]
    ex_order = sorted(prog_oos, key=lambda i: (-sum(len(v) for v in prog_oos[i].values()), programs[i]["name"]))
    exclusions = [{**prog_ref(i), "exclusions": sum(len(v) for v in prog_oos[i].values())} for i in ex_order[:15]]

    # --- programs worth a look: where the collector probably missed something, so a person (or a parser fix) should check the page
    #   no_target: the program has values, but none a tool can test (only maybe / internal hosts / patterns): the scope text was likely not understood
    #   duplicates: programs of ONE platform whose names are the same after removing case and punctuation: the merge in the collector missed a spelling
    weak = {"maybe", "internal-hosts", "patterns"}
    no_target = [i for i in order[::-1] if programs[i]["counts"] and set(programs[i]["counts"]) <= weak]
    no_target.sort(key=lambda i: (programs[i]["platform"], programs[i]["name"].lower()))
    by_norm: Dict[tuple, List[int]] = defaultdict(list)
    for i, p in enumerate(programs):
        by_norm[(p["platform"], re.sub(r"[^a-z0-9]+", "", p["name"].lower()))].append(i)
    dups = [idxs for (_pl, norm), idxs in sorted(by_norm.items()) if norm and len(idxs) > 1]
    review = {"no_target": [{**prog_ref(i), "values": programs[i]["hosts"], "url": programs[i]["url"]} for i in no_target[:100]], "no_target_total": len(no_target),
              "duplicates": [[{**prog_ref(i), "url": programs[i]["url"]} for i in idxs] for idxs in dups[:50]], "duplicates_total": len(dups)}
    texts["insights/programs-to-review.txt"] = [f"{programs[i]['name']}\t{programs[i]['url']}\tno testable target found (only maybe / internal / patterns)" for i in no_target] + \
        [f"{programs[i]['name']}\t{programs[i]['url']}\tpossible duplicate of another {programs[i]['platform']} program" for idxs in dups for i in idxs]

    # --- hosts that two or more programs list
    shared_rows = []
    for (asset, value), idxs in value_programs.items():
        if asset in HOST_ASSETS and len(idxs) >= 2:
            shared_rows.append((len(idxs), value, sorted(idxs)))
    shared_rows.sort(key=lambda r: (-r[0], r[1]))
    texts["insights/shared-hosts.txt"] = sorted({r[1] for r in shared_rows})
    shared = [{"value": v, "programs": [prog_ref(i) for i in idxs[:6]], "count": n} for n, v, idxs in shared_rows[:40]]

    # --- address space, apps, github
    ip = _ip_numbers([v[0] for v in values.get("ips", [])])
    ip["asn"] = len(values.get("asn", []))
    apps = Counter(_app_store(v[0]) for v in values.get("apps", []))
    orgs = Counter()
    for v in values.get("github", []):
        m = re.search(r"github\.com/([^/\s]+)", v[0].lower())
        if m:
            orgs[m.group(1)] += 1

    insights = {
        "hosts": len(hosts), "tlds": [[t, n] for t, n in tlds.most_common(15)], "tld_total": len(tlds),
        "services": services, "service_hosts": sum(s["count"] for s in services),
        "biggest": biggest, "wildcard_rich": wildcard_rich, "exclusions": exclusions,
        "shared": shared, "shared_total": len(shared_rows), "review": review,
        "ip": ip, "apps": dict(apps), "github_orgs": [[o, n] for o, n in orgs.most_common(15)], "github_org_total": len(orgs),
    }
    return insights, texts
