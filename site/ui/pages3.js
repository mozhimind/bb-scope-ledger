/* pages3.js - the Insights page: extra facts the site works out from the data (see site/insights.py), each with a plain list to pipe.
 * Every number links to something: a program, a list, or a filter, so the page is a place to start hunting from, not a report to read. */
"use strict";

route(/^\/insights\/?$/, "insights", async (view, _, q) => {
  view.innerHTML = '<div class="skeleton"></div><div class="skeleton"></div>';
  const ins = await jget("insights.json");
  const prog = (r, extra) => `<div class="row t-${r.bounty === "paying" ? "pay" : r.bounty === "unknown" ? "unk" : "free"}" data-href="#/program/${esc(r.slug)}" style="--cols:minmax(0,2fr) 130px 90px">
      <div><a class="name" href="#/program/${esc(r.slug)}">${esc(r.name)}</a></div><div class="c-x">${platBadge(r.platform)}</div><div class="num">${extra}</div></div>`;
  const progList = (rows, key, unit) => rows.length ? `<div class="ledger">${rows.map(r => prog(r, `${fmt(r[key])}`)).join("")}</div>` : emptyBox("Nothing yet", "This fills in after the first full run.");
  const maxT = Math.max(1, ...ins.tlds.map(t => t[1]));
  const kindWord = { storage: "storage", cdn: "CDN", paas: "app hosting", static: "static hosting", saas: "SaaS", api: "API", infra: "infrastructure" };
  const B = API_ABS("insights/");

  const svc = ins.services.length ? `<div class="ledger">
    <div class="row head" style="--cols:minmax(0,2fr) 110px 70px 150px"><div>Service</div><div>Kind</div><div class="num">Hosts</div><div>List</div></div>
    ${ins.services.map(s => `<div class="row ${s.lead ? "t-unk" : "t-free"}" style="--cols:minmax(0,2fr) 110px 70px 150px">
      <div><b>${esc(s.name)}</b>${s.lead ? ' <span class="badge warn" title="Names on this service can often be claimed by someone else when the DNS record is left behind">check DNS</span>' : ""}<div class="sub mono">${s.examples.map(esc).join(", ")}</div></div>
      <div class="c-x">${esc(kindWord[s.kind] || s.kind)}</div><div class="num c-x">${fmt(s.count)}</div>
      <div class="btn-row c-end"><a class="btn" href="${B}services/${esc(s.id)}.txt" target="_blank" rel="noopener" style="min-height:32px;padding:3px 10px">Plain list</a></div>
      <div class="meta"><span>${esc(kindWord[s.kind] || s.kind)}</span><span>${plural(s.count, "host")}</span></div></div>`).join("")}</div>`
    : emptyBox("No host on third-party hosting", "None of the in-scope hosts end in a known hosting service name.");

  const cols = (rows, empty) => rows.length ? rows.map(([n, c]) => `<div class="bar-row"><span class="bar-l mono">${esc(n)}</span><span class="bar-t"><i style="width:${Math.max(2, Math.round(c / (rows[0][1] || 1) * 100))}%"></i></span><span class="bar-n">${fmt(c)}</span></div>`).join("") : `<p class="muted">${esc(empty)}</p>`;

  const shared = ins.shared.length ? `<div class="ledger">${ins.shared.slice(0, 15).map(s => `<div class="row" style="--cols:minmax(0,1.4fr) minmax(0,2fr)">
      <div class="host">${esc(s.value)}</div><div class="progs" style="grid-column:auto;margin:0">${s.programs.map(p => `<a href="#/program/${esc(p.slug)}">${platBadge(p.platform)} ${esc(p.name)}</a>`).join("")}${s.count > s.programs.length ? `<span class="muted small">+${s.count - s.programs.length} more</span>` : ""}</div></div>`).join("")}</div>
    <p class="small muted" style="margin-top:8px">${fmt(ins.shared_total)} hosts in all. <a href="${B}shared-hosts.txt" target="_blank" rel="noopener">Plain list of all of them</a></p>`
    : emptyBox("No host is listed twice", "Each host belongs to one program.");

  const rv = ins.review || { no_target: [], duplicates: [], no_target_total: 0, duplicates_total: 0 };
  const review = (rv.no_target_total || rv.duplicates_total) ? `
    <h2 id="insights-review">Programs worth a look</h2>
    <p class="muted small">Places where the collector probably missed something. Open the program page, compare with what you see there, and tell me what is different so the parser can learn it.
      <a href="${B}programs-to-review.txt" target="_blank" rel="noopener">Plain list</a></p>
    ${rv.no_target_total ? `<h3>No testable target found (${fmt(rv.no_target_total)})</h3><div class="ledger">${rv.no_target.slice(0, 15).map(r => prog(r, fmt(r.values))).join("")}</div>${rv.no_target_total > 15 ? `<p class="small muted">First 15 shown. The plain list has all.</p>` : ""}` : ""}
    ${rv.duplicates_total ? `<h3>Possible duplicates (${fmt(rv.duplicates_total)})</h3><div class="ledger">${rv.duplicates.slice(0, 10).map(g => `<div class="row" style="--cols:minmax(0,1fr)"><div class="progs" style="grid-column:auto;margin:0">${g.map(p => `<a href="#/program/${esc(p.slug)}">${platBadge(p.platform)} ${esc(p.name)}</a>`).join("")}</div></div>`).join("")}</div>` : ""}` : "";
  const ip = ins.ip, ap = ins.apps || {};
  view.innerHTML = `
    <div class="page-head"><div><h1>Insights</h1><p>Facts worked out from the scope lists: where hosts live, which programs are big, what overlaps. A host in a list below is a lead to look at, not a finding.</p></div></div>
    <div class="glance">
      <a href="#/targets/subdomains"><div class="v">${fmt(ins.hosts)}</div><div class="l">distinct hosts in scope</div></a>
      <a href="#/insights?go=services"><div class="v">${fmt(ins.service_hosts)}</div><div class="l">on third-party hosting</div></a>
      <a href="#/insights?go=shared"><div class="v">${fmt(ins.shared_total)}</div><div class="l">listed by 2+ programs</div></a>
      <a href="#/targets/ips"><div class="v">${fmt(ip.addresses)}</div><div class="l">IP addresses covered</div></a>
      <a href="#/targets/apps"><div class="v">${fmt(Object.values(ap).reduce((a, b) => a + b, 0))}</div><div class="l">mobile apps</div></a>
      <a href="#/targets/github"><div class="v">${fmt(ins.github_org_total)}</div><div class="l">GitHub organisations</div></a>
    </div>

    <h2 id="insights-services">Third-party hosting</h2>
    <p class="muted small">In-scope hosts whose name ends in a hosting service. Look for DNS records that point at an unclaimed name (subdomain takeover) and for open storage.
      <a href="${B}services/dangling-leads.txt" target="_blank" rel="noopener">All "check DNS" hosts as one list</a></p>
    ${svc}

    <div class="cols2">
      <div><h2>Most used top-level domains</h2>${cols(ins.tlds, "No hosts yet.")}<p class="small muted">${fmt(ins.tld_total)} different endings.</p></div>
      <div><h2>GitHub organisations</h2>${cols(ins.github_orgs, "No GitHub scope listed.")}<p class="small muted">${fmt(ins.github_org_total)} organisations or users in all.</p></div>
    </div>

    <div class="cols2">
      <div><h2>Largest scopes</h2>${progList(ins.biggest, "assets")}</div>
      <div><h2>Most wildcards</h2>${progList(ins.wildcard_rich, "wildcards")}<p class="small muted">Wildcards are room to enumerate subdomains.</p></div>
    </div>

    ${review}
    <h2 id="insights-shared">Hosts listed by more than one program</h2>
    <p class="muted small">The programs overlap here. Check each program's rules before reporting: the same bug may be one report or two.</p>
    ${shared}

    <div class="cols2">
      <div><h2>Address space</h2>
        <dl class="kv"><dt>Single IPs</dt><dd>${fmt(ip.single_ips)}</dd><dt>Ranges (CIDR)</dt><dd>${fmt(ip.ranges)}</dd><dt>Addresses in total</dt><dd>${fmt(ip.addresses)}</dd><dt>IPv6 entries</dt><dd>${fmt(ip.ipv6)}</dd><dt>ASNs</dt><dd>${fmt(ip.asn)}</dd></dl>
        ${ip.largest.length ? `<h3>Largest ranges</h3><p class="mono small">${ip.largest.map(r => `${esc(r.range)} <span class="muted">(${fmt(r.addresses)})</span>`).join("<br>")}</p>` : ""}</div>
      <div><h2>Mobile apps</h2>
        <dl class="kv"><dt>App Store links</dt><dd>${fmt(ap.apple || 0)}</dd><dt>Google Play links</dt><dd>${fmt(ap.google || 0)}</dd><dt>Package / bundle ids</dt><dd>${fmt(ap.package || 0)}</dd><dt>Other</dt><dd>${fmt(ap.other || 0)}</dd></dl>
        <h2>Most exclusions</h2>${progList(ins.exclusions, "exclusions")}<p class="small muted">Read these programs' rules first: they rule out the most.</p></div>
    </div>`;
  applyIcons(view);
  if (q && q.go) { const t = view.querySelector("#insights-" + q.go); if (t) t.scrollIntoView(); }          // the tiles at the top jump to their section
}, "Insights");
