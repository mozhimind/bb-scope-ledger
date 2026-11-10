/* pages.js - Overview, Programs, Program detail, Targets.
 * Every page is  route(regex, navKey, async (view, [captured groups], query) => { view.innerHTML = ... }, "title")
 * Lists keep their filters in the URL (setQuery) and re-render only the results block when a filter changes. */
"use strict";

const ASSET_LABEL = { apex: "Apex domains", subdomains: "Subdomains", wildcards: "Wildcards", urls: "URLs", apis: "APIs", ips: "IPs and ranges", asn: "ASNs", github: "GitHub", "repos-other": "Other repos",
  apps: "Apps", patterns: "Patterns", "internal-hosts": "Internal hosts", maybe: "Maybe (guesses)" };
const assetLabel = a => ASSET_LABEL[a] || a;
const showValue = (asset, v) => (asset === "wildcards" ? "*." + v : v);
/** Program events (scripts/proghistory.py): the word for each kind and a one-line text with the numbers. */
const EVENT_WORD = { appeared: "New program", left: "Program left", returned: "Came back", shrank: "Shrank", grew: "Grew" };
const eventText = e => e.event === "appeared" ? `${fmt(e.count)} values. ${e.note}` : e.event === "left" ? `${fmt(e.previous)} values before. ${e.note}`
  : e.event === "returned" ? `${fmt(e.count)} values. ${e.note}` : `${fmt(e.previous)} to ${fmt(e.count)} values. ${e.note}`;
const API_ABS = p => BASE + p;                                  // absolute URL of an API file (what a tool needs)
const SELF = h => h === "self-hosted" || h === "both";

/* ======================================================================= Overview */
route(/^\/?$/, "home", async view => {
  const [st, hist, pj, latest] = await Promise.all([jget("stats.json"), jget("history.json"), jget("programs.json"), jget("changes/latest.json")]);
  const c = st.cards || {};
  const sumSeries = (key, skipWild) => hist.dates.map((_, i) => ASSETS_FOR_SUM(skipWild).reduce((a, k) => a + (hist.series[k]?.[key]?.[i] || 0), 0));
  const failed = st.failed || [], warns = st.warnings || [];
  const okCount = (st.sources || []).filter(s => s.status === "ok").length;

  const cell = (v, label, href, series) => `<a href="${href}"><div class="v">${fmt(v)}</div><div class="l">${esc(label)}</div>${series ? spark(series) : ""}</a>`;
  const glance = [
    cell(c.paying_programs, "programs that pay", "#/programs?bounty=paying", hist.programs.some(x => x) ? hist.programs : null),
    cell(c.free_programs, "programs without a bounty", "#/programs?bounty=non-paying"),
    cell(c.self_hosted_programs, "self-hosted programs", "#/programs?hosting=self"),
    cell(c.assets_total, "assets in scope", "#/targets", sumSeries("count", true)),
    cell(c.wildcards, "wildcards in scope", "#/targets/wildcards", hist.series.wildcards.count),
    cell(c.programs_with_new_scope, "programs with new scope", "#/changes", sumSeries("new", true)),
    cell(c.new_paying_today, "new today in paying programs", "#/changes?tab=paying"),
    cell(c.excluded_values, "values programs exclude", "#/targets/out-of-scope"),
    cell(c.programs_with_exclusions, "programs that list exclusions", "#/targets/out-of-scope"),
  ].join("");
  const progsAll = pj.programs, mine = watched();
  const platTotal = (st.platforms || []).reduce((a, p) => a + p.programs, 0) || 1;
  const shareBar = (st.platforms || []).length ? `<div class="share" role="img" aria-label="Programs per platform">${(st.platforms || []).map(p => `<a href="#/programs?platform=${esc(p.platform)}" style="flex:${p.programs};--h:${PLAT_HUE[p.platform] ?? 215}" title="${esc(platName(p.platform))}: ${fmt(p.programs)} programs"></a>`).join("")}</div>
    <p class="share-key small">${(st.platforms || []).map(p => `<span><i style="--h:${PLAT_HUE[p.platform] ?? 215}"></i>${esc(platName(p.platform))} ${Math.round(p.programs / platTotal * 100)}%</span>`).join("")}</p>` : "";
  const watchRows = progsAll.filter(p => mine.has(p.id)).sort((a, b) => b.new - a.new || a.name.localeCompare(b.name)).map(p => `
    <div class="row ${tick(p.bounty)}" data-href="#/program/${esc(p.slug)}" style="--cols:minmax(0,2.4fr) 130px 120px 70px 44px">
      <div><a class="name" href="#/program/${esc(p.slug)}">${esc(p.name)}</a><div class="sub">${esc(hostOf(p.url))}</div></div>
      <div class="c-x">${platBadge(p.platform)}</div><div class="c-x">${esc(bountyWord(p.bounty))}</div><div class="num c-x">${p.new ? `<span class="mk">${fmt(p.new)} new</span>` : "–"}</div>
      <div class="meta"><span>${esc(bountyWord(p.bounty))}</span>${p.new ? `<span class="mk">${fmt(p.new)} new</span>` : ""}</div>${starBtn(p.id, true)}</div>`).join("");

  const platRows = (st.platforms || []).map(p => `
    <a class="row" href="#/programs?platform=${esc(p.platform)}" style="--cols:minmax(0,1.5fr) 110px 100px 110px 100px 100px">
      <div class="name">${platBadge(p.platform)}</div>
      <div class="num c-x">${fmt(p.paying_programs)} <span class="muted">/ ${fmt(p.programs)}</span></div>
      <div class="num c-x">${fmt(p.assets)}</div><div class="num c-x">${fmt(p.paying_assets)}</div><div class="num c-x">${fmt(p.wildcards)}</div>
      <div class="num c-x">${p.new_assets ? `<span class="mk">${fmt(p.new_assets)}</span>` : "0"}</div>
      <div class="meta"><span>${fmt(p.paying_programs)} of ${fmt(p.programs)} programs pay</span><span>${fmt(p.assets)} assets</span>${p.new_assets ? `<span class="mk">${fmt(p.new_assets)} new</span>` : ""}</div>
    </a>`).join("");

  // asset table: the name is the link (a row cannot be one big link because it also holds the plain-list links)
  const assetRows = (st.assets || []).map(a => `
    <div class="row" style="--cols:minmax(0,1.6fr) 100px 100px 90px 90px 150px">
      <div><a class="name" href="#/targets/${esc(a.asset)}">${esc(assetLabel(a.asset))}</a><div class="sub">${esc((st.asset_info || {})[a.asset] || "")}</div></div>
      <div class="num c-x">${fmt(a.count)}</div><div class="num c-x">${fmt(a.paying)}</div>
      <div class="num c-x">${a.new ? `<span class="mk">+${fmt(a.new)}</span>` : (a.new == null ? "–" : "0")}</div><div class="num c-x">${a.removed ? "−" + fmt(a.removed) : (a.removed == null ? "–" : "0")}</div>
      <div class="c-x sub">${link(API_ABS("assets/" + a.asset + ".txt"), "all")} · ${link(API_ABS("assets/" + a.asset + "-paying.txt"), "paying")}</div>
      <div class="meta"><span>${fmt(a.count)} total</span><span>${fmt(a.paying)} pay</span>${a.new ? `<span class="mk">+${fmt(a.new)} new</span>` : ""}${a.removed ? `<span>−${fmt(a.removed)} removed</span>` : ""}</div>
    </div>`).join("");

  const pay = (latest.new_paying || []).slice(0, 8);
  const newList = pay.map(r => `<div class="row ${tick(r.bounty)}" style="--cols:minmax(0,2fr) 130px minmax(0,1.6fr)">
      <div class="host"><span class="mk">${esc(showValue(r.asset, r.host))}</span></div><div class="c-x"><span class="badge">${esc(assetLabel(r.asset))}</span></div>
      <div class="c-x sub">${esc(firstProg(r.programs))}</div><div class="meta"><span class="badge">${esc(assetLabel(r.asset))}</span><span>${esc(firstProg(r.programs))}</span></div></div>`).join("");

  view.innerHTML = `
    <section class="hero">
      <h1>Is it in scope?</h1>
      <p class="muted" style="margin-top:8px;max-width:60ch">Paste a host, URL or IP. The answer comes from ${fmt((st.sources || []).length)} sources: the bounty platforms and your own self-hosted list.</p>
      <div class="ask"><i data-ic="search"></i><input id="ask" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="app.example.com or 203.0.113.7" aria-label="Host, URL or IP to check"></div>
      <div class="ask-out" id="askOut" aria-live="polite"></div>
    </section>
    ${failed.length ? `<div class="notice bad"><b>${plural(failed.length, "source")} failed in the last run.</b> The lists below still contain the last good copy. <a href="#/sources">See what went wrong</a></div>` : ""}
    ${!failed.length && warns.length ? `<div class="notice warn"><b>${plural(warns.length, "warning")}</b> in the last run (${okCount} of ${(st.sources || []).length} sources ok). <a href="#/sources">Details</a></div>` : ""}

    <h2>Since the last run</h2>
    ${st.have_diffs === false ? `<div class="notice">No comparison today: ${esc(String(st.diff_note || "").replace(/: no diffs today$/, ""))}. The lists are complete, only the new and removed marks are missing.</div>`
      : `<p><b>${fmt(c.new_today)}</b> new and <b>${fmt(c.removed_today)}</b> removed assets (${esc(st.diff_note || "")}). <b>${fmt(c.new_paying_today)}</b> of the new ones are in programs that pay or whose bounty is unknown.</p>`}
    ${newList ? `<div class="ledger">${newList}</div><p style="margin-top:10px"><a href="#/changes">All changes of this run</a></p>` : ""}

    ${watchRows ? `<h2>Programs you watch</h2><div class="ledger" id="watchBox">${watchRows}</div>` : ""}

    <h2>At a glance</h2>
    <div class="glance">${glance}</div>

    <h2>By platform</h2>
    ${shareBar}
    <div class="ledger">
      <div class="row head" style="--cols:minmax(0,1.5fr) 110px 100px 110px 100px 100px"><div>Platform</div><div class="num">Paying / programs</div><div class="num">Assets</div><div class="num">Paying assets</div><div class="num">Wildcards</div><div class="num">New</div></div>
      ${platRows || emptyBox("No programs yet", "Run the daily script, then rebuild the site.")}
    </div>

    <h2>By asset type</h2>
    <div class="ledger">
      <div class="row head" style="--cols:minmax(0,1.6fr) 100px 100px 90px 90px 150px"><div>Asset type</div><div class="num">In scope</div><div class="num">Paying</div><div class="num">New</div><div class="num">Removed</div><div>Plain lists</div></div>
      ${assetRows}
    </div>`;

  /* the search box: loads the lists on first focus, answers while typing (one line), full page for several lines */
  const input = view.querySelector("#ask"), out = view.querySelector("#askOut");
  let idx = null;
  const run = async () => {
    const v = input.value.trim(); if (!v) { out.innerHTML = ""; return; }
    if (!idx) { out.innerHTML = '<p class="muted">Loading the lists (first time only)…</p>'; idx = await loadCheckIndex(); }
    const res = checkOne(idx, v);
    out.innerHTML = verdictHtml(res, { maxPrograms: 6 }) + (res.hits.length ? `<a class="small" href="#/check?q=${encodeURIComponent(v)}">Show every match</a>` : "");
  };
  input.addEventListener("focus", () => loadCheckIndex().then(i => (idx = i)).catch(() => {}), { once: true });
  input.addEventListener("input", debounce(run, 180));
  input.addEventListener("keydown", e => { if (e.key === "Enter" && input.value.trim()) location.hash = "#/check?q=" + encodeURIComponent(input.value.trim()); });
}, "Overview");

function ASSETS_FOR_SUM(skipWild) { return CHECK_ASSETS.filter(a => !(skipWild && a === "wildcards")); }
function firstProg(cell) { const p = String(cell || "").split("; ")[0]; return p + (String(cell || "").includes("; ") ? " …" : ""); }

/* ======================================================================= Programs */
route(/^\/programs\/?$/, "programs", async (view, _, q) => {
  const pj = await jget("programs.json"), progs = pj.programs;
  const plats = [...new Set(progs.map(p => p.platform))].sort();
  const S = { q: q.q || "", platform: q.platform || "", hosting: q.hosting || "", bounty: q.bounty || "", news: q.news === "1", mine: q.mine === "1", sort: q.sort || "name", page: +q.page || 0 };

  view.innerHTML = `
    <div class="page-head"><div><h1>${S.hosting === "self" ? "Self-hosted programs" : "Programs"}</h1>
      <p>${S.hosting === "self" ? "Programs a company runs on its own website instead of a platform. Their scope comes from your own list (config/self-hosted-programs.tsv)." : "Every program from every source, one line each. Open one to see its whole scope."}</p></div></div>
    <div class="filters">
      <input class="field search" id="fq" type="search" placeholder="Search by name or link" value="${esc(S.q)}" aria-label="Search programs">
      <select class="field" id="fp" aria-label="Platform"><option value="">All platforms</option>${plats.map(p => `<option value="${esc(p)}" ${S.platform === p ? "selected" : ""}>${esc(platName(p))}</option>`).join("")}</select>
      <div class="seg" role="group" aria-label="Where it is hosted">${[["", "All"], ["platform", "On a platform"], ["self", "Self-hosted"]].map(([v, l]) => `<button type="button" data-h="${v}" aria-pressed="${S.hosting === v}">${l}</button>`).join("")}</div>
      <select class="field" id="fb" aria-label="Bounty"><option value="">Any bounty</option><option value="paying" ${S.bounty === "paying" ? "selected" : ""}>Pays</option><option value="non-paying" ${S.bounty === "non-paying" ? "selected" : ""}>No bounty</option><option value="unknown" ${S.bounty === "unknown" ? "selected" : ""}>Bounty unknown</option></select>
      <label class="check"><input type="checkbox" id="fn" ${S.news ? "checked" : ""}> New scope today</label>
      <label class="check"><input type="checkbox" id="fm" ${S.mine ? "checked" : ""}> Watching</label>
      <select class="field" id="fs" aria-label="Sort"><option value="name">Sort: name</option><option value="size" ${S.sort === "size" ? "selected" : ""}>Sort: most assets</option><option value="new" ${S.sort === "new" ? "selected" : ""}>Sort: most new</option></select>
    </div>
    <div id="out"></div>`;

  const out = view.querySelector("#out");
  const mine = watched();
  function update() {
    const needle = S.q.trim().toLowerCase();
    let list = progs.filter(p =>
      (!needle || p.name.toLowerCase().includes(needle) || p.url.toLowerCase().includes(needle)) &&
      (!S.platform || p.platform === S.platform) &&
      (!S.hosting || (S.hosting === "self" ? SELF(p.hosting) : p.hosting === "platform")) &&
      (!S.bounty || p.bounty === S.bounty) && (!S.news || p.new > 0) && (!S.mine || mine.has(p.id)));
    list.sort(S.sort === "size" ? (a, b) => b.hosts - a.hosts || a.name.localeCompare(b.name) : S.sort === "new" ? (a, b) => b.new - a.new || a.name.localeCompare(b.name) : (a, b) => a.name.localeCompare(b.name));
    const pg = paginate(list.length, S.page, 50); S.page = pg.page;
    setQuery({ q: S.q, platform: S.platform, hosting: S.hosting, bounty: S.bounty, news: S.news ? "1" : "", mine: S.mine ? "1" : "", sort: S.sort === "name" ? "" : S.sort, page: S.page || "" });
    if (!list.length) { out.innerHTML = emptyBox(S.mine && !mine.size ? "You are not watching any program yet" : "No program matches", S.mine && !mine.size ? "Tap the star next to a program to keep it here and on the overview." : S.hosting === "self" && !progs.some(p => SELF(p.hosting)) ? "No self-hosted program is known yet. Add some to config/self-hosted-programs.tsv." : "Try removing a filter."); return; }
    out.innerHTML = `<div class="ledger"><div class="row head" style="--cols:minmax(0,2.4fr) 130px 120px 80px 70px 44px"><div>Program</div><div>Platform</div><div>Bounty</div><div class="num">Assets</div><div class="num">New</div><div></div></div>
      ${list.slice(pg.start, pg.end).map(p => `<div class="row ${tick(p.bounty)}" data-href="#/program/${esc(p.slug)}" style="--cols:minmax(0,2.4fr) 130px 120px 80px 70px 44px">
        <div><a class="name" href="#/program/${esc(p.slug)}">${esc(p.name)}</a> ${hostingBadge(p.hosting)}<div class="sub">${esc(hostOf(p.url))}</div></div>
        <div class="c-x">${platBadge(p.platform)}</div><div class="c-x">${esc(bountyWord(p.bounty))}</div><div class="num c-x">${fmt(p.hosts)}</div><div class="num c-x">${p.new ? `<span class="mk">${fmt(p.new)}</span>` : ""}</div>
        <div class="meta">${platBadge(p.platform)}<span>${esc(bountyWord(p.bounty))}</span><span>${plural(p.hosts, "asset")}</span>${p.excluded ? `<span>${fmt(p.excluded)} excluded</span>` : ""}${p.new ? `<span class="mk">${fmt(p.new)} new</span>` : ""}</div>${starBtn(p.id, mine.has(p.id))}</div>`).join("")}</div>${pg.html}`;
    out.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { S.page = +b.dataset.pg; update(); window.scrollTo(0, 0); }));
  }
  const on = (id, ev, fn) => view.querySelector(id).addEventListener(ev, fn);
  on("#fq", "input", debounce(e => { S.q = e.target.value; S.page = 0; update(); }));
  on("#fp", "change", e => { S.platform = e.target.value; S.page = 0; update(); });
  on("#fb", "change", e => { S.bounty = e.target.value; S.page = 0; update(); });
  on("#fn", "change", e => { S.news = e.target.checked; S.page = 0; update(); });
  on("#fm", "change", e => { S.mine = e.target.checked; S.page = 0; update(); });
  on("#fs", "change", e => { S.sort = e.target.value; S.page = 0; update(); });
  view.querySelectorAll("[data-h]").forEach(b => b.addEventListener("click", () => {
    S.hosting = b.dataset.h; S.page = 0; view.querySelectorAll("[data-h]").forEach(x => x.setAttribute("aria-pressed", String(x === b))); update();
  }));
  update();
  const again = () => { mine.clear(); watched().forEach(x => mine.add(x)); if (S.mine) update(); };
  view._onWatch = again;                                       // core.js calls it when a star is toggled; cleared on the next page change
}, "Programs");

function hostOf(u) { try { return new URL(u).host + (new URL(u).pathname.length > 1 ? new URL(u).pathname : ""); } catch (e) { return u || ""; } }

/* ======================================================================= One program */
route(/^\/program\/([^/]+)\/?$/, "programs", async (view, [slug], q) => {
  const p = await jget(`programs/${encodeURIComponent(slug)}.json`);
  const assets = Object.keys(p.scope).sort((a, b) => TARGET_ASSETS.indexOf(a) - TARGET_ASSETS.indexOf(b));
  // "All": every asset type of the program in one searchable list (the apis overlay repeats values, so it is not added again)
  const allRows = assets.filter(a => a !== "apis").flatMap(a => p.scope[a].map(([v, b]) => [v, b, a]));
  if (assets.length > 1) { p.scope.__all = allRows; assets.unshift("__all"); }
  const oos = p.out_of_scope || {};                              // what the program EXCLUDES: {asset: [values], text: [sentences]}
  const oosRows = [...CHECK_ASSETS.filter(a => oos[a]).flatMap(a => oos[a].map(v => [a, v])), ...(oos.text || []).map(v => ["text", v])];
  const tabs = oosRows.length ? [...assets, "__out"] : assets;
  let cur = q.asset === "out-of-scope" && oosRows.length ? "__out" : q.asset === "all" && p.scope.__all ? "__all" : q.asset && p.scope[q.asset] ? q.asset : (p.scope.__all ? "__all" : assets.includes("subdomains") ? "subdomains" : tabs[0]);
  let needle = q.q || "";

  view.innerHTML = `
    <p class="small"><a href="#/programs">Programs</a> / ${esc(platName(p.platform))}</p>
    <div class="page-head"><div><h1>${esc(p.name)}</h1>
      <div class="btn-row" style="margin-top:10px">${platBadge(p.platform)} ${hostingBadge(p.hosting)} <span class="badge ${p.bounty === "paying" ? "good" : ""}">${esc(bountyWord(p.bounty))}</span>${p.new ? ` <span class="badge new">${fmt(p.new)} new today</span>` : ""}</div></div>
      <div class="btn-row"><button type="button" class="btn star-btn" data-watch="${esc(p.id)}" aria-pressed="${watched().has(p.id)}">${icon("star")}<span class="on">Watching</span><span class="off">Watch</span></button>${/^https?:/.test(p.url) ? `<a class="btn primary" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${icon("ext")}Open program page</a>` : ""}<a class="btn" href="${esc(API_ABS("programs/" + p.slug + ".json"))}">${icon("code")}JSON</a></div></div>
    <dl class="kv">
      <dt>Program page</dt><dd>${link(p.url, p.url) || "–"}</dd>
      <dt>Listed by</dt><dd>${p.sources.map(s => `<span class="badge">${esc(s)}</span>`).join(" ") || "–"}</dd>
      ${p.self_urls && p.self_urls.length ? `<dt>Also self-hosted</dt><dd>${p.self_urls.map(u => link(u, u)).join("<br>")}</dd>` : ""}
      ${p.also_on ? `<dt>Also on</dt><dd>${esc(p.also_on)}</dd>` : ""}
      <dt>Assets</dt><dd>${plural(p.hosts, "value")} in ${plural(assets.filter(a => a !== "__all" && a !== "apis").length, "asset type")}${oosRows.length ? `, and ${plural(oosRows.length, "exclusion")}` : ""}</dd>
    </dl>
    ${(p.events || []).length ? `<h2>History</h2><div class="ledger">${p.events.slice(0, 8).map(e => `<div class="row" style="--cols:92px 90px minmax(0,1fr)"><div class="sub">${esc(e.date)}</div><div><span class="badge ${e.event === "left" || e.event === "shrank" ? "warn" : e.event === "appeared" || e.event === "returned" || e.event === "grew" ? "good" : ""}">${esc(EVENT_WORD[e.event] || e.event)}</span></div><div class="sub">${esc(eventText(e))}</div></div>`).join("")}</div>` : ""}
    <h2>Scope</h2>
    ${tabs.length ? `<div class="tabs" id="tabs" role="tablist">${tabs.map(a => a === "__out"
        ? `<button type="button" role="tab" class="oos" data-a="__out" aria-pressed="${a === cur}" title="What this program says is NOT in scope">Out of scope <span class="n">${fmt(oosRows.length)}</span></button>`
        : `<button type="button" role="tab" data-a="${esc(a)}" aria-pressed="${a === cur}">${a === "__all" ? "All" : esc(assetLabel(a))} <span class="n">${fmt(p.scope[a].length)}</span></button>`).join("")}</div>
      <div class="filters"><input class="field search" id="pq" type="search" placeholder="Filter this list" value="${esc(needle)}" aria-label="Filter scope values">
        <button type="button" class="btn" id="pcopy">${icon("copy")}Copy list</button><a class="btn" id="ptxt" href="#">${icon("down")}Plain list</a></div>
      <div id="pout"></div>` : emptyBox("No scope values", "This program was listed without a usable scope (for example only free text the parser could not read).")}`;
  if (!tabs.length) return;

  const pout = view.querySelector("#pout");
  function update() {
    if (cur === "__out") {                                       // the exclusions: assets first, then the plain-language ones
      const rows = oosRows.filter(([, v]) => !needle || v.toLowerCase().includes(needle.toLowerCase()));
      setQuery({ asset: "out-of-scope", q: needle });
      const link_ = view.querySelector("#ptxt"); link_.href = API_ABS(`programs/${p.slug}/out-of-scope.txt`); link_.target = "_blank";
      const shown = rows.slice(0, 500);
      pout.innerHTML = rows.length ? `<p class="small muted" style="margin:0 0 10px">The program says these are <b>not</b> in scope. Do not test them for this program.</p><div class="ledger">${shown.map(([a, v]) => `<div class="row t-out" style="--cols:minmax(0,1fr) 130px"><div class="${a === "text" ? "" : "host"} oos-v">${esc(showValue(a, v))}</div><div class="c-x"><span class="badge">${a === "text" ? "Written rule" : esc(assetLabel(a))}</span></div><div class="meta"><span class="badge">${a === "text" ? "Written rule" : esc(assetLabel(a))}</span></div></div>`).join("")}</div>
        <div class="pager"><span>${rows.length > 500 ? `First 500 of ${fmt(rows.length)}.` : plural(rows.length, "exclusion")}</span></div>` : emptyBox("Nothing matches", "Clear the filter to see all exclusions.");
      view._rows = rows.filter(([a]) => a !== "text").map(([a, v]) => [showValue(a, v)]); view._asset = "out";
      return;
    }
    view._asset = null;
    const rows = p.scope[cur].filter(([v]) => !needle || v.toLowerCase().includes(needle.toLowerCase()));
    setQuery({ asset: cur === "__all" ? "all" : cur === "subdomains" ? "" : cur, q: needle });
    view.querySelector("#ptxt").href = API_ABS(`programs/${p.slug}/${cur === "__all" ? "all" : cur}.txt`); view.querySelector("#ptxt").target = "_blank";
    const shown = rows.slice(0, 500);
    const isAll = cur === "__all";                               // the All list names each value's asset type; a single list does not need to
    pout.innerHTML = rows.length ? `<div class="ledger">${shown.map(([v, b, a]) => { const at = isAll ? a : cur; return `<div class="row ${tick(b)}" style="--cols:minmax(0,1fr) ${isAll ? "110px " : ""}120px"><div class="host">${/^https?:/.test(v) ? link(v, v) : esc(showValue(at, v))}</div>${isAll ? `<div class="c-x"><span class="badge">${esc(assetLabel(a))}</span></div>` : ""}<div class="sub c-x">${esc(bountyWord(b))}</div><div class="meta">${isAll ? `<span class="badge">${esc(assetLabel(a))}</span> ` : ""}${esc(bountyWord(b))}</div></div>`; }).join("")}</div>
      <div class="pager"><span>${rows.length > 500 ? `First 500 of ${fmt(rows.length)}. Use the plain list for all of them.` : plural(rows.length, "value")}</span></div>` : emptyBox("Nothing matches", "Clear the filter to see all values.");
    view._rows = rows;
  }
  view.querySelectorAll("#tabs [data-a]").forEach(b => b.addEventListener("click", () => { cur = b.dataset.a; view.querySelectorAll("#tabs [data-a]").forEach(x => x.setAttribute("aria-pressed", String(x === b))); update(); }));
  view.querySelector("#pq").addEventListener("input", debounce(e => { needle = e.target.value; update(); }));
  view.querySelector("#pcopy").addEventListener("click", () => copyText((view._rows || []).map(([v, , a]) => view._asset === "out" ? v : showValue(a || cur, v)).join("\n"), plural((view._rows || []).length, "value")));
  update();
}, "Program");

/* ======================================================================= Targets (one asset type at a time) */
/** Asset types the Targets "All" tab leaves out: apis repeats values that are already in subdomains / urls, maybe holds guesses. */
const ALL_SKIP = ["apis", "maybe"];

/** The row of asset-type tabs shared by the targets page and the exclusions page. */
function targetTabs(active, counts, excluded) {
  const allN = TARGET_ASSETS.filter(a => !ALL_SKIP.includes(a)).reduce((n, a) => n + (counts[a] || 0), 0);
  return `<div class="tabs" role="tablist"><a href="#/targets/all" ${active === "all" ? 'aria-current="true"' : ""} title="Every asset type in one searchable list (without the apis overlay and the maybe guesses)">All <span class="n">${fmt(allN)}</span></a>${TARGET_ASSETS.map(a => `<a href="#/targets/${a}" ${a === active ? 'aria-current="true"' : ""}>${esc(assetLabel(a))} <span class="n">${fmt(counts[a])}</span></a>`).join("")}
    <a href="#/targets/out-of-scope" class="oos" ${active === "out-of-scope" ? 'aria-current="true"' : ""} title="What programs say is NOT in scope">Out of scope <span class="n">${fmt(excluded)}</span></a></div>`;
}

route(/^\/targets(?:\/([a-z-]+))?\/?$/, "targets", async (view, [asset], q) => {
  if (asset === "out-of-scope") return exclusionsPage(view, q);
  asset = asset === "all" || TARGET_ASSETS.includes(asset) ? asset : "subdomains";
  const isAll = asset === "all";
  let sc;
  if (isAll) {                                                   // "All": the scope file of every asset type, merged; each row remembers its asset type (6th item)
    const parts = await Promise.all(TARGET_ASSETS.filter(a => !ALL_SKIP.includes(a)).map(a => jget(`scope/${a}.json`).then(d => ({ a, d }))));
    sc = { ...parts[0].d, rows: parts.flatMap(({ a, d }) => d.rows.map(r => [...r, a])) };
  }
  const [st, sc1, pj, latest] = await Promise.all([jget("stats.json"), isAll ? null : jget(`scope/${asset}.json`), jget("programs.json"), jget("changes/latest.json")]);
  if (!isAll) sc = sc1;
  const progs = pj.programs, counts = Object.fromEntries((st.assets || []).map(a => [a.asset, a.count]));
  const newSet = new Set((latest.new || []).filter(r => isAll || r.asset === asset).map(r => r.host));
  const plats = [...new Set(progs.map(p => p.platform))].sort();
  const S = { q: q.q || "", bounty: q.bounty || "", hosting: q.hosting || "", platform: q.platform || "", source: q.source || "", news: q.news === "1", sort: q.sort || "", page: +q.page || 0 };
  const BCODE = { paying: 0, "non-paying": 1, unknown: 2 };

  view.innerHTML = `
    <div class="page-head"><div><h1>Targets</h1><p>${isAll ? "Every asset type in one list, so one search finds a value wherever it is" : esc((st.asset_info || {})[asset] || "")}. Filter, copy, or download the result as a plain list for your tools.</p></div></div>
    ${targetTabs(asset, counts, (st.cards || {}).excluded_values)}
    <div class="filters">
      <input class="field search" id="tq" type="search" placeholder="Search values" value="${esc(S.q)}" aria-label="Search values">
      <div class="seg" role="group" aria-label="Bounty">${[["", "All"], ["paying", "Pays"], ["unknown", "Unknown"], ["non-paying", "No bounty"]].map(([v, l]) => `<button type="button" data-b="${v}" aria-pressed="${S.bounty === v}">${l}</button>`).join("")}</div>
      <select class="field" id="th" aria-label="Where hosted"><option value="">Any hosting</option><option value="platform" ${S.hosting === "platform" ? "selected" : ""}>On a platform</option><option value="self" ${S.hosting === "self" ? "selected" : ""}>Self-hosted</option></select>
      <select class="field" id="tp" aria-label="Platform"><option value="">All platforms</option>${plats.map(p => `<option value="${esc(p)}" ${S.platform === p ? "selected" : ""}>${esc(platName(p))}</option>`).join("")}</select>
      <select class="field" id="ts" aria-label="Source"><option value="">All sources</option>${sc.sources.map(s => `<option value="${esc(s)}" ${S.source === s ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <label class="check"><input type="checkbox" id="tn" ${S.news ? "checked" : ""}> New today</label>
      <select class="field" id="tz" aria-label="Sort"><option value="">Sort: A to Z</option><option value="programs" ${S.sort === "programs" ? "selected" : ""}>Sort: most programs</option><option value="sources" ${S.sort === "sources" ? "selected" : ""}>Sort: most sources</option></select>
    </div>
    <div class="btn-row" id="tact" style="margin-bottom:12px"></div>
    <div id="out"></div>`;

  const out = view.querySelector("#out"), act = view.querySelector("#tact");
  let matched = [];
  function update() {
    const needle = S.q.trim().toLowerCase(), srcI = S.source ? sc.sources.indexOf(S.source) : -1;
    matched = sc.rows.filter(r => {
      const [v, b, h, srcs, pidx] = r;
      if (needle && !v.toLowerCase().includes(needle)) return false;
      if (S.bounty && b !== BCODE[S.bounty]) return false;
      if (S.hosting && (S.hosting === "self" ? !(h === 1 || h === 2) : h !== 0)) return false;
      if (S.platform && !pidx.some(i => progs[i] && progs[i].platform === S.platform)) return false;
      if (srcI >= 0 && !srcs.includes(srcI)) return false;
      if (S.news && !newSet.has(v)) return false;
      return true;
    });
    if (S.sort === "programs") matched.sort((a, b) => b[4].length - a[4].length || (a[0] < b[0] ? -1 : 1));
    else if (S.sort === "sources") matched.sort((a, b) => b[3].length - a[3].length || (a[0] < b[0] ? -1 : 1));
    const pg = paginate(matched.length, S.page, 100); S.page = pg.page;
    setQuery({ q: S.q, bounty: S.bounty, hosting: S.hosting, platform: S.platform, source: S.source, news: S.news ? "1" : "", sort: S.sort, page: S.page || "" });
    const ready = readyApi();
    act.innerHTML = `<button type="button" class="btn" id="tcopy" ${matched.length ? "" : "disabled"}>${icon("copy")}Copy ${fmt(matched.length)}</button>
      <button type="button" class="btn" id="tdl" ${matched.length ? "" : "disabled"}>${icon("down")}Download .txt</button>
      ${ready ? `<a class="btn" target="_blank" href="${esc(ready)}">${icon("code")}Same list as API</a><button type="button" class="btn" data-copy="curl -s ${esc(ready)}" data-what="curl command">${icon("copy")}curl</button>` : ""}`;
    applyIcons(act);
    act.querySelector("#tcopy")?.addEventListener("click", () => copyText(matched.map(r => showValue(r[5] || asset, r[0])).join("\n"), plural(matched.length, "value")));
    act.querySelector("#tdl")?.addEventListener("click", () => downloadText(`${asset}${S.bounty ? "-" + S.bounty : ""}.txt`, matched.map(r => showValue(r[5] || asset, r[0])).join("\n") + "\n"));
    if (!matched.length) { out.innerHTML = emptyBox("Nothing matches", "Try clearing a filter."); return; }
    out.innerHTML = `<div class="ledger"><div class="row head" style="--cols:minmax(0,2fr) minmax(0,1.6fr) 130px 70px"><div>${isAll ? "Value (asset type in the detail)" : "Value"}</div><div>Programs</div><div>Bounty</div><div class="num">Sources</div></div>
      ${matched.slice(pg.start, pg.end).map((r, i) => rowHtml(r, pg.start + i)).join("")}</div>${pg.html}`;
    out.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { S.page = +b.dataset.pg; update(); window.scrollTo(0, 0); }));
    out.querySelectorAll(".row.click").forEach(el => el.addEventListener("click", e => { if (e.target.closest("a")) return; const d = el.querySelector(".detail"); d.hidden = !d.hidden; }));
  }
  /** The ready-made API file that holds exactly this list, when there is one (no free-text filter). */
  function readyApi() {
    if (S.q || S.hosting || S.source || S.news || (S.bounty && S.bounty !== "paying")) return "";
    if (isAll) return S.bounty || S.platform ? "" : API_ABS("assets/all.txt");      // all.txt = this very list (every asset type, without apis and maybe)
    const suffix = S.bounty === "paying" ? "-paying" : "";
    return S.platform ? API_ABS(`platforms/${S.platform}/${asset}${suffix}.txt`) : API_ABS(`assets/${asset}${suffix}.txt`);
  }
  function rowHtml(r) {
    const [v, b, h, srcs, pidx] = r, bounty = sc.bounty[b], pr = pidx.map(i => progs[i]).filter(Boolean);
    const names = pr.length ? esc(pr[0].name) + (pr.length > 1 ? ` <span class="muted">+${pr.length - 1}</span>` : "") : '<span class="muted">no program known</span>';
    return `<div class="row click ${tick(bounty)}" style="--cols:minmax(0,2fr) minmax(0,1.6fr) 130px 70px" tabindex="0">
      <div class="host">${newSet.has(v) ? `<span class="mk">${esc(showValue(r[5] || asset, v))}</span>` : esc(showValue(r[5] || asset, v))}${isAll ? ` <span class="badge">${esc(assetLabel(r[5]))}</span>` : ""}</div>
      <div class="c-x sub">${names}</div><div class="c-x">${esc(bountyWord(bounty))}</div><div class="num c-x">${srcs.length}</div>
      <div class="meta">${esc(bountyWord(bounty))}${selfBadge(sc.hosting[h])}<span>${names}</span></div>
      <div class="detail" hidden>
        <div><b>Programs</b></div><div class="progs" style="grid-column:auto">${pr.map(p => `<a href="#/program/${esc(p.slug)}">${platBadge(p.platform)} ${esc(p.name)}</a>`).join("") || '<span class="muted">The flat lists do not say which program it belongs to.</span>'}</div>
        <div><b>Sources</b> ${srcs.map(i => `<span class="badge">${esc(sc.sources[i])}</span>`).join(" ")}</div></div></div>`;
  }
  const on = (id, ev, fn) => view.querySelector(id).addEventListener(ev, fn);
  on("#tq", "input", debounce(e => { S.q = e.target.value; S.page = 0; update(); }));
  on("#th", "change", e => { S.hosting = e.target.value; S.page = 0; update(); });
  on("#tp", "change", e => { S.platform = e.target.value; S.page = 0; update(); });
  on("#ts", "change", e => { S.source = e.target.value; S.page = 0; update(); });
  on("#tn", "change", e => { S.news = e.target.checked; S.page = 0; update(); });
  on("#tz", "change", e => { S.sort = e.target.value; S.page = 0; update(); });
  view.querySelectorAll("[data-b]").forEach(b => b.addEventListener("click", () => { S.bounty = b.dataset.b; S.page = 0; view.querySelectorAll("[data-b]").forEach(x => x.setAttribute("aria-pressed", String(x === b))); update(); }));
  view.addEventListener("keydown", e => { if ((e.key === "Enter" || e.key === " ") && e.target.classList?.contains("click")) { e.preventDefault(); e.target.click(); } });
  update();
}, "Targets");


/* ======================================================================= Out of scope (what programs exclude) */
async function exclusionsPage(view, q) {
  const [st, ox, pj] = await Promise.all([jget("stats.json"), jget("out-of-scope.json").catch(() => ({ rows: [], text_entries: 0 })), jget("programs.json")]);
  const progs = pj.programs, counts = Object.fromEntries((st.assets || []).map(a => [a.asset, a.count]));
  const byAsset = {}; ox.rows.forEach(([a]) => { byAsset[a] = (byAsset[a] || 0) + 1; });
  const S = { q: q.q || "", asset: q.asset || "", page: +q.page || 0 };
  view.innerHTML = `
    <div class="page-head"><div><h1>Out of scope</h1><p>What programs say is <b>not</b> in scope, read from the same sources as the targets. Use it as an exclusion list, or let the scope check use it for you.</p></div></div>
    ${targetTabs("out-of-scope", counts, ox.rows.length)}
    ${ox.rows.length ? `<div class="filters">
      <input class="field search" id="xq" type="search" placeholder="Search excluded values" value="${esc(S.q)}" aria-label="Search excluded values">
      <select class="field" id="xa" aria-label="Asset type"><option value="">All asset types (${fmt(ox.rows.length)})</option>${CHECK_ASSETS.filter(a => byAsset[a]).map(a => `<option value="${esc(a)}" ${S.asset === a ? "selected" : ""}>${esc(assetLabel(a))} (${fmt(byAsset[a])})</option>`).join("")}</select>
    </div>
    <div class="btn-row" id="xact" style="margin-bottom:12px"></div><div id="out"></div>
    <p class="small muted" style="margin-top:14px">${fmt(ox.text_entries)} more exclusions are written as sentences (for example "social engineering"). They are listed on each program's page under <i>Out of scope</i>.</p>`
      : emptyBox("No exclusions yet", "They appear after the next daily run: the sources already carry them, this page just did not exist when the last run was made.")}`;
  if (!ox.rows.length) return;
  const out = view.querySelector("#out"), act = view.querySelector("#xact");
  let matched = [];
  function update() {
    const needle = S.q.trim().toLowerCase();
    matched = ox.rows.filter(([a, v]) => (!S.asset || a === S.asset) && (!needle || v.toLowerCase().includes(needle)));
    const pg = paginate(matched.length, S.page, 100); S.page = pg.page;
    setQuery({ q: S.q, asset: S.asset, page: S.page || "" });
    const ready = !S.q ? API_ABS(`out-of-scope/${S.asset || "master"}.txt`) : "";
    act.innerHTML = `<button type="button" class="btn" id="xcopy" ${matched.length ? "" : "disabled"}>${icon("copy")}Copy ${fmt(matched.length)}</button>
      <button type="button" class="btn" id="xdl" ${matched.length ? "" : "disabled"}>${icon("down")}Download .txt</button>
      ${ready ? `<a class="btn" target="_blank" href="${esc(ready)}">${icon("code")}Same list as API</a><button type="button" class="btn" data-copy="curl -s ${esc(ready)}" data-what="curl command">${icon("copy")}curl</button>` : ""}`;
    applyIcons(act);
    act.querySelector("#xcopy")?.addEventListener("click", () => copyText(matched.map(([a, v]) => showValue(a, v)).join("\n"), plural(matched.length, "value")));
    act.querySelector("#xdl")?.addEventListener("click", () => downloadText(`out-of-scope${S.asset ? "-" + S.asset : ""}.txt`, matched.map(([a, v]) => showValue(a, v)).join("\n") + "\n"));
    if (!matched.length) { out.innerHTML = emptyBox("Nothing matches", "Try clearing a filter."); return; }
    out.innerHTML = `<div class="ledger"><div class="row head" style="--cols:minmax(0,2fr) 130px minmax(0,1.6fr)"><div>Excluded value</div><div>Type</div><div>Excluded by</div></div>
      ${matched.slice(pg.start, pg.end).map(([a, v, pidx]) => {
        const pr = pidx.map(i => progs[i]).filter(Boolean);
        const names = pr.length ? esc(pr[0].name) + (pr.length > 1 ? ` <span class="muted">+${pr.length - 1}</span>` : "") : "";
        return `<div class="row click t-out" style="--cols:minmax(0,2fr) 130px minmax(0,1.6fr)" tabindex="0"><div class="host oos-v">${esc(showValue(a, v))}</div><div class="c-x"><span class="badge">${esc(assetLabel(a))}</span></div><div class="c-x sub">${names}</div>
          <div class="meta"><span class="badge">${esc(assetLabel(a))}</span><span>${names}</span></div>
          <div class="detail" hidden><div><b>Excluded by</b></div><div class="progs" style="grid-column:auto">${pr.map(p => `<a href="#/program/${esc(p.slug)}?asset=out-of-scope">${platBadge(p.platform)} ${esc(p.name)}</a>`).join("")}</div></div></div>`;
      }).join("")}</div>${pg.html}`;
    out.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { S.page = +b.dataset.pg; update(); window.scrollTo(0, 0); }));
    out.querySelectorAll(".row.click").forEach(el => el.addEventListener("click", e => { if (e.target.closest("a")) return; const d = el.querySelector(".detail"); d.hidden = !d.hidden; }));
  }
  view.querySelector("#xq").addEventListener("input", debounce(e => { S.q = e.target.value; S.page = 0; update(); }));
  view.querySelector("#xa").addEventListener("change", e => { S.asset = e.target.value; S.page = 0; update(); });
  view.addEventListener("keydown", e => { if ((e.key === "Enter" || e.key === " ") && e.target.classList?.contains("click")) { e.preventDefault(); e.target.click(); } });
  update();
}
