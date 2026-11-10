/* pages2.js - Changes, Check scope, Sources, API documentation. (pages.js has Overview, Programs, Targets.) */
"use strict";

/* ======================================================================= Changes */
route(/^\/changes(?:\/(\d{4}-\d{2}-\d{2}))?\/?$/, "changes", async (view, [date], q) => {
  const [st, index, latest, pj] = await Promise.all([jget("stats.json"), jget("changes/index.json"), jget("changes/latest.json"), jget("programs.json")]);
  const days = index.days;                                          // newest first
  if (!days.length && !(latest.new || []).length && !(latest.removed || []).length) {
    view.innerHTML = `<div class="page-head"><h1>Changes</h1></div>${emptyBox("No history yet", "After the second daily run this page lists what was added and removed each day.")}`; return;
  }
  date = date || (days[0] && days[0].date) || st.date;
  const isLatest = date === st.date;
  const day = isLatest ? { date, note: latest.note, baseline: st.have_diffs === false, new: latest.new || [], removed: latest.removed || [], new_paying: latest.new_paying || [], programs: latest.programs || [] }
    : await jget(`changes/${date}.json`);
  if (!day.new_paying) day.new_paying = day.new.filter(r => r.bounty !== "non-paying");
  const slugByName = new Map(); pj.programs.forEach(p => { if (!slugByName.has(p.name)) slugByName.set(p.name, p.slug); });
  const S = { tab: q.tab || "new", asset: q.asset || "", q: q.q || "", page: +q.page || 0 };

  const chron = [...days].reverse().slice(-45), peak = Math.max(1, ...chron.map(d => d.new + d.removed));
  view.innerHTML = `
    <div class="page-head"><div><h1>Changes</h1><p>What appeared and what disappeared between two daily runs. Newest assets are marked like this: <span class="mk">example.com</span></p></div>
      <div class="btn-row"><a class="btn" href="${esc(API_ABS("feeds/new-paying.txt"))}" target="_blank">${icon("code")}New (paying) as list</a></div></div>
    <div class="days" role="group" aria-label="Pick a day">${chron.map(d => `<button type="button" data-d="${d.date}" aria-pressed="${d.date === date}" title="${d.date}: ${fmt(d.new)} new, ${fmt(d.removed)} removed${d.baseline ? " (no comparison that day)" : ""}">
      <i class="n" style="height:${Math.round(d.new / peak * 56)}px"></i><i class="r" style="height:${Math.round(d.removed / peak * 56)}px"></i></button>`).join("")}</div>
    <p class="small muted" style="margin:-8px 0 14px">Last ${chron.length} runs, oldest on the left: <span class="mk">yellow</span> new, <span style="color:var(--bad)">red</span> removed. Click a bar to open that day.</p>
    <p><b>${esc(date)}</b>${isLatest ? ' <span class="badge acc">latest run</span>' : ""} ${day.baseline ? "" : `<span class="muted">${fmt(day.new.length)} new, ${fmt(day.removed.length)} removed</span>`}</p>
    ${day.baseline ? `<div class="notice">There is no comparison for this day${day.note ? `: ${esc(String(day.note).replace(/: no diffs today$/, ""))}` : ""}. The lists were complete, but nothing can be called new or removed.</div>` : ""}
    <div class="tabs" id="ctabs" role="tablist"></div>
    <div class="filters"><input class="field search" id="cq" type="search" placeholder="Search host, program or entry" value="${esc(S.q)}" aria-label="Search changes"><select class="field" id="ca" aria-label="Asset type"></select><button type="button" class="btn" id="ccopy">${icon("copy")}Copy hosts</button></div>
    <div id="out"></div>`;

  const progEvents = day.programs || [];
  const sets = () => ({ new: day.new, paying: day.new_paying, removed: day.removed, programs: progEvents });
  const out = view.querySelector("#out");
  function update() {
    const all = sets()[S.tab] || [];
    view.querySelector("#ctabs").innerHTML = [["new", "New"], ["paying", "New, paying or unknown"], ["removed", "Removed"], ["programs", "Programs"]].map(([k, l]) =>
      `<button type="button" data-t="${k}" aria-pressed="${S.tab === k}">${l} <span class="n">${fmt(sets()[k].length)}</span></button>`).join("");
    view.querySelectorAll("#ctabs [data-t]").forEach(b => b.addEventListener("click", () => { S.tab = b.dataset.t; S.page = 0; update(); }));
    if (S.tab === "programs") {                                     // program events of the day: appeared / left / returned / shrank / grew
      view.querySelector(".filters").hidden = true;
      setQuery({ tab: "programs" });
      out.innerHTML = progEvents.length ? `<p class="small muted">Programs that appeared, left, came back, or changed a lot in size on this day. A program counts as "left" only after it was missing on two runs in a row.</p><div class="ledger">${
        [...progEvents].sort((a, b) => ["left", "shrank", "appeared", "returned", "grew"].indexOf(a.event) - ["left", "shrank", "appeared", "returned", "grew"].indexOf(b.event) || a.program.localeCompare(b.program)).map(e =>
        `<div class="row" style="--cols:110px minmax(0,1.4fr) minmax(0,2fr)"><div><span class="badge ${e.event === "left" || e.event === "shrank" ? "warn" : e.event === "appeared" || e.event === "returned" || e.event === "grew" ? "good" : ""}">${esc(EVENT_WORD[e.event] || e.event)}</span></div>
          <div class="host">${e.slug ? `<a href="#/program/${esc(e.slug)}">${esc(e.program)}</a>` : esc(e.program)}</div><div class="sub">${esc(eventText(e))}</div></div>`).join("")}</div>`
        : emptyBox("No program events", day.baseline ? "No comparison on baseline days." : "No program appeared, left, came back or changed a lot in size on this day.");
      return;
    }
    view.querySelector(".filters").hidden = false;
    const counts = {}; all.forEach(r => counts[r.asset] = (counts[r.asset] || 0) + 1);
    const sel = view.querySelector("#ca");
    sel.innerHTML = `<option value="">All asset types (${fmt(all.length)})</option>` + Object.keys(counts).sort().map(a => `<option value="${esc(a)}" ${S.asset === a ? "selected" : ""}>${esc(assetLabel(a))} (${fmt(counts[a])})</option>`).join("");
    const needle = S.q.trim().toLowerCase();
    const rows = all.filter(r => (!S.asset || r.asset === S.asset) && (!needle || (r.host + " " + r.programs + " " + r.raw).toLowerCase().includes(needle)));
    const pg = paginate(rows.length, S.page, 60); S.page = pg.page;
    setQuery({ tab: S.tab === "new" ? "" : S.tab, asset: S.asset, q: S.q, page: S.page || "" });
    view._hosts = rows.map(r => showValue(r.asset, r.host));
    if (!rows.length) { out.innerHTML = day.baseline ? "" : emptyBox(S.tab === "removed" ? "Nothing was removed" : "Nothing new", needle || S.asset ? "No change matches the filter." : "The sources did not change between these two runs."); return; }
    out.innerHTML = `<div class="ledger"><div class="row head" style="--cols:minmax(0,2fr) 120px minmax(0,2fr)"><div>Value</div><div>Type</div><div>Program</div></div>
      ${rows.slice(pg.start, pg.end).map(r => {
        const names = String(r.programs || "").replace(/\s*\(\+\d+ more\)\s*$/, "").split("; ").filter(Boolean);
        const progLinks = names.map(n => slugByName.has(n) ? `<a href="#/program/${esc(slugByName.get(n))}">${esc(n)}</a>` : esc(n)).join(", ");
        const urls = String(r.program_urls || "").split("; ").filter(Boolean);
        return `<div class="row click ${tick(r.bounty)}" style="--cols:minmax(0,2fr) 120px minmax(0,2fr)" tabindex="0">
          <div class="host">${S.tab === "removed" ? esc(showValue(r.asset, r.host)) : `<span class="mk">${esc(showValue(r.asset, r.host))}</span>`}</div>
          <div class="c-x"><span class="badge">${esc(assetLabel(r.asset))}</span></div><div class="c-x sub">${esc(names[0] || "no program known")}${names.length > 1 ? ` <span class="muted">+${names.length - 1}</span>` : ""}</div>
          <div class="meta"><span class="badge">${esc(assetLabel(r.asset))}</span><span>${esc(bountyWord(r.bounty))}</span><span>${esc(names[0] || "")}</span></div>
          <div class="detail" hidden><div><b>${esc(bountyWord(r.bounty))}</b>${r.last_seen_in ? ` · last seen in ${esc(r.last_seen_in)}` : ""}</div>
            ${r.why ? `<div><b>Why removed</b> ${esc(r.why)}</div>` : ""}
            ${progLinks ? `<div><b>Programs</b> ${progLinks}</div>` : ""}${urls.length ? `<div><b>Pages</b> ${urls.map(u => link(u, u)).join(" ")}</div>` : ""}
            ${r.sources ? `<div><b>Sources</b> ${String(r.sources).split(",").map(s => `<span class="badge">${esc(s)}</span>`).join(" ")}</div>` : ""}
            ${r.raw ? `<div><b>Entry as written</b></div><div class="raw">${esc(r.raw)}</div>` : ""}</div></div>`;
      }).join("")}</div>${pg.html}`;
    out.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { S.page = +b.dataset.pg; update(); window.scrollTo(0, 0); }));
    out.querySelectorAll(".row.click").forEach(el => el.addEventListener("click", e => { if (e.target.closest("a")) return; const d = el.querySelector(".detail"); d.hidden = !d.hidden; }));
    view.querySelector("#ca").onchange = e => { S.asset = e.target.value; S.page = 0; update(); };
  }
  view.querySelectorAll(".days [data-d]").forEach(b => b.addEventListener("click", () => { location.hash = "#/changes/" + b.dataset.d; }));
  view.querySelector("#cq").addEventListener("input", debounce(e => { S.q = e.target.value; S.page = 0; update(); }));
  view.querySelector("#ccopy").addEventListener("click", () => copyText([...new Set(view._hosts || [])].join("\n"), plural((view._hosts || []).length, "value")));
  view.addEventListener("keydown", e => { if ((e.key === "Enter" || e.key === " ") && e.target.classList?.contains("click")) { e.preventDefault(); e.target.click(); } });
  update();
}, "Changes");

/* ======================================================================= Check scope (many lines) */
route(/^\/check\/?$/, "check", async (view, _, q) => {
  view.innerHTML = `
    <div class="page-head"><div><h1>Check scope</h1><p>One host, URL or IP per line. Wildcards, patterns, IP ranges and GitHub projects are taken into account. Nothing leaves your browser.</p></div></div>
    <textarea class="field" id="cin" spellcheck="false" autocapitalize="off" placeholder="app.example.com&#10;https://api.example.org/v1/login&#10;203.0.113.7&#10;https://github.com/example/repo" aria-label="Hosts, URLs or IPs to check">${esc(q.q || "")}</textarea>
    <div class="btn-row" style="margin:10px 0 18px"><button type="button" class="btn primary" id="cgo">Check</button><button type="button" class="btn" id="cexp" disabled>${icon("copy")}Copy results as table</button></div>
    <div class="chips" id="recent"></div>
    <div id="out" aria-live="polite"></div>`;
  const out = view.querySelector("#out"), cin = view.querySelector("#cin");
  let last = [];
  /* the last few checks are remembered in this browser only, so a host checked yesterday is one tap away */
  const RKEY = "sl-recent";
  const recent = () => { try { return JSON.parse(localStorage.getItem(RKEY) || "[]").filter(x => typeof x === "string").slice(0, 8); } catch (e) { return []; } };
  const remember = lines => { try { const list = [lines.join("\n"), ...recent().filter(x => x !== lines.join("\n"))].slice(0, 8); localStorage.setItem(RKEY, JSON.stringify(list)); } catch (e) { /* storage blocked */ } paintRecent(); };
  function paintRecent() {
    const box = view.querySelector("#recent"), list = recent();
    box.innerHTML = list.length ? `<span class="small muted">Recent:</span> ` + list.map((t, i) => `<button type="button" class="chip" data-r="${i}" title="${esc(t)}">${esc(t.split("\n")[0].slice(0, 38))}${t.includes("\n") ? " +" + (t.split("\n").length - 1) : ""}</button>`).join("") + ` <button type="button" class="chip quiet" id="rclear">Clear</button>` : "";
    box.querySelectorAll("[data-r]").forEach(b => b.addEventListener("click", () => { cin.value = recent()[+b.dataset.r] || ""; go(); }));
    box.querySelector("#rclear")?.addEventListener("click", () => { try { localStorage.removeItem(RKEY); } catch (e) { /* ignore */ } paintRecent(); });
  }
  async function go() {
    const lines = [...new Set(cin.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean))].slice(0, 500);
    setQuery({ q: lines.length === 1 ? lines[0] : "" });
    if (!lines.length) { out.innerHTML = emptyBox("Nothing to check", "Paste one or more hosts above."); return; }
    out.innerHTML = '<p class="muted" id="prog">Loading the lists…</p>';
    const idx = await loadCheckIndex((d, t) => { const el = out.querySelector("#prog"); if (el) el.textContent = `Loading the lists… ${d} of ${t}`; });
    last = lines.map(l => checkOne(idx, l));
    const n = last.reduce((a, r) => (a[r.level] = (a[r.level] || 0) + 1, a), {});
    out.innerHTML = `<p><b>${fmt(n.yes || 0)}</b> in scope, <b>${fmt(n.out || 0)}</b> excluded, <b>${fmt(n.maybe || 0)}</b> unsure, <b>${fmt(n.none || 0)}</b> not found.</p>` + last.map(r => verdictHtml(r, { maxPrograms: 10 })).join("");
    remember(lines);
    view.querySelector("#cexp").disabled = false;
  }
  view.querySelector("#cgo").addEventListener("click", go);
  cin.addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  view.querySelector("#cexp").addEventListener("click", () => copyText("input\tresult\tbounty\tprograms\n" + last.map(r => [r.q.raw, r.level === "yes" ? "in scope" : r.level === "out" ? "excluded" : r.level === "maybe" ? "unsure" : "not found",
    r.hits.some(h => h.bounty === "paying") ? "pays" : r.hits.length ? "no/unknown" : "", [...new Set(r.hits.flatMap(h => h.programs.map(p => p.name)))].slice(0, 5).join("; ")].join("\t")).join("\n"), "results"));
  paintRecent();
  if (q.q) go();
  else cin.focus();
}, "Check scope");

/* ======================================================================= Sources and parser quality */
route(/^\/sources\/?$/, "sources", async view => {
  const [st, src] = await Promise.all([jget("stats.json"), jget("sources.json")]);
  const cls = s => (/ok/.test(s) ? "good" : /carried|stale/.test(s) ? "warn" : /FAIL|unavailable/.test(s) ? "bad" : "");
  const rules = Object.entries(st.recovered || {}), reasons = Object.entries(st.rejected || {});
  const maxR = Math.max(1, ...rules.map(x => x[1])), maxJ = Math.max(1, ...reasons.map(x => x[1]));
  const bars = (list, max) => list.map(([k, n]) => `<div class="row" style="--cols:minmax(0,1fr) 70px 120px"><div class="name">${esc(k)}</div><div class="num">${fmt(n)}</div><div class="c-x"><div class="bar"><i class="b-pay" style="width:${Math.round(n / max * 100)}%"></i></div></div></div>`).join("");
  view.innerHTML = `
    <div class="page-head"><div><h1>Sources</h1><p>Where the data comes from and whether today's download worked. Sources ending in <code>-direct</code> are read from the platform itself; the others are mirrors.</p></div></div>
    ${(src.failed || []).length ? `<div class="notice bad"><b>Failed:</b><br>${src.failed.map(esc).join("<br>")}</div>` : ""}
    ${(src.warnings || []).length ? `<div class="notice warn"><b>Warnings (the run stayed green):</b><br>${src.warnings.map(esc).join("<br>")}</div>` : ""}
    ${!(src.failed || []).length && !(src.warnings || []).length ? '<div class="notice good"><b>All sources are healthy.</b></div>' : ""}
    <div class="ledger"><div class="row head" style="--cols:minmax(0,1.5fr) 150px 90px 90px 80px minmax(0,2fr)"><div>Source</div><div>Status</div><div class="num">Entries</div><div class="num">Not used</div><div class="num">Seconds</div><div>Note</div></div>
    ${(src.sources || []).map(s => `<div class="row" style="--cols:minmax(0,1.5fr) 150px 90px 90px 80px minmax(0,2fr)"><div class="name">${esc(s.name)}</div><div><span class="badge ${cls(s.status)}">${esc(s.status)}</span></div>
      <div class="num c-end">${fmt(s.rows)}</div><div class="num c-x">${fmt(s.rejected)}</div><div class="num c-x">${esc(s.seconds)}</div><div class="c-x sub">${esc(s.note || "")}</div>
      <div class="meta"><span>${fmt(s.rows)} entries</span><span>${esc(s.seconds)} s</span>${s.note ? `<span>${esc(s.note)}</span>` : ""}</div></div>`).join("")}</div>
    <p class="small muted" style="margin-top:10px"><b>ok</b> downloaded fine · <b>carried forward</b> the download failed or shrank a lot, so yesterday's copy is used · <b>skipped</b> not configured (for example no API token), not an error · <b>disabled</b> retired on purpose · <b>unavailable / FAILED</b> failed and there is no earlier copy.</p>

    <h2>How the entries were understood</h2>
    <div class="cols2"><div><h3>Repaired or guessed</h3><div class="ledger">${bars(rules, maxR) || emptyBox("None")}</div></div>
    <div><h3>Not understood</h3><div class="ledger">${bars(reasons, maxJ) || emptyBox("None")}</div></div></div>
    <div class="btn-row" style="margin-top:14px"><button type="button" class="btn" id="qrej">Browse entries that were not understood</button><button type="button" class="btn" id="qrec">Browse repaired entries</button></div>
    <div id="qout"></div>
    <h2>This build</h2>
    <dl class="kv"><dt>Data of</dt><dd>${esc(st.date)}</dd><dt>Run finished</dt><dd>${esc(st.generated_at || "")}</dd><dt>Project version</dt><dd>${esc(st.version || "")}</dd><dt>Parser version</dt><dd>${esc(st.parser_version || "")}</dd>${st.archive && Object.keys(st.archive).length ? `<dt>All-time database</dt><dd>${fmt(Object.values(st.archive).reduce((n, x) => n + x.total, 0))} values ever seen, ${fmt(Object.values(st.archive).reduce((n, x) => n + x.gone, 0))} no longer listed (<a href="${esc(API_ABS("archive/subdomains-ever.txt"))}">subdomains</a>, <a href="${esc(API_ABS("archive/subdomains-gone.txt"))}">gone</a>)</dd>` : ""}${st.disk ? `<dt>Disk</dt><dd>project ${fmt(st.disk.project_mb)} MB, ${fmt(st.disk.free_mb)} MB free</dd>` : ""}<dt>Site built</dt><dd>${esc(st.built_at || "")}</dd></dl>`;

  const qout = view.querySelector("#qout");
  async function browse(kind) {
    qout.innerHTML = '<p class="muted">Loading…</p>';
    const data = await jget(`quality/${kind === "rej" ? "rejected" : "recovered"}.json`);
    const rows = data.rows;                                          // rejected: [source, reason, raw]   recovered: [rule, source, raw, assets, result]
    const S = { q: "", key: "", page: 0 };
    const keys = [...new Set(rows.map(r => (kind === "rej" ? r[1] : r[0])))].sort();
    qout.innerHTML = `<h3>${kind === "rej" ? "Not understood" : "Repaired or guessed"} (${fmt(rows.length)})</h3><div class="filters"><input class="field search" id="qq" type="search" placeholder="Search text" aria-label="Search entries">
      <select class="field" id="qk"><option value="">${kind === "rej" ? "All reasons" : "All rules"}</option>${keys.map(k => `<option>${esc(k)}</option>`).join("")}</select></div><div id="qlist"></div>`;
    const list = qout.querySelector("#qlist");
    const upd = () => {
      const n = S.q.toLowerCase(), f = rows.filter(r => (!S.key || (kind === "rej" ? r[1] : r[0]) === S.key) && (!n || r.join(" ").toLowerCase().includes(n)));
      const pg = paginate(f.length, S.page, 50); S.page = pg.page;
      list.innerHTML = f.length ? `<div class="ledger">${f.slice(pg.start, pg.end).map(r => kind === "rej"
        ? `<div class="row" style="--cols:minmax(0,1fr)"><div class="host">${esc(r[2])}</div><div class="meta" style="display:flex"><span class="badge">${esc(r[1])}</span><span>${esc(r[0])}</span></div></div>`
        : `<div class="row" style="--cols:minmax(0,1fr)"><div class="host">${esc(r[2])}</div><div class="sub">→ ${esc(r[4])} <span class="badge">${esc(r[0])}</span> <span class="muted">${esc(r[1])}</span></div></div>`).join("")}</div>${pg.html}` : emptyBox("No entry matches");
      list.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { S.page = +b.dataset.pg; upd(); }));
    };
    qout.querySelector("#qq").addEventListener("input", debounce(e => { S.q = e.target.value; S.page = 0; upd(); }));
    qout.querySelector("#qk").addEventListener("change", e => { S.key = e.target.value; S.page = 0; upd(); });
    upd();
  }
  view.querySelector("#qrej").addEventListener("click", () => browse("rej"));
  view.querySelector("#qrec").addEventListener("click", () => browse("rec"));
}, "Sources");

/* ======================================================================= API documentation */
route(/^\/api\/?$/, "api", async view => {
  const [idx, st] = await Promise.all([jget("index.json"), jget("stats.json")]);
  const B = BASE.replace(/\/$/, "");
  const snip = (code, id) => `<div class="snippet"><pre class="code">${esc(code)}</pre><button type="button" class="btn" data-copy="${esc(code)}" data-what="command">Copy</button></div>`;
  const plats = idx.platforms.filter(p => p !== "unknown");
  view.innerHTML = `
    <div class="page-head"><div><h1>API</h1><p>Plain files over HTTP: no key, no rate limit, read-only. Lists come as text (one value per line) so they go straight into your tools; the rest is JSON. Data of ${esc(idx.data_date || "–")}.</p></div>
      <a class="btn" href="${esc(B)}/index.json" target="_blank">${icon("code")}index.json</a></div>
    <dl class="kv"><dt>Base URL</dt><dd><code>${esc(B)}</code> <button type="button" class="btn" style="min-height:28px;padding:1px 9px" data-copy="${esc(B)}" data-what="base URL">Copy</button></dd></dl>

    <h2>Build a URL</h2>
    <div class="filters"><select class="field" id="ba" aria-label="Asset type">${idx.assets.map(a => `<option value="${esc(a)}" ${a === "subdomains" ? "selected" : ""}>${esc(assetLabel(a))}</option>`).join("")}<option value="master">Everything (master)</option>${(st.out_of_scope && Object.keys(st.out_of_scope).length) ? `<optgroup label="Out of scope (what programs exclude)"><option value="oos:master">All exclusions</option>${Object.keys(st.out_of_scope).filter(a => a !== "text").map(a => `<option value="oos:${esc(a)}">Out of scope: ${esc(assetLabel(a))} (${st.out_of_scope[a]})</option>`).join("")}</optgroup>` : ""}</select>
      <select class="field" id="bk" aria-label="Which values"><option value="">All values</option><option value="-paying">Paying (and bounty unknown)</option><option value="-new">New today</option><option value="-removed">Removed today</option></select>
      <select class="field" id="bp" aria-label="Platform"><option value="">All platforms</option>${plats.map(p => `<option value="${esc(p)}">${esc(platName(p))}</option>`).join("")}</select></div>
    <div id="built"></div>

    <h2>Pipe it into your tools</h2>
    ${snip(`# probe every paying subdomain
curl -s ${B}/assets/subdomains-paying.txt | httpx -silent

# only what is new today in programs that pay, straight into a scanner
curl -s ${B}/feeds/new-paying.txt | httpx -silent | nuclei -silent

# tools that want a file
curl -s ${B}/assets/apex-paying.txt -o apex.txt && subfinder -dL apex.txt -silent
curl -s ${B}/assets/ips-paying.txt -o ips.txt && nmap -iL ips.txt -Pn -T3

# one program's scope
curl -s ${B}/programs/<slug>/subdomains.txt     # slug: see programs.json or the program page

# self-hosted programs only
curl -s ${B}/platforms/self-hosted/apex.txt

# take out what programs EXCLUDE before you scan (exact matches; wildcard exclusions are in out-of-scope/wildcards.txt)
curl -s ${B}/assets/subdomains-paying.txt | grep -vxFf <(curl -s ${B}/out-of-scope/subdomains.txt)`)}
    <h2>JSON with jq</h2>
    ${snip(`# names of all self-hosted programs
curl -s ${B}/programs.json | jq -r '.programs[] | select(.hosting=="self-hosted" or .hosting=="both") | .name'

# programs with new scope today, biggest first
curl -s ${B}/programs.json | jq -r '.programs | map(select(.new>0)) | sort_by(-.new)[] | "\\(.new)\\t\\(.name)\\t\\(.url)"'

# is a host in the subdomain list, and who lists it?
curl -s ${B}/scope/subdomains.json | jq -r '.rows[] | select(.[0]=="app.example.com")'

# daily numbers for a chart
curl -s ${B}/history.json | jq '.series.subdomains.count'`)}
    <h2>Every endpoint</h2>
    <div class="ledger"><div class="row head" style="--cols:minmax(0,1.4fr) minmax(0,2fr) 70px"><div>Path</div><div>What it returns</div><div>Type</div></div>
      ${idx.endpoints.map(e => `<div class="row click" data-copy="${esc(B + e.path.replace(idx.base, ""))}" data-what="URL" style="--cols:minmax(0,1.4fr) minmax(0,2fr) 70px"><div class="host">${esc(e.path)}</div><div class="sub">${esc(e.description)}</div><div class="c-x"><span class="badge">${esc(e.type)}</span></div></div>`).join("")}</div>
    <p class="small muted" style="margin-top:8px">Click a row to copy its URL. <code>{asset}</code> is one of: ${idx.assets.map(a => `<code>${esc(a)}</code>`).join(", ")}. <code>{platform}</code> is one of: ${idx.platforms.map(p => `<code>${esc(p)}</code>`).join(", ")}.</p>
    <p class="small muted">Values in <code>wildcards</code> files are bases: <code>example.com</code> means <code>*.example.com</code>. Files are rebuilt once per daily run, so there is no need to call them more often.</p>`;

  const built = view.querySelector("#built");
  function build() {
    const a = view.querySelector("#ba").value, k = view.querySelector("#bk").value, p = view.querySelector("#bp").value;
    let path, note = "";
    if (a.startsWith("oos:")) { path = `out-of-scope/${a.slice(4)}.txt`; note = "Exclusion lists are for all platforms together; the platform and 'which values' choices do not apply."; }
    else if (a === "master") path = "assets/master.txt";
    else if (p && (k === "" || k === "-paying")) path = `platforms/${p}/${a}${k}.txt`;
    else { path = `assets/${a}${k}.txt`; if (p) note = "Platform lists exist for all and paying values only, so the platform choice is ignored here."; }
    const url = `${B}/${path}`;
    built.innerHTML = `${note ? `<p class="small muted">${esc(note)}</p>` : ""}${snip(`curl -s ${url}`)}<div class="btn-row"><a class="btn" target="_blank" href="${esc(url)}">Open in a new tab</a></div>`;
  }
  view.querySelectorAll("#ba,#bk,#bp").forEach(el => el.addEventListener("change", build));
  view.querySelectorAll(".row.click[data-copy]").forEach(r => r.setAttribute("title", "Click to copy"));
  build();
}, "API");
