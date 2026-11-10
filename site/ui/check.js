/* check.js - "is this in scope?" in the browser. No server involved: the lists are downloaded once (api/v1/scope/<asset>.json)
 * and the question is answered from memory. Used by the Overview search box and by the Check scope page.
 *
 * What counts as an answer (best first):
 *   listed    the host / IP / URL is written in a program's scope exactly (apex, subdomains, ips, apps, github, ...)
 *   wildcard  a parent is a wildcard base: a.b.example.com is covered by *.b.example.com or *.example.com
 *   pattern   it fits a template such as api-*.example.com or {tenant}.example.com
 *   range     the IP lies inside a listed CIDR range
 *   github    the repo lies inside a listed GitHub organisation / project
 *   url       the input lies under a listed URL: same host (or a wildcard host) and a path that starts with the listed path, on a
 *             segment boundary (/kubernetes-release covers /kubernetes-release/v1 but not /kubernetes-release-old)
 *   guess     only found inside free text (the "maybe" list) or only in the internal-hosts list: check by hand
 *   related   not listed itself, but its parent domain is: read the program's scope text
 *   urlhost   the input is a bare host and programs list only a PATH on it (a URL): the host as a whole is NOT in scope
 *   none      nothing found
 *
 * Exclusions (api/v1/out-of-scope.json): what a program says is OUT of scope. They are matched the same way (exact, wildcard
 * parent, IP range). A program's exclusion wins over its own in-scope match, so "*.example.com is in scope" together with
 * "admin.example.com is excluded" answers "excluded" for admin.example.com, and says which program excluded it:
 *   out       every program that lists the host also excludes it, or only exclusions were found
 */
"use strict";

const CHECK_ASSETS = ["apex", "subdomains", "wildcards", "urls", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"];
/** Asset types shown as tabs on the Targets page: the scope-check ones plus the "apis" overlay (a list of API addresses that are also in subdomains / urls: never used for matching). */
const TARGET_ASSETS = ["apex", "subdomains", "wildcards", "urls", "apis", "ips", "asn", "github", "repos-other", "apps", "patterns", "internal-hosts", "maybe"];
let _idx = null;

/** Download everything needed for matching (once). onProgress(done, total) is called while loading. */
async function loadCheckIndex(onProgress) {
  if (_idx) return _idx;
  const progs = (await jget("programs.json")).programs;
  const oos = await jget("out-of-scope.json").catch(() => ({ rows: [] }));     // old builds have no exclusions: everything still works
  let done = 0;
  const sets = await Promise.all(CHECK_ASSETS.map(a => jget(`scope/${a}.json`).then(s => { onProgress && onProgress(++done, CHECK_ASSETS.length); return s; })));
  const idx = { progs, exact: new Map(), wild: new Map(), patterns: [], cidrs: [], github: [], urls: [], urlHosts: new Map(), byAsset: {}, xExact: new Map(), xWild: new Map(), xCidrs: [], xUrls: [] };
  for (const [asset, value, pidx] of oos.rows || []) {                          // exclusions: same shapes as the scope lists
    const key = value.toLowerCase(), hit = { asset, value, programs: pidx };
    if (asset === "wildcards") idx.xWild.set(key, hit);
    else if (asset === "urls") { const u = parseUrlEntry(value); if (u) idx.xUrls.push({ ...u, hit }); }
    else {
      idx.xExact.set(key, [...(idx.xExact.get(key) || []), hit]);
      if (asset === "ips" && key.includes("/")) { const c = parseCidr(key); if (c) idx.xCidrs.push({ ...c, hit }); }
    }
  }
  sets.forEach(s => {
    idx.byAsset[s.asset] = s;
    for (const row of s.rows) {
      const [value, b, h, srcs, pidx] = row;
      const hit = { asset: s.asset, value, bounty: s.bounty[b], hosting: s.hosting[h], programs: pidx };
      const key = value.toLowerCase();
      if (s.asset === "wildcards") idx.wild.set(key, hit);
      else if (s.asset === "urls") {                       // kept apart from exact matches: a URL covers everything below its path
        const u = parseUrlEntry(value);
        if (u) { idx.urls.push({ ...u, hit }); idx.urlHosts.set(u.host, [...(idx.urlHosts.get(u.host) || []), hit]); }
      }
      else if (s.asset === "patterns") { const re = patternToRegex(key); if (re) idx.patterns.push({ re, hit }); idx.exact.set(key, [...(idx.exact.get(key) || []), hit]); }
      else {
        idx.exact.set(key, [...(idx.exact.get(key) || []), hit]);
        if (s.asset === "ips" && key.includes("/")) { const c = parseCidr(key); if (c) idx.cidrs.push({ ...c, hit }); }
        if (s.asset === "github") idx.github.push({ key: key.replace(/\/+$/, ""), hit });
      }
    }
  });
  return (_idx = idx);
}


/** A listed URL "https://*.example.com:8443/api/{v}/x" -> {host, wild, path, re}. Only the host and the path matter for scope.
 *  `re` matches a request path that is the listed path or lies below it (segment boundary); "{v}" is one segment, "*" stays inside one. */
function parseUrlEntry(value) {
  const m = value.match(/^[a-z][a-z0-9+.-]*:\/\/([^/]+)(\/.*)$/i);
  if (!m) return null;
  let host = m[1].toLowerCase().replace(/:\d+$/, ""), wild = false;
  if (host.startsWith("*.")) { wild = true; host = host.slice(2); }
  const body = m[2].replace(/\/+$/, "").replace(/[.+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]*\}/g, "[^/]+").replace(/\*/g, "[^/]*");
  let re = null;
  try { re = new RegExp("^" + body + "(?:/.*)?$"); } catch (e) { /* a path that is not a valid pattern never matches */ }
  return re ? { host, wild, path: m[2].replace(/\/+$/, ""), re } : null;
}
/** Does the listed URL u cover the input (q.host + the request path qp)? */
const urlCovers = (u, q, qp) => !!qp && (q.host === u.host || (u.wild && q.host.endsWith("." + u.host))) && u.re.test(qp);

/** api-*.example.com or {tenant}.example.com -> RegExp (a "*" stays inside one label, {x} is one label). */
function patternToRegex(p) {
  if (!/[*{]/.test(p)) return null;
  let s = p.replace(/[.+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]*\}/g, "[a-z0-9-]+");
  if (s.startsWith("*\\.")) s = "(?:[a-z0-9-]+\\.)+" + s.slice(3);
  s = s.replace(/\*/g, "[a-z0-9-]*");
  try { return new RegExp("^" + s + "$"); } catch (e) { return null; }
}
const ipToInt = s => { const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); if (!m) return null; const p = m.slice(1).map(Number); return p.some(x => x > 255) ? null : ((p[0] * 16777216) + (p[1] << 16) + (p[2] << 8) + p[3]); };
function parseCidr(s) {
  const [ip, bits] = s.split("/"); const n = ipToInt(ip), b = +bits;
  if (n == null || !(b >= 0 && b <= 32)) return null;
  const size = Math.pow(2, 32 - b), start = Math.floor(n / size) * size;
  return { start, end: start + size - 1 };
}

/** One input line -> what to look up: {raw, host, ip, asn, urlPath}. */
function parseQuery(raw) {
  let s = (raw || "").trim().replace(/^["'`<(\[]+|["'`>)\],;]+$/g, "");
  const out = { raw: raw.trim(), host: "", ip: null, asn: null, url: "", wildcard: false };
  if (!s) return out;
  if (/^asn?\s*\d+$/i.test(s)) { out.asn = "AS" + s.replace(/\D/g, ""); return out; }
  out.url = s;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^@/]*@/, "");
  const slash = s.search(/[/?#]/);
  const path = slash >= 0 ? s.slice(slash) : "";
  let host = (slash >= 0 ? s.slice(0, slash) : s).toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  if (host.startsWith("*.")) { out.wildcard = true; host = host.slice(2); }
  out.host = host; out.path = path;
  if (ipToInt(host) != null) out.ip = host;
  return out;
}

const queryPath = q => (q.path || "").split(/[?#]/)[0].replace(/\/{2,}/g, "/").replace(/\/+$/, "");

/** What the programs EXCLUDE for this input: [{how, via, asset, value, programs:[prog]}] (exact, wildcard parent, IP range). */
function exclusionsFor(idx, q) {
  const out = [], seen = new Set();
  const add = (how, hit, via) => { const id = how + hit.asset + hit.value; if (!seen.has(id)) { seen.add(id); out.push({ how, via: via || hit.value, asset: hit.asset, value: hit.value, programs: hit.programs.map(i => idx.progs[i]).filter(Boolean) }); } };
  if (!q.host) return out;
  for (const key of [q.host, q.url.toLowerCase().replace(/\/+$/, "")]) for (const h of idx.xExact.get(key) || []) add("listed", h);
  const qp = queryPath(q);
  for (const u of idx.xUrls) if (urlCovers(u, q, qp)) add("listed", u.hit);               // an excluded URL excludes everything below its path
  if (q.ip) { const n = ipToInt(q.ip); for (const c of idx.xCidrs) if (n >= c.start && n <= c.end) add("range", c.hit); }
  else {
    const parts = q.host.split(".");
    for (let i = (q.wildcard ? 0 : 1); i < parts.length - 1; i++) { const parent = parts.slice(i).join("."); const w = idx.xWild.get(parent); if (w) add("wildcard", w, "*." + parent); }
  }
  return out;
}

/** Answer one input. Returns {q, level, title, why, hits:[{how, asset, value, bounty, programs:[prog]}]} */
function checkOne(idx, raw) {
  const q = parseQuery(raw);
  const res = { q, level: "none", title: "Not in the lists", why: "", hits: [] };
  const add = (how, hit, via) => res.hits.push({ how, via: via || hit.value, asset: hit.asset, value: hit.value, bounty: hit.bounty, hosting: hit.hosting, programs: hit.programs.map(i => idx.progs[i]).filter(Boolean) });
  if (!q.host && !q.asn) { res.level = "empty"; return res; }
  if (q.asn) { (idx.exact.get(q.asn.toLowerCase()) || []).forEach(h => add("listed", h)); }
  const host = q.host;
  // 1. exact (apex, subdomains, ips, apps, patterns written out, ...)
  const seen = new Set();
  for (const key of [host, q.url.toLowerCase().replace(/\/+$/, "")]) {
    for (const h of idx.exact.get(key) || []) { const id = h.asset + "|" + h.value; if (!seen.has(id) && h.asset !== "maybe" && h.asset !== "internal-hosts" && h.asset !== "patterns") { seen.add(id); add("listed", h); } }
  }
  // 2. a wildcard written as "*.example.com" asks for the wildcard itself
  if (q.wildcard && idx.wild.has(host)) add("listed", idx.wild.get(host), "*." + host);
  // 3. wildcard parents
  if (!q.ip) {
    const parts = host.split(".");
    for (let i = (q.wildcard ? 0 : 1); i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      const w = idx.wild.get(parent);
      if (w) add("wildcard", w, "*." + parent);
    }
    // 4. patterns
    for (const { re, hit } of idx.patterns) if (re.test(host)) add("pattern", hit);
  } else {
    // 5. CIDR ranges
    const n = ipToInt(q.ip);
    for (const c of idx.cidrs) if (n >= c.start && n <= c.end) add("range", c.hit);
  }
  // 5b. URLs: the input has a path and lies under a listed URL
  const qp = queryPath(q);
  for (const u of idx.urls) if (urlCovers(u, q, qp)) add("url", u.hit);
  // 6. github
  if (host === "github.com" || host === "www.github.com") {
    const parts = (q.path || "").split(/[?#]/)[0].split("/").filter(Boolean);
    for (let k = parts.length; k >= 1; k--) {
      const key = ("https://github.com/" + parts.slice(0, k).join("/")).toLowerCase();
      for (const g of idx.github) if (g.key === key) add("github", g.hit);
    }
  }
  const ex = exclusionsFor(idx, q), exIds = new Set(ex.flatMap(e => e.programs.map(p => p.id)));
  res.excluded = ex;
  res.hits.forEach(h => { h.programs = h.programs.map(p => ({ ...p, excluded: exIds.has(p.id) })); });
  if (res.hits.length && ex.length && res.hits.every(h => h.programs.length && h.programs.every(p => p.excluded))) {
    // every program that lists it also excludes it (and a hit without a known program is not covered by this rule)
    res.level = "out";
    res.title = `Excluded: ${ex[0].how === "wildcard" ? "inside " + ex[0].via : "listed as out of scope"}`;
    res.why = "The program lists it in scope, but its own exclusions cover it. Read the program page before testing.";
    return res;
  }
  if (!res.hits.length && ex.length) {
    res.level = "out";
    res.title = `Out of scope: ${ex[0].how === "wildcard" ? "inside the excluded " + ex[0].via : ex[0].how === "range" ? "inside the excluded range " + ex[0].value : "excluded by the program"}`;
    res.why = "A program lists this as out of scope. Do not test it for that program.";
    return res;
  }
  if (res.hits.length) {
    const best = ["listed", "wildcard", "pattern", "range", "url", "github"].find(k => res.hits.some(h => h.how === k));
    res.level = "yes";
    const top = res.hits.find(h => h.how === best);
    res.title = { listed: "In scope: listed exactly", wildcard: `In scope: covered by a wildcard (${top.via})`, pattern: `In scope: fits the pattern ${top.value}`,
      range: `In scope: inside the range ${top.value}`, url: `In scope: under the listed URL ${top.value}`, github: "In scope: inside a listed GitHub project" }[best];
    const pays = res.hits.some(h => h.bounty === "paying");
    res.why = pays ? "At least one program that lists it pays a bounty." : res.hits.every(h => h.bounty === "non-paying") ? "The programs that list it do not pay a bounty." : "The bounty is not known.";
    if (ex.length) res.why += ` Careful: ${ex.flatMap(e => e.programs).map(p => p.name).slice(0, 3).join(", ")} excludes it.`;
    return res;
  }
  // weaker answers
  for (const h of idx.exact.get(host) || []) if (h.asset === "maybe" || h.asset === "internal-hosts") add("guess", h);
  if (res.hits.length) {
    res.level = "maybe"; res.title = "Only a guess: found in free text or marked internal";
    res.why = "The program mentioned this host inside a sentence, or it is not on the public internet. Read the program's scope before testing.";
    return res;
  }
  if (!res.hits.length && !qp) for (const h of idx.urlHosts.get(host) || []) add("urlhost", h);
  if (res.hits.length) {
    res.level = "maybe"; res.title = "Only part of this host is in scope: a URL path";
    res.why = "Programs list this host only with a path (" + res.hits.slice(0, 2).map(h => h.value).join(", ") + "). The rest of the host is not in scope: test only under that path.";
    return res;
  }
  if (!q.ip) {                                                  // parent domain listed? (apex.txt, subdomains.txt)
    const parts = host.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      for (const h of idx.exact.get(parent) || []) if (h.asset === "apex" || h.asset === "subdomains") add("related", h, parent);
    }
    if (res.hits.length) {
      res.level = "maybe"; res.title = "Not listed, but its parent domain is";
      res.why = `${res.hits[0].via} is in a program's scope, this host is not written there. It may still count: read the scope text.`;
    }
  }
  if (res.level === "none") res.why = "Nothing in any source matches. A program can still allow it in free text that the parser could not read: see Sources > Not understood.";
  return res;
}

/** HTML for one answer (used on the overview and on the check page). */
function verdictHtml(res, opts = {}) {
  if (res.level === "empty") return "";
  const cls = res.level === "yes" ? "yes" : res.level === "maybe" ? "maybe" : res.level === "out" ? "out" : "no";
  const progs = new Map();
  res.hits.forEach(h => h.programs.forEach(p => progs.set(p.id, p)));
  (res.excluded || []).forEach(e => e.programs.forEach(p => progs.set(p.id, { ...(progs.get(p.id) || p), excluded: true })));
  const chips = [...progs.values()].slice(0, opts.maxPrograms || 8).map(p =>
    `<a href="#/program/${esc(p.slug)}"${p.excluded ? ' class="ex"' : ""}>${platBadge(p.platform)} ${esc(p.name)} <span class="muted">${p.excluded ? "excludes it" : esc(bountyWord(p.bounty))}</span></a>`).join("");
  const more = progs.size > (opts.maxPrograms || 8) ? `<span class="muted small">+${progs.size - (opts.maxPrograms || 8)} more programs</span>` : "";
  return `<div class="verdict ${cls}"><span class="dot"></span><div><b>${esc(res.q.raw)}</b><br>${esc(res.title)}</div>
    <div class="why">${esc(res.why)}</div>${chips || more ? `<div class="progs">${chips}${more}</div>` : ""}</div>`;
}
