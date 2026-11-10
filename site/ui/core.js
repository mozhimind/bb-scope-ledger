/* core.js - shared helpers for Scope Ledger: data loading, escaping, icons, theme, router, small widgets.
 *
 * How the page works (read this first):
 *   - There is no build step and no framework. index.html loads core.js, check.js, pages.js, pages2.js in this order.
 *   - All data comes from static files under api/v1/ (made by site/build_site.py). jget() fetches and caches them.
 *   - Each page is a function registered with route(). The URL hash (#/programs?hosting=self) is the page state, so every
 *     view can be bookmarked and the back button works.
 *   - SECURITY: scope text is written by third parties, so everything that goes into HTML passes through esc(), and a
 *     value only becomes a link when it starts with http:// or https:// (see link()).
 */
"use strict";

const BASE = new URL("api/v1/", document.baseURI).href;       // works at "/" and under a sub-folder like "/bb/"
const _cache = new Map();

/** Fetch a JSON file of the API (cached for the life of the page). */
function jget(path) {
  if (!_cache.has(path)) {
    _cache.set(path, fetch(BASE + path).then(r => {
      if (!r.ok) throw new Error(`${r.status} for api/v1/${path}`);
      return r.json();
    }).catch(e => { _cache.delete(path); throw e; }));
  }
  return _cache.get(path);
}

/** HTML-escape anything that goes into innerHTML. */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
/** A safe href: only http(s) URLs are returned, anything else becomes "#". */
function safeUrl(u) { return /^https?:\/\//i.test(u || "") ? u : "#"; }
function link(url, text, cls) {
  return /^https?:\/\//i.test(url || "")
    ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer"${cls ? ` class="${cls}"` : ""}>${esc(text ?? url)}</a>` : esc(text ?? url);
}
const fmt = n => (n == null ? "–" : Number(n).toLocaleString("en-US"));
const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : (many || one + "s")}`;

/* ---------- icons (simple outlines, drawn here so no icon font is needed) ---------- */
const ICONS = {
  home: '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>', search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>', house: '<path d="M4 20V9l8-5 8 5v11zM9 20v-6h6v6"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/>',
  delta: '<path d="M12 4l9 16H3zM12 10v5"/>', pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>', code: '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/>',
  moon: '<path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 0010.5 10.5z"/>', sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-8M22 20H2"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>', copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>',
  star: '<path d="M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1 5.9L12 16.9 6.8 19.7l1-5.9L3.5 9.7l5.9-.8z"/>', down: '<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>', ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
};
function applyIcons(root = document) {
  root.querySelectorAll("i[data-ic]:not([data-done])").forEach(el => {
    el.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[el.dataset.ic] || ""}</svg>`;
    el.dataset.done = "1";
  });
}
const icon = name => `<i data-ic="${name}"></i>`;

/* ---------- theme (System / Light / Dark / Fiesta, remembered in this browser) ---------- */
const THEMES = ["", "light", "dark", "fiesta"];                     // "" = follow the system (light or dark)
const THEME_COLOR = { light: "#F6F8F9", dark: "#0B131A", fiesta: "#4B1FD1" };
function applyTheme(t) {
  const root = document.documentElement;
  if (THEMES.includes(t) && t) root.dataset.theme = t; else delete root.dataset.theme;
  document.querySelectorAll("[data-theme-set]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.themeSet === (root.dataset.theme || ""))));
  const eff = root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[eff]);
}
function initTheme() {
  let saved = "";
  try { saved = localStorage.getItem("sl-theme") || ""; } catch (e) { /* storage blocked: follow the system */ }
  applyTheme(saved);
  document.querySelectorAll("[data-theme-set]").forEach(b => b.addEventListener("click", () => {
    applyTheme(b.dataset.themeSet);
    try { b.dataset.themeSet ? localStorage.setItem("sl-theme", b.dataset.themeSet) : localStorage.removeItem("sl-theme"); } catch (e) { /* ignore */ }
  }));
}

/* ---------- watchlist: programs you starred, kept in this browser only ---------- */
const WATCH_KEY = "sl-watch";
function watched() { try { return new Set(JSON.parse(localStorage.getItem(WATCH_KEY) || "[]").filter(x => typeof x === "string")); } catch (e) { return new Set(); } }
function saveWatched(set) { try { localStorage.setItem(WATCH_KEY, JSON.stringify([...set])); } catch (e) { toast("This browser does not allow saving the watchlist"); } }
/** A star button for one program id. Clicks are handled once, for every star on the page (see below). */
const starBtn = (id, on) => `<button type="button" class="star c-end" data-watch="${esc(id)}" aria-pressed="${!!on}" aria-label="Watch this program" title="Watch this program">${icon("star")}</button>`;
document.addEventListener("click", e => {
  const b = e.target.closest("[data-watch]");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  const set = watched(), id = b.dataset.watch, on = !set.has(id);
  on ? set.add(id) : set.delete(id);
  saveWatched(set);
  document.querySelectorAll(`[data-watch="${CSS.escape(id)}"]`).forEach(x => x.setAttribute("aria-pressed", String(on)));
  toast(on ? "Watching this program" : "Stopped watching");
  const v = document.getElementById("view");
  if (v && v._onWatch) v._onWatch();                           // the page showing the stars may want to refresh (e.g. the "Watching" filter)
}, true);
/** A whole row that behaves like a link without nesting buttons inside an <a>: <div class="row" data-href="#/program/x"> */
document.addEventListener("click", e => {
  const r = e.target.closest("[data-href]");
  if (r && !e.target.closest("a, button, input, select, label")) location.hash = r.dataset.href;
});

/* ---------- small widgets ---------- */
let _toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(_toastTimer); _toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}
async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {                                                   // http:// on a LAN has no clipboard API: use the old way
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); } catch (e2) { /* ignore */ } ta.remove();
  }
  toast(what ? `Copied ${what}` : "Copied");
}
function downloadText(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" })); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
/** Delegated click handling: <button data-copy="text"> copies, <button data-copy-el="#id"> copies the text of an element. */
document.addEventListener("click", e => {
  const b = e.target.closest("[data-copy],[data-copy-el]");
  if (!b) return;
  const text = b.dataset.copy ?? document.querySelector(b.dataset.copyEl)?.textContent ?? "";
  copyText(text, b.dataset.what);
});

const PLAT_HUE = { hackerone: 25, bugcrowd: 345, intigriti: 160, yeswehack: 255, hackenproof: 195, immunefi: 290, federacy: 60,
  synack: 40, yogosha: 130, zerocopter: 100, openbugbounty: 320, cobalt: 215, "self-hosted": 215, unknown: 215 };
const PLAT_NAME = { hackerone: "HackerOne", bugcrowd: "Bugcrowd", intigriti: "Intigriti", yeswehack: "YesWeHack", hackenproof: "HackenProof",
  immunefi: "Immunefi", federacy: "Federacy", "self-hosted": "Self-hosted", unknown: "Unknown", openbugbounty: "Open Bug Bounty" };
const platName = p => PLAT_NAME[p] || (p ? p[0].toUpperCase() + p.slice(1) : "Unknown");
function platBadge(p) {
  const hue = PLAT_HUE[p] ?? ([...p].reduce((a, c) => a + c.charCodeAt(0), 0) * 7 % 360);
  return `<span class="badge pb" style="--h:${hue}">${esc(platName(p))}</span>`;
}
const BOUNTY_WORD = { paying: "Pays", "non-paying": "No bounty", unknown: "Bounty unknown" };
const bountyWord = b => BOUNTY_WORD[b] || BOUNTY_WORD.unknown;
const tick = b => (b === "paying" ? "t-pay" : b === "non-paying" ? "t-free" : "t-unk");
/** Badge for programs that exist both on a platform and on the company's own site. (For a purely self-hosted program the
 *  platform badge already says "Self-hosted", so nothing more is shown.) */
function hostingBadge(h) { return h === "both" ? '<span class="badge acc">Also on a platform</span>' : ""; }
const selfBadge = h => (h === "self-hosted" || h === "both" ? '<span class="badge acc">Self-hosted</span>' : "");

/** Tiny line chart (inline SVG, colour from CSS). values may contain null. */
function spark(values, w = 160, h = 34) {
  const v = values.map(x => (x == null ? null : +x)); const ok = v.filter(x => x != null);
  if (ok.length < 2) return "";
  const lo = Math.min(...ok), hi = Math.max(...ok), span = hi - lo || 1, pad = 3;
  const pts = v.map((x, i) => x == null ? null : [pad + (i * (w - 2 * pad)) / (v.length - 1), h - pad - ((x - lo) / span) * (h - 2 * pad)]).filter(Boolean);
  const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join("");
  const last = pts[pts.length - 1];
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="trend"><path class="area" d="${d}L${last[0].toFixed(1)} ${h}L${pts[0][0].toFixed(1)} ${h}Z"/><path class="line" d="${d}"/><circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.6"/></svg>`;
}

/** Pager: returns {slice(items), html(total)} for page-numbered lists. page is 0-based. */
function paginate(total, page, size) {
  const pages = Math.max(1, Math.ceil(total / size)); page = Math.min(Math.max(0, page), pages - 1);
  const from = total ? page * size + 1 : 0, to = Math.min(total, (page + 1) * size);
  return { page, pages, start: page * size, end: to, html: total <= size ? `<div class="pager"><span>${plural(total, "result")}</span></div>` :
    `<div class="pager"><span>${fmt(from)}–${fmt(to)} of ${fmt(total)}</span><span class="btn-row"><button class="btn" data-pg="${page - 1}" ${page ? "" : "disabled"}>Previous</button><button class="btn" data-pg="${page + 1}" ${page < pages - 1 ? "" : "disabled"}>Next</button></span></div>` };
}
const debounce = (fn, ms = 160) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const emptyBox = (title, text) => `<div class="empty"><b>${esc(title)}</b>${esc(text || "")}</div>`;

/* ---------- router ---------- */
const routes = [];
function route(re, nav, fn, title) { routes.push({ re, nav, fn, title }); }
function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [path, qs] = raw.split("?");
  return { path, query: Object.fromEntries(new URLSearchParams(qs || "")) };
}
/** Put filter values into the URL without re-rendering (so a filtered list can be bookmarked / shared). */
function setQuery(obj) {
  const { path } = parseHash();
  const qs = new URLSearchParams(Object.entries(obj).filter(([, v]) => v !== "" && v != null && v !== false)).toString();
  history.replaceState(null, "", "#" + path + (qs ? "?" + qs : ""));
}
let _renderToken = 0;
async function render() {
  const view = document.getElementById("view");
  const { path, query } = parseHash();
  const token = ++_renderToken;
  for (const r of routes) {
    const m = path.match(r.re);
    if (!m) continue;
    document.querySelectorAll("[data-nav]").forEach(a => {
      const on = a.dataset.nav === (r.nav === "programs" && query.hosting === "self" ? "selfhosted" : r.nav);
      on ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current");
    });
    document.title = (r.title ? r.title + " · " : "") + "Scope Ledger";
    view._onWatch = null;
    view.innerHTML = '<div class="skeleton" style="width:40%;height:30px"></div><div class="skeleton"></div><div class="skeleton" style="width:80%"></div><div class="skeleton" style="width:60%"></div>';
    window.scrollTo(0, 0);
    try {
      await r.fn(view, m.slice(1).map(x => (x == null ? undefined : decodeURIComponent(x))), query);
      if (token !== _renderToken) return;
      applyIcons(view);
    } catch (e) {
      if (token !== _renderToken) return;
      console.error(e);
      view.innerHTML = `<div class="notice bad"><b>This page could not load its data.</b><br>${esc(e.message)}<br>
        <span class="small">If this is a new install, build the site first: <code>python3 site/build_site.py</code>, then reload.</span></div>`;
    }
    closeMenu();
    return;
  }
  view.innerHTML = `<h1>Page not found</h1><p class="muted">There is no page <code>${esc(path)}</code>.</p><p><a class="btn primary" href="#/">Go to the overview</a></p>`;
}
function closeMenu() { document.getElementById("rail").classList.remove("open"); document.getElementById("scrim").classList.remove("open"); }

/** Freshness line in the side bar: date of the data, and a warning when the daily run seems to have stopped. */
async function initFreshness() {
  try {
    const st = await jget("stats.json");
    const d = st.date ? new Date(st.date + "T00:00:00") : null;
    const age = d ? Math.floor((Date.now() - d.getTime()) / 86400000) : null;
    const stale = age != null && age > 2;
    const html = d ? `Data of <b>${esc(st.date)}</b>${stale ? `<br>${age} days old: has the daily run stopped?` : ""}` : "No data yet";
    for (const id of ["freshness", "topFresh"]) { const el = document.getElementById(id); el.innerHTML = id === "topFresh" && stale ? `<b>${esc(st.date)}</b> (old)` : id === "topFresh" ? `<b>${esc(st.date)}</b>` : html; el.classList.toggle("stale", stale); if (id === "freshness" && st.version) el.insertAdjacentHTML("beforeend", ` <span class="ver">v${esc(st.version)}</span>`); }
  } catch (e) {
    for (const id of ["freshness", "topFresh"]) document.getElementById(id).textContent = "No data yet";
  }
}

window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", () => {
  applyIcons(); initTheme(); initFreshness();
  document.getElementById("menuBtn").addEventListener("click", () => { document.getElementById("rail").classList.add("open"); document.getElementById("scrim").classList.add("open"); });
  document.getElementById("scrim").addEventListener("click", closeMenu);
  document.addEventListener("keydown", e => {                   // "/" jumps to the scope check, like on most search pages
    if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); const i = document.getElementById("ask"); i ? i.focus() : (location.hash = "#/check"); }
    if (e.key === "Escape") closeMenu();
  });
  render();
});
