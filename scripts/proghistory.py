"""proghistory.py - remembers every program from day to day and writes down what happened to it.

Why: the daily diff only says "this host is new / removed". It cannot say that a WHOLE program disappeared (made private, paused,
closed), came back, or suddenly lost most of its assets (a scope edit, or a parser that stopped understanding a page). Those are the
events a bug bounty hunter wants to see first, so they are tracked per program:

    appeared   a program that was never seen before
    left       a program that was listed on at least two runs in a row and is now missing on two runs in a row
               (two runs, so one hiccup of a source's directory does not count as a program leaving)
    returned   a program that had left and is listed again
    shrank     the number of values fell to half or less (and by at least 10)
    grew       the number of values doubled or more (and by at least 10)

Two files, both small:

    state/programs-seen.tsv      one line per program ever seen: its identity (key), name, url, first / last seen, value count,
                                 status (active / left), runs missing in a row, the sources that listed it last time.
    history/program-events.tsv   append-only log of the events above (date, event, id, program, url, count, previous, note).

The module has no knowledge of the rest of the project: update_bb_domains.py hands it today's programs and the list of sources that
did not answer today, and gets the events back. Standard library only.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List

SEEN_HEAD = "key\tid\tname\turl\tfirst_seen\tlast_seen\tcount\tstatus\tmissing\tchecked\tsources"
EVENT_HEAD = "date\tevent\tid\tprogram\turl\tcount\tprevious\tnote"
MISSING_RUNS = 2           # a program must be missing on this many different runs in a row before it "left"
SHRINK_RATIO = 0.5         # "shrank": value count at most half of the last run's ...
GROW_RATIO = 2.0           # "grew": ... or at least double ...
MIN_CHANGE = 10            # ... and in both cases by at least this many values (a 2 -> 1 program is not news)
# Nothing is ever forgotten: a program that left stays in the seen file, and every event stays in the log (this is a database of everything
# that was ever in scope; both files stay small because they only hold programs and changes).


def _clean(s: str) -> str:
    return (s or "").replace("\t", " ").replace("\n", " ").strip()


def _read_seen(path: Path) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        c = line.split("\t")
        if len(c) < 11:
            continue
        out[c[0]] = {"id": c[1], "name": c[2], "url": c[3], "first": c[4], "last": c[5], "count": int(c[6] or 0),
                     "status": c[7] or "active", "missing": int(c[8] or 0), "checked": c[9], "sources": c[10]}
    return out


def _write_seen(path: Path, seen: Dict[str, dict]) -> None:
    lines = [SEEN_HEAD] + ["\t".join([k, r["id"], _clean(r["name"]), _clean(r["url"]), r["first"], r["last"], str(r["count"]), r["status"],
                                     str(r["missing"]), r["checked"], r["sources"]]) for k, r in sorted(seen.items())]
    _atomic(path, "\n".join(lines) + "\n")


def _atomic(path: Path, text: str) -> None:
    """Write through a temp file in the same folder, so a crash never leaves half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".part")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, str(path))


def _days_between(a: str, b: str) -> int:
    from datetime import date
    try:
        return (date.fromisoformat(b) - date.fromisoformat(a)).days
    except ValueError:
        return 0


def update(seen_path: Path, events_path: Path, programs: Iterable[dict], date: str, quiet: bool, unhealthy: Iterable[str]) -> List[dict]:
    """Compare today's programs with the remembered ones, rewrite the seen file, append the new events and return them.

    programs   dicts with key (identity), id, name, url, count (number of values), sources (iterable of source names)
    quiet      True on the very first run and on baseline runs (parser changed): the memory is updated but NO event is written,
               because a changed parser changes the program list and that is not news
    unhealthy  names of the sources that did not deliver fresh data today (failed / carried forward)"""
    bad = set(unhealthy)
    first_run = not seen_path.is_file()
    quiet = quiet or first_run
    seen = _read_seen(seen_path)
    today = {p["key"]: p for p in programs if p.get("key")}
    events: List[dict] = []

    def ev(kind: str, rec: dict, count: int, prev: int, note: str = "") -> None:
        if not quiet:
            events.append({"date": date, "event": kind, "id": rec["id"], "program": rec["name"], "url": rec["url"], "count": count, "previous": prev, "note": note})

    for key, p in today.items():
        srcs = ",".join(sorted(p.get("sources") or ()))
        n = int(p.get("count") or 0)
        rec = seen.get(key)
        if rec is None:
            rec = {"id": p["id"], "name": p["name"], "url": p["url"], "first": date, "last": date, "count": n, "status": "active", "missing": 0,
                   "checked": date, "sources": srcs}
            seen[key] = rec
            ev("appeared", rec, n, 0, "listed by " + (srcs or "?"))
            continue
        if rec["checked"] == date:                                   # a second run on the same day: nothing new to say
            rec.update(id=p["id"], name=p["name"], url=p["url"], count=n, last=date, status="active", missing=0, sources=srcs)
            continue
        prev = rec["count"]
        if rec["status"] == "left":
            ev("returned", rec, n, prev, f"had left (last listed on {rec['last']})")
        elif prev and n <= prev * SHRINK_RATIO and prev - n >= MIN_CHANGE:
            ev("shrank", rec, n, prev, "values of this program fell to half or less: scope edit, or a page the parser no longer understands")
        elif prev and n >= prev * GROW_RATIO and n - prev >= MIN_CHANGE:
            ev("grew", rec, n, prev, "values of this program doubled or more")
        rec.update(id=p["id"], name=p["name"], url=p["url"], count=n, last=date, status="active", missing=0, checked=date, sources=srcs)

    for key, rec in seen.items():
        if key in today or rec["checked"] == date:
            continue
        rec["checked"] = date
        if quiet or rec["status"] == "left":
            continue                                                 # no counting on baseline days; a program that left stays quiet
        rec["missing"] += 1
        if rec["missing"] >= MISSING_RUNS:
            rec["status"] = "left"
            listed = [s for s in rec["sources"].split(",") if s]
            silent = [s for s in listed if s in bad]
            if silent:
                note = f"last listed by {rec['sources']}; {','.join(silent)} did not answer today, so it may only be a source problem"
            else:
                note = f"last listed by {rec['sources']}; every one of them answered, so it was really dropped (made private, paused or closed)"
            ev("left", rec, 0, rec["count"], note)

    _write_seen(seen_path, seen)
    _append_events(events_path, events, date)
    return events


def _append_events(path: Path, events: List[dict], date: str) -> None:
    old = path.read_text(encoding="utf-8").splitlines()[1:] if path.is_file() else []
    have = {tuple(l.split("\t")[:3]) for l in old}
    new = []
    for e in events:
        if (e["date"], e["event"], e["id"]) in have:                 # a re-run of the same day does not write the event twice
            continue
        new.append("\t".join([e["date"], e["event"], e["id"], _clean(e["program"]), _clean(e["url"]), str(e["count"]), str(e["previous"]), _clean(e["note"])]))
    if new or not path.is_file():
        _atomic(path, "\n".join([EVENT_HEAD] + [l for l in old if l] + new) + "\n")


def read_events(path: Path) -> List[dict]:
    """The events file as dicts, newest last (used by the site builder)."""
    out = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            c = line.split("\t")
            if len(c) >= 8:
                out.append({"date": c[0], "event": c[1], "id": c[2], "program": c[3], "url": c[4], "count": int(c[5] or 0),
                            "previous": int(c[6] or 0), "note": c[7]})
    return out
