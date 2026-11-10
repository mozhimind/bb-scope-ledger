"""archive.py - the ALL-TIME database: every value that was ever in scope, kept forever.

The daily files (data/) only show what is in scope TODAY, and history/daily keeps a month. This file never forgets: a value that a
program drops, or a program that closes, stays here with the day it was first seen and the day it disappeared.

    history/all-time.tsv     asset <TAB> value <TAB> first_seen <TAB> gone_on <TAB> bounty <TAB> programs

    first_seen   the first day this archive saw the value (for values that were already there when the archive started: that day)
    gone_on      empty while the value is listed; the day it was first missing from every source otherwise. A value that comes back
                 gets an empty gone_on again.
    bounty       the best status it ever had: paying > unknown > non-paying
    programs     up to three program names that listed it (the last known ones, frozen once the value is gone)

Why these columns: a line only changes when a value appears, disappears or changes program, never merely because a day passed, so
the file (and its git history) stays small even with hundreds of thousands of values. Rows are never deleted. Standard library only.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Dict, Tuple

HEAD = "asset\tvalue\tfirst_seen\tgone_on\tbounty\tprograms"
_RANK = {"non-paying": 0, "unknown": 1, "paying": 2}


def _read(path: Path) -> Dict[Tuple[str, str], list]:
    out: Dict[Tuple[str, str], list] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            c = line.split("\t")
            if len(c) >= 6:
                out[(c[0], c[1])] = [c[2], c[3], c[4], c[5]]
    return out


def update(path: Path, today: Dict[Tuple[str, str], Tuple[str, str]], date: str, quiet: bool) -> dict:
    """Merge today's values into the archive and rewrite it. today maps (asset, value) -> (bounty, programs text).
    quiet = baseline run (the parser changed, so a value missing today may be a parsing change): nothing is marked as gone.
    Returns {"total", "gone", "added", "went"} for the log."""
    rows = _read(path)
    added = went = 0
    for key, (bounty, programs) in today.items():
        row = rows.get(key)
        if row is None:
            rows[key] = [date, "", bounty or "unknown", programs]
            added += 1
            continue
        row[1] = ""                                               # listed today: not gone (a returning value is cleared again)
        if _RANK.get(bounty, 1) > _RANK.get(row[2], 1):
            row[2] = bounty
        if programs:
            row[3] = programs
    if not quiet:
        for key, row in rows.items():
            if key not in today and not row[1]:
                row[1] = date
                went += 1
    lines = [HEAD] + ["\t".join([a, v] + r) for (a, v), r in sorted(rows.items())]
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".part")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, str(path))
    return {"total": len(rows), "gone": sum(1 for r in rows.values() if r[1]), "added": added, "went": went}
