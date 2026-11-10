#!/usr/bin/env bash
# update.sh - the whole daily job on the Raspberry Pi: collect the data from the public sources, then rebuild the website + API.
# Run by the systemd timer (bb-domains-update.timer) every day, or by hand: bash site/update.sh
# No GitHub involved. Optional API tokens go into config/secrets.env (see config/secrets.env.example).
set -u
cd "$(dirname "$0")/.." || exit 1
if [ -f config/secrets.env ]; then set -a; . config/secrets.env; set +a; fi
export BB_TZ="${BB_TZ:-Asia/Kolkata}"

python3 scripts/update_bb_domains.py
rc=$?
# exit code 1 = the run had a problem (a failed source, a warning...). The data of the other sources may still have been written,
# so the site is rebuilt anyway; it stops by itself with a message when there is no data at all.
[ $rc -ne 0 ] && echo "update: collector exited with code $rc (see the lines above); building the site from what exists"
python3 site/build_site.py
exit $rc
