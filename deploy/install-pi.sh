#!/usr/bin/env bash
# install-pi.sh - one-time setup on the Raspberry Pi (Ubuntu). Safe to run again. No GitHub needed.
#
#   bash deploy/install-pi.sh                 # normal: runs the collector once (takes a few minutes), builds the site, starts everything
#   PORT=80 bash deploy/install-pi.sh         # settings go IN FRONT of the command, on the same line
#   DEMO=1 bash deploy/install-pi.sh          # made-up demo data instead of a real run, to look around first (no internet needed)
#   PORT=80 DEMO=1 bash deploy/install-pi.sh  # both
#
# After a DEMO install, run a normal install once to replace the demo with real data.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8080}"
RUN_USER="${SUDO_USER:-$(id -un)}"

echo "==> project: $DIR   user: $RUN_USER   port: $PORT"
command -v python3 >/dev/null || { echo "python3 is missing: sudo apt install -y python3"; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "Python $(python3 -V) is too old: the scripts need 3.8 or newer."; exit 1; }

if [ "${DEMO:-0}" = "1" ]; then
  echo "==> building the site from made-up DEMO data (nothing real)"
  python3 "$DIR/site/demo_data.py" "$DIR/demo"
  python3 "$DIR/site/build_site.py" --data "$DIR/demo/data" --history "$DIR/demo/history"
else
  echo "==> first real run: collecting data from the public sources (a few minutes, needs internet)"
  # a warning or one broken source makes the script exit 1; that must not stop the installation
  bash "$DIR/site/update.sh" || echo "    (the run reported problems, see above; the site is built from what was collected)"
  [ -d "$DIR/site/public" ] || { echo "No site was built, so no data was collected. Check the Pi's internet connection and run again."; exit 1; }
fi

echo "==> installing systemd units (asks for your sudo password)"
for f in bb-domains-web.service bb-domains-update.service bb-domains-update.timer; do
  sed -e "s|@USER@|$RUN_USER|g" -e "s|@DIR@|$DIR|g" -e "s|@PORT@|$PORT|g" "$DIR/deploy/$f" | sudo tee "/etc/systemd/system/$f" >/dev/null
done
sudo rm -f /etc/systemd/system/bb-domains-sync.service /etc/systemd/system/bb-domains-sync.timer
sudo systemctl daemon-reload
sudo systemctl enable bb-domains-web.service
# RESTART, not just "enable --now": a copy of the service that is already running (from an older or deleted folder) would otherwise
# keep serving the OLD path and answer "not found" for every page. Restart makes it use this folder.
sudo systemctl restart bb-domains-web.service
if [ "${DEMO:-0}" = "1" ]; then
  echo "==> DEMO mode: the daily timer is NOT enabled. Run without DEMO=1 to switch to real data and enable it."
  sudo systemctl disable --now bb-domains-update.timer 2>/dev/null || true
else
  sudo systemctl enable --now bb-domains-update.timer
fi
sleep 2
# self-check: the web service must run from THIS folder and the home page must answer 200
if ! curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
  echo "!! The site did not answer on port $PORT. Checks:"
  echo "   systemctl status bb-domains-web.service --no-pager | head -15"
  echo "   sudo ss -ltnp | grep :$PORT      (only ONE process should hold the port)"
  echo "   ls $DIR/site/public              (index.html must be there)"
fi
IP="$(hostname -I | awk '{print $1}')"
echo
echo "Done. Open  http://$IP:$PORT/   (or http://$(hostname).local:$PORT/)"
echo "API list:   http://$IP:$PORT/api/v1/"
[ "${DEMO:-0}" = "1" ] || systemctl list-timers bb-domains-update.timer --no-pager | head -3
