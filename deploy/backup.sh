#!/usr/bin/env bash
# backup.sh - one compressed backup of everything that is YOURS in the project (not the code, which is in the zip / on GitHub).
#
#   bash deploy/backup.sh                 # writes ~/bb-backups/bb-domains-YYYY-MM-DD.tar.gz, keeps the newest 7
#   BACKUP_DIR=/mnt/usb/bb bash deploy/backup.sh      # somewhere else (an USB disk, a mounted share)
#   KEEP=14 bash deploy/backup.sh         # keep more copies
#
# What is inside: config/ (your self-hosted lists and pasted pages), state/ (the last copy of every source and the program memory) and
# history/ (daily snapshots, monthly unions, program events). data/ and site/public/ are NOT inside: the next run rebuilds them.
# About 10 MB compressed. To restore: unpack in the project folder (tar xzf FILE -C ~/bb-domains-v<version>), then run site/update.sh.
#
# Optional, weekly, as a cron line (crontab -e):   30 4 * * 0  bash $HOME/bb-domains-vX.Y.Z/deploy/backup.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${BACKUP_DIR:-$HOME/bb-backups}"
KEEP="${KEEP:-7}"
mkdir -p "$OUT"
FILE="$OUT/bb-domains-$(date +%Y-%m-%d).tar.gz"
cd "$DIR"
# only the folders that exist (a fresh install has no history yet)
PARTS=()
for p in config state history; do [ -d "$p" ] && PARTS+=("$p"); done
tar czf "$FILE" "${PARTS[@]}"
echo "backup written: $FILE ($(du -h "$FILE" | cut -f1))"
# keep only the newest $KEEP backups
ls -1t "$OUT"/bb-domains-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
