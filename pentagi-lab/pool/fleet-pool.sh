#!/bin/bash
# fleet-pool.sh <worker-id> — one pool worker's queue (/srv/wN/queue.txt: "profile tier run"
# per line). Resume-safe: cells with an existing summary.json are skipped. Runs in the
# worker's systemd unit with its env already set (TENANT_ID wN, PENTAGI_URL, ...).
set -uo pipefail
W=${1:?worker id}
cd /srv/w$W/pentagi-lab
LOG=/tmp/fleet-w$W.log
echo "=== WORKER $W START $(date)" >> "$LOG"
while read -r prof tier run; do
  [ -z "$prof" ] && continue
  rd="runs/$prof/t$tier-r$run"
  if [ -f "$rd/summary.json" ]; then
    echo "=== SKIP $prof t$tier r$run (done)" >> "$LOG"
    continue
  fi
  echo "=== CELL $prof t$tier r$run start $(date)" >> "$LOG"
  ./cell.sh "$prof" "$tier" "$run" >> "$LOG" 2>&1
  rc=$?
  echo "=== CELL DONE $prof t$tier r$run rc=$rc $(date)" >> "$LOG"
  if [ -f "$rd/events.bin" ] && [ -x /opt/LID-DS/collector/filter ]; then
    /opt/LID-DS/collector/filter 1 < "$rd/events.bin" > "$rd/events-focus.bin" 2>> "$LOG" \
      && rm -f "$rd/events.bin"
  fi
  docker ps -aq --filter "name=w$W-pentagi-terminal" | xargs -r docker rm -f >> "$LOG" 2>&1
  df -h / | python3 -c "import sys; print('disk free:', sys.stdin.readlines()[1].split()[3])" >> "$LOG"
done < /srv/w$W/queue.txt
echo "=== WORKER $W DONE $(date)" >> "$LOG"
