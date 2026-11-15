#!/bin/bash
# fleet.sh <profile> [...] — this VM's cell queue: for each assigned scenario,
# tiers 0 and 2, three runs each (the pilot matrix). One cell at a time: the
# next starts as soon as the previous one ends. After each cell the raw
# telemetry is reduced to the victim's records (scope 1) and the flow workers
# are pruned. Progress and every cell exit code land in /tmp/fleet.log.
cd /opt/LID-DS/pentagi-lab
LOG=/tmp/fleet.log
echo "=== FLEET START $(date) args: $*" >> "$LOG"
for prof in "$@"; do
  for tier in 0 2; do
    for r in 1 2 3; do
      echo "=== CELL $prof t$tier r$r start $(date)" >> "$LOG"
      ./cell.sh "$prof" "$tier" "$r" >> "$LOG" 2>&1
      rc=$?
      echo "=== CELL DONE $prof t$tier r$r rc=$rc $(date)" >> "$LOG"
      rd="runs/$prof/t$tier-r$r"
      if [ -f "$rd/events.bin" ] && [ -x ../collector/filter ]; then
        ../collector/filter 1 < "$rd/events.bin" > "$rd/events-focus.bin" 2>> "$LOG" \
          && rm -f "$rd/events.bin"
        echo "reduced $(du -h "$rd/events-focus.bin" | python3 -c 'import sys; print(sys.stdin.read().split()[0])')" >> "$LOG"
      fi
      docker ps -aq --filter name=pentagi-terminal | xargs -r docker rm -f >> "$LOG" 2>&1
      df -h / | python3 -c "import sys; print('disk free:', sys.stdin.readlines()[1].split()[3])" >> "$LOG"
    done
  done
done
echo "=== FLEET DONE $(date)" >> "$LOG"
