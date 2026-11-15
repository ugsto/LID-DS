#!/bin/bash
# Disk watchdog: when free space drops below the floor, SIGTERM the collector
# so it drains cleanly and writes counters.json (truncated-but-lossless
# telemetry instead of a full disk). Deployed as a systemd timer on the fleet.
set -u
FLOOR_GB=${FLOOR_GB:-15}
free_kb=$(df / | python3 -c "import sys; print(sys.stdin.readlines()[1].split()[2])")
if [ "$free_kb" -lt $((FLOOR_GB * 1024 * 1024)) ]; then
  pids=$(pgrep -f "collector runs/")
  if [ -n "$pids" ]; then
    echo "$(date) disk low (${FLOOR_GB}G floor): stopping collector $pids" >> /tmp/fleet.log
    kill -TERM $pids
  fi
fi
