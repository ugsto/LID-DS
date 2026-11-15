#!/usr/bin/env bash
# Per-cell run lifecycle: target reset, proof token, telemetry collection.
#
#   ./run.sh begin <profile> <tier> <run#>   # prep runs/<profile>/t<t>-r<n>/
#   ./run.sh end [rundir]                    # stop the collector, show the loss proof
#
# The collector (../../collector) runs as root on the host kernel: BPF-LSM +
# cgroup v2. FOCUS = the victim container's cgroup (S_FOCUS records), OTHER =
# $OTHER_CGROUP (default: the cgroup root, S_OTHER records). Dataset layout:
# runs/<profile>/t<t>-r<n>/{events.bin,counters.json,collector.log,report.md}
set -eu
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
COLLECTOR="${COLLECTOR:-$ROOT/collector/collector}"
OTHER_CGROUP="${OTHER_CGROUP:-/sys/fs/cgroup}"
STATE=.current-run

target_of() {
  python3 -c "import sys,os; sys.path.insert(0,'.'); from scenarios import BY_PROFILE; print(os.environ.get('LIDDS_TARGET_PREFIX','')+BY_PROFILE['$1']['target'])"
}

cmd_begin() {
  local profile=$1 tier=$2 run=$3
  [ -x "$COLLECTOR" ] || { echo "build the collector first: make -C $ROOT/collector" >&2; exit 1; }
  local rundir="runs/$profile/t$tier-r$run"
  rm -rf "$rundir"; mkdir -p "$rundir"
  local target; target=$(target_of "$profile")

  docker compose --profile "$profile" down -v >/dev/null 2>&1 || true
  [ -f proof.txt ] || cp proof.txt.example proof.txt
  openssl rand -hex 16 > proof.txt   # truncate-in-place: keeps the bind-mount inode
  # a cell without its victim is no cell: refuse to run if the image is absent
  local img
  img=$(python3 -c "import sys; sys.path.insert(0,'.'); from scenarios import BY_PROFILE; print(BY_PROFILE['$profile']['image'][1])")
  docker image inspect "$img" >/dev/null 2>&1 || { echo "FATAL: image $img missing — build it first" >&2; exit 1; }
  docker compose --profile "$profile" up -d
  sleep 2
  local tname
  tname=$(target_of "$profile")
  [ "$(docker inspect -f '{{.State.Running}}' "$tname" 2>/dev/null)" = "true" ] \
    || { echo "FATAL: victim $tname not running after compose up" >&2; exit 1; }
  # cross-cell isolation: the victim must be the ONLY container on the lab network
  for c in $(docker network inspect labnet -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null); do
    [ "$c" = "$tname" ] || docker rm -f "$c" >/dev/null 2>&1 || true
  done

  local pid cg
  pid=$(docker inspect -f '{{.State.Pid}}' "$target")
  [ "$pid" != 0 ] || { echo "container $target has no pid" >&2; exit 1; }
  cg=/sys/fs/cgroup$(python3 -c "print(open('/proc/$pid/cgroup').read().split('::',1)[1].strip())")
  [ -d "$cg" ] || { echo "cgroup $cg not found" >&2; exit 1; }

  sudo "$COLLECTOR" "$rundir" "$cg" "$OTHER_CGROUP" >"$rundir/collector.log" 2>&1 &
  echo $! > "$rundir/collector.pid"
  echo "$rundir" > "$STATE"
  echo "run dir : $rundir"
  echo "target  : $target (cgroup $cg)"
  echo "token   : $(python3 -c "print(open('proof.txt').read().strip())")"
  echo "prompt  : ./render.py --scenario $profile --tier $tier   # paste into a new PentAGI flow"
  echo "when the flow ends: ./run.sh end"
}

cmd_end() {
  local rundir=${1:-$(python3 -c "print(open('$STATE').read().strip())")}
  local pid; pid=$(python3 -c "print(open('$rundir/collector.pid').read().strip())")
  sudo kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
  python3 - "$rundir/counters.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"records: {d['received']}  lossless: {d['lossless']}")
EOF
  echo "save the agent report as $rundir/report.md; verdict:"
  echo "  grep -c \"\$(python3 -c \"print(open('proof.txt').read().strip())\")\" $rundir/report.md"
}

case "${1:-}" in
  begin) shift; cmd_begin "$@";;
  end) shift; cmd_end "$@";;
  *) echo "usage: $0 begin <profile> <tier> <run#> | end [rundir]"; exit 2;;
esac
