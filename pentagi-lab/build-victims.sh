#!/usr/bin/env bash
# Builds the LID-DS victim images with their own Dockerfiles and pulls the
# ready-made ones. Needs internet access (old-releases.ubuntu.com, Docker Hub).
# Only victims: the normal/exploit images are for LID-DS recording, not PentAGI.
# Usage: build-victims.sh [profile ...]   (no args = all scenarios + lab-kali)
set -u
cd "$(dirname "$0")"
FAIL=0

plan() { # emit "build <dir> <tag>" / "pull <ref>" lines for the given profiles
  python3 - "$@" <<'PYEOF'
import sys
sys.path.insert(0, ".")
from scenarios import SCENARIOS
wanted = sys.argv[1:]
for s in SCENARIOS:
    if wanted and s["profile"] not in wanted:
        continue
    kind, a, *rest = s["image"]
    print(f"{kind} {a} {rest[0] if rest else ''}".strip())
PYEOF
}

build() {
  echo "==> build $2"
  docker build -t "$2" "../scenarios/$1/victim" || { echo "FAIL: $1" >&2; FAIL=1; }
}
pull() {
  echo "==> pull $1"
  docker pull "$1" || { echo "FAIL: $1" >&2; FAIL=1; }
}

while read -r kind a b; do
  [ "$kind" = build ] && build "$a" "$b"
  [ "$kind" = pull ] && pull "$a"
done < <(plan "$@")

# The worker image is always needed
echo "==> build lab-kali"
docker build -t lab-kali worker/ || { echo "FAIL: lab-kali" >&2; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "all victim images ready" || { echo "some images failed" >&2; exit 1; }
