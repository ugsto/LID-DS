#!/usr/bin/env bash
# Builds the LID-DS victim images with their own Dockerfiles and pulls the
# ready-made ones. Needs internet access (old-releases.ubuntu.com, Docker Hub).
# Only victims: the normal/exploit images are for LID-DS recording, not PentAGI.
set -u
S="$(cd "$(dirname "$0")/../scenarios" && pwd)"
FAIL=0

build() { # <scenario dir> <image tag>
  echo "==> build $2"
  docker build -t "$2" "$S/$1/victim" || { echo "FAIL: $1" >&2; FAIL=1; }
}
pull() { # <image>
  echo "==> pull $1"
  docker pull "$1" || { echo "FAIL: $1" >&2; FAIL=1; }
}

build Bruteforce_CWE-307    victim_bruteforce
build CVE-2014-0160         victim_heartbleed
build CVE-2017-7529         victim_overflow
build CVE-2018-3760         victim_sprockets
build CVE-2019-5418         victim_rails
build CVE-2020-13942        victim_unomi
build CVE-2020-23839        victim_xss
build CVE-2020-9484         victim_tomcat
build CWE-89-SQL-injection  victim_sql
build EPS_CWE-434           victim_eps
build PHP_CWE-434           victim_php
build ZipSlip               victim_zipslip

# Scenarios whose victim is a ready-made image, no build needed
pull vulhub/mysql:5.5.23
pull vulhub/couchdb:2.1.0
pull bkimminich/juice-shop:v10.0.0

# Worker image with the offline tools the scenarios need (Java/ysoserial, mysql client)
echo "==> build lab-kali"
docker build -t lab-kali worker/ || { echo "FAIL: lab-kali" >&2; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "all victim images ready" || { echo "some images failed" >&2; exit 1; }
