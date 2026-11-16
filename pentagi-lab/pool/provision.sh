#!/bin/bash
# provision.sh — bring a bare pool host (Ubuntu 24.04, BPF-LSM kernel) up to a
# ready pool: packages, repo, collector, ALL victim images once, watchdog, empty
# OTHER cgroup. Workers are created by mk-worker.sh after queues land.
set -euo pipefail
exec >/var/log/pool-provision.log 2>&1
export DEEPSEEK_KEY="${DEEPSEEK_KEY:?env}"

echo "=== pool provision $(date)"
# containers on lab bridges must not reach host services (sshd et al.)
iptables -C INPUT -i br-+ -j DROP 2>/dev/null || iptables -I INPUT -i br-+ -j DROP
grep -qw bpf /sys/kernel/security/lsm || { echo "FATAL: no BPF-LSM"; exit 1; }

apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 git make gcc clang libbpf-dev linux-tools-common linux-tools-generic curl openssl python3 gawk >/dev/null

mkdir -p /opt
[ -d /opt/LID-DS ] || git clone --recurse-submodules https://github.com/ugsto/LID-DS /opt/LID-DS
cd /opt/LID-DS
# pool needs the fleet commits; wait for the push if we cloned early
until [ -f pentagi-lab/pool/fleet-pool.sh ] && grep -q "early stop" pentagi-lab/cell.sh; do
  echo "waiting for pool commits in the fork"; sleep 30
  git fetch -q origin && git reset -q --hard origin/master
done

make -C collector collector filter
cp pentagi-lab/proof.txt.example pentagi-lab/proof.txt
./pentagi-lab/build-victims.sh

# empty cgroup for OTHER: pool telemetry keeps only the victim (S_FOCUS)
mkdir -p /sys/fs/cgroup/lidds-empty

# disk watchdog (same as the cloud fleet)
install -m 755 /opt/LID-DS/pentagi-lab/pool/disk-watchdog.sh /usr/local/bin/disk-watchdog.sh
cat > /etc/systemd/system/disk-watchdog.service <<'EOF'
[Unit]
Description=disk watchdog for the telemetry collector
[Service]
Type=oneshot
ExecStart=/usr/local/bin/disk-watchdog.sh
EOF
cat > /etc/systemd/system/disk-watchdog.timer <<'EOF'
[Unit]
Description=run disk-watchdog every minute
[Timer]
OnCalendar=*-*-* *:*:30
AccuracySec=15s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now disk-watchdog.timer >/dev/null 2>&1 || true

echo "=== POOL READY $(date)"
