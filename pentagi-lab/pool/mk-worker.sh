#!/bin/bash
# mk-worker.sh <N> — materialize pool worker N on the pool host (one shared docker
# daemon; workers are compose projects with distinct TENANT_ID, ports and labnet).
# Requires: /opt/LID-DS cloned (provision.sh), docker up, victim images built,
# queue file /srv/wN/queue.txt already in place.
set -euo pipefail
N=${1:?worker id}
W=w$N
BASE=/srv/$W
REPO=/opt/LID-DS
PORT=$((28440 + N))

[ -d "$BASE" ] && { echo "$BASE exists"; exit 0; }
mkdir -p "$BASE"
FIRST_PROFILE=$(python3 -c "print(open('$BASE/../w$N/queue.txt').readline().split()[0])" 2>/dev/null || true)
FIRST_PROFILE=$(python3 -c "print(open('/srv/$W/queue.txt').readline().split()[0])")

# --- pentagi-lab copy: own runs/, own proof token, prefixed containers, own subnet
cp -r "$REPO/pentagi-lab" "$BASE/pentagi-lab"
rm -rf "$BASE/pentagi-lab/runs" "$BASE/pentagi-lab/.git" 2>/dev/null || true
mkdir -p "$BASE/pentagi-lab/runs"
cp "$REPO/pentagi-lab/proof.txt.example" "$BASE/pentagi-lab/proof.txt"
sed -i \
  -e "s/name: labnet/name: labnet$N/" \
  -e "s|- subnet: 172.30.99.0/24|- subnet: 172.30.$N.0/24|" \
  -e "s/container_name: target/container_name: $W-target/g" \
  "$BASE/pentagi-lab/docker-compose.yml"

# --- pentagi stack copy: base env + worker overrides (project, tenant, ports, net)
cp -r "$REPO/pentagi" "$BASE/pentagi"
cp "$BASE/pentagi/.env.example" "$BASE/pentagi/.env"
cat >> "$BASE/pentagi/.env" <<EOF

## pool worker $N
TENANT_ID=$W
COMPOSE_PROJECT_NAME=$W-pentagi
PENTAGI_LISTEN_PORT=$PORT
PGVECTOR_LISTEN_PORT=$((25430 + N))
POSTGRES_EXPORTER_LISTEN_PORT=$((29180 + N))
COOKIE_SIGNING_SALT=$W$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
DOCKER_NETWORK=labnet$N
DOCKER_INSIDE=false
DOCKER_PUBLIC_IP=127.0.0.1
DOCKER_IMAGE_SELECTION_MODE=fixed
DOCKER_DEFAULT_IMAGE_FOR_PENTEST=lab-kali
DOCKER_DEFAULT_IMAGE=lab-kali
DUCKDUCKGO_ENABLED=false
LLM_SERVER_URL=https://api.deepseek.com
LLM_SERVER_KEY=__DEEPSEEK_KEY__
LLM_SERVER_MODEL=deepseek-flash
LLM_SERVER_PRESERVE_REASONING=true
PENTAGI_LLM_SERVER_CONFIG_PATH=$REPO/pentagi-lab/deepseek-flash.provider.yml
LLM_SERVER_CONFIG_PATH=/opt/pentagi/conf/custom.provider.yml
EOF
sed -i "s|__DEEPSEEK_KEY__|${DEEPSEEK_KEY:?set DEEPSEEK_KEY}|" "$BASE/pentagi/.env"
chmod 600 "$BASE/pentagi/.env"

# the labnet$N network is created by the worker's own victim compose (correct
# flags); bring the first victim up so pentagi finds the network at boot
cd "$BASE/pentagi-lab"
docker compose -f docker-compose.yml --profile "$FIRST_PROFILE" up -d
cd "$BASE/pentagi"
docker compose up -d

# --- systemd unit for the queue
cat > /etc/systemd/system/lidds-$W.service <<EOF
[Unit]
Description=lidds pool worker $W
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
[Service]
Type=simple
Environment=PENTAGI_URL=https://localhost:$PORT
Environment=LIDDS_TARGET_PREFIX=$W-target
Environment=LIDDS_NET=$N
Environment=COLLECTOR=$REPO/collector/collector
Environment=OTHER_CGROUP=/sys/fs/cgroup/lidds-empty
ExecStart=$REPO/pentagi-lab/pool/fleet-pool.sh $N
Restart=on-failure
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
echo "worker $W ready — systemctl start lidds-$W when queues should run"
