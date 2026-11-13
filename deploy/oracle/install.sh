#!/bin/bash
# Project Chimera: one-shot installer for an Oracle Cloud "Always Free" Ubuntu server.
# Used as cloud-init user data by provision.sh (or paste it as the "Cloud-init script" in the console).
# The ONLY line to edit is DISCORD_WEBHOOK below.
DISCORD_WEBHOOK="PASTE_YOUR_DISCORD_WEBHOOK_URL_HERE"

set -euxo pipefail
exec > >(tee -a /var/log/chimera-install.log) 2>&1
export DEBIAN_FRONTEND=noninteractive

# 1. Swap, so the 1 GB "micro" shape can build the image comfortably.
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 2. Docker and git (all free, from Ubuntu's own repositories).
apt-get update
apt-get install -y docker.io docker-compose-v2 git curl python3 iptables-persistent
systemctl enable --now docker

# 3. Oracle's Ubuntu images reject every port except SSH. Open only the decoy port.
iptables -C INPUT -p tcp --dport 8000 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 8000 -j ACCEPT
netfilter-persistent save

# 4. Get Chimera.
if [ ! -d /opt/chimera ]; then
  git clone --depth 1 https://github.com/xsignon-secure/Honeypot-MCP /opt/chimera
fi
cd /opt/chimera

# 5. Configuration with fresh random secrets (generated here, never leave this server except the
#    dashboard password, which is sent to your private Discord channel).
PUBLIC_IP="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
gen() { python3 -c "import secrets;print(secrets.token_urlsafe(24))"; }
if [ ! -f .env ]; then
  ADMIN_PASSWORD="$(gen)"
  cat > .env <<EOF
CHIMERA_WEBHOOK_SECRET=$(gen)$(gen)
CHIMERA_SEED=$(gen)
CHIMERA_CANARY_SECRET=$(gen)
CHIMERA_PUBLIC_BASE_URL=http://${PUBLIC_IP}:8000
CHIMERA_PROFILE=aws-prod-root
CHIMERA_SERVER_NAME=prod-iam-broker
CHIMERA_SERVER_VERSION=3.2.1
CHIMERA_ALERT_MIN_SEVERITY=medium
RESPONDER_ADMIN_PASSWORD=${ADMIN_PASSWORD}
RESPONDER_MODE=approve
RESPONDER_TRIGGER_SEVERITY=high
RESPONDER_ACTIONS=blocklist
RESPONDER_PUBLIC_URL=http://127.0.0.1:9000
EOF
  if [[ "$DISCORD_WEBHOOK" == https://* ]]; then
    echo "RESPONDER_DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK}" >> .env
  fi
  chmod 600 .env
fi

# 6. Private HTTPS link to the dashboard (free Cloudflare quick tunnel, no account needed).
#    The dashboard still requires the admin password; the decoy never sees this tunnel.
cat > docker-compose.override.yml <<'EOF'
services:
  tunnel:
    image: cloudflare/cloudflared:latest
    command: ["tunnel", "--no-autoupdate", "--url", "http://responder:9000"]
    networks: [soc]
    restart: unless-stopped
    depends_on: [responder]
EOF

# 7. On every boot: start the stack, then send the dashboard link (it changes after a reboot).
cat > /opt/chimera/announce.sh <<'EOF'
#!/bin/bash
set -u
cd /opt/chimera
docker compose up -d --build
URL=""
for _ in $(seq 1 60); do
  URL="$(docker compose logs tunnel 2>/dev/null | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1)"
  [ -n "$URL" ] && break
  sleep 5
done
[ -z "$URL" ] && exit 0
if ! grep -q "^RESPONDER_PUBLIC_URL=${URL}$" .env; then
  sed -i "s|^RESPONDER_PUBLIC_URL=.*|RESPONDER_PUBLIC_URL=${URL}|" .env
  docker compose up -d responder
fi
HOOK="$(grep '^RESPONDER_DISCORD_WEBHOOK_URL=' .env | cut -d= -f2-)"
PW="$(grep '^RESPONDER_ADMIN_PASSWORD=' .env | cut -d= -f2-)"
DECOY="$(grep '^CHIMERA_PUBLIC_BASE_URL=' .env | cut -d= -f2-)/mcp"
echo "Dashboard: ${URL}  user: admin  password: ${PW}  decoy: ${DECOY}" > /opt/chimera/ACCESS.txt
chmod 600 /opt/chimera/ACCESS.txt
if [ -n "$HOOK" ]; then
  MSG="Chimera is running. Dashboard: ${URL} (user admin, password ${PW}). Decoy MCP endpoint: ${DECOY}"
  python3 - "$HOOK" "$MSG" <<'PY'
import json, sys, urllib.request
req = urllib.request.Request(sys.argv[1], data=json.dumps({"content": sys.argv[2], "allowed_mentions": {"parse": []}}).encode(), headers={"Content-Type": "application/json", "User-Agent": "chimera-installer"})
urllib.request.urlopen(req, timeout=15)
PY
fi
EOF
chmod 700 /opt/chimera/announce.sh

cat > /etc/systemd/system/chimera.service <<'EOF'
[Unit]
Description=Project Chimera honeypot
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/chimera/announce.sh
TimeoutStartSec=1200

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable chimera.service
systemctl start chimera.service
