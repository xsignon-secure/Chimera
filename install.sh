#!/usr/bin/env bash
# Project Chimera: one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/xsignon-secure/Honeypot-MCP/main/install.sh | sudo bash
#
# Works on a fresh Linux server on any cloud or on-prem: Ubuntu, Debian, RHEL, Rocky, Alma,
# Oracle Linux, Amazon Linux, Fedora. Installs Docker if needed, generates fresh secrets,
# starts the decoy + Blue Team responder as a systemd service, and prints how to reach them.
# Re-running it upgrades in place and keeps your configuration.
#
# Optional settings (pass as environment variables, e.g. `curl ... | sudo CHIMERA_PROFILE=full bash`):
#   CHIMERA_PROFILE        aws-prod-root (default) | internal-admin | full
#   CHIMERA_SERVER_NAME    name the decoy announces (default: prod-iam-broker)
#   CHIMERA_PUBLIC_URL     how attackers reach the decoy (default: http://<public IP>:<port>)
#   CHIMERA_PORT           decoy port (default: 8000)
#   CHIMERA_MODE           responder mode: approve (default) | dry_run | auto
#   CHIMERA_DISCORD_WEBHOOK / CHIMERA_SLACK_WEBHOOK   send alerts and the dashboard link there
#   CHIMERA_TUNNEL         yes (default): private HTTPS dashboard link via a free Cloudflare quick tunnel
#                          no: dashboard only on 127.0.0.1:9000 (reach it over SSH)
#   CHIMERA_VERSION        git ref or release tag to install (default: main)
#   CHIMERA_DIR            install directory (default: /opt/chimera)
set -Eeuo pipefail

REPO="xsignon-secure/Honeypot-MCP"
VERSION="${CHIMERA_VERSION:-main}"
DIR="${CHIMERA_DIR:-/opt/chimera}"
PORT="${CHIMERA_PORT:-8000}"
TUNNEL="${CHIMERA_TUNNEL:-yes}"
LOG=/var/log/chimera-install.log

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "install failed at line $LINENO (details: $LOG)"' ERR

[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash"
[ "$(uname -s)" = Linux ] || die "Chimera's installer supports Linux servers only"
touch "$LOG" && chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
case "$PORT" in '' | *[!0-9]*) die "CHIMERA_PORT must be a number" ;; esac
case "${CHIMERA_MODE:-approve}" in approve | dry_run | auto) ;; *) die "CHIMERA_MODE must be approve, dry_run or auto" ;; esac

. /etc/os-release 2>/dev/null || true
OS="${ID:-unknown} ${ID_LIKE:-}"
say "Installing Project Chimera ($VERSION) on ${PRETTY_NAME:-Linux} into $DIR"

pkg_install() {
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q "$@" >/dev/null
  elif command -v yum >/dev/null; then
    yum install -y -q "$@" >/dev/null
  else
    die "no supported package manager (apt, dnf, yum) found"
  fi
}

# 1. Base tools.
if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null; fi
for tool in curl tar python3; do command -v "$tool" >/dev/null || pkg_install "$tool"; done

# 2. Small servers (1 GB) need swap to pull and start comfortably. Best effort only.
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if [ "$MEM_MB" -lt 2000 ] && ! swapon --show 2>/dev/null | grep -q .; then
  if [ ! -f /swapfile ] && fallocate -l 2G /swapfile 2>/dev/null && chmod 600 /swapfile \
     && mkswap /swapfile >/dev/null && swapon /swapfile 2>/dev/null; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    say "Added 2 GB swap (server has ${MEM_MB} MB RAM)"
  else
    warn "could not enable swap; continuing"
  fi
fi

# 3. Docker Engine + Compose v2.
if ! command -v docker >/dev/null; then
  say "Installing Docker"
  case "$OS" in
    *ubuntu*) pkg_install docker.io docker-compose-v2 ;;
    *) curl -fsSL https://get.docker.com | sh >/dev/null ;;
  esac
fi
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
if ! docker compose version >/dev/null 2>&1; then
  case "$OS" in
    *ubuntu*) pkg_install docker-compose-v2 ;;
    *debian*) pkg_install docker-compose-plugin || curl -fsSL https://get.docker.com | sh >/dev/null ;;
    *) pkg_install docker-compose-plugin ;;
  esac
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is not available"
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || die "Docker is installed but not running"

# 4. Chimera itself (a release tarball: no git needed). Your .env and data are kept on upgrade.
say "Downloading Chimera"
mkdir -p "$DIR"
TMP=$(mktemp -d)
curl -fsSL "https://github.com/$REPO/archive/$VERSION.tar.gz" | tar -xz -C "$TMP" --strip-components=1
cp -a "$TMP"/. "$DIR"/
rm -rf "$TMP"
cd "$DIR"

# 5. Configuration with fresh random secrets (generated here, never sent anywhere).
gen() { python3 -c "import secrets; print(secrets.token_urlsafe(${1:-24}))"; }
if [ ! -f .env ]; then
  say "Generating configuration"
  if [ -n "${CHIMERA_PUBLIC_URL:-}" ]; then
    PUBLIC_URL="${CHIMERA_PUBLIC_URL%/}"
  else
    IP=""
    for svc in https://checkip.amazonaws.com https://api.ipify.org https://ifconfig.me; do
      IP=$(curl -fsS -m 5 "$svc" 2>/dev/null | tr -d '[:space:]') && [ -n "$IP" ] && break
    done
    [ -n "$IP" ] || IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    PUBLIC_URL="http://${IP}:${PORT}"
  fi
  umask 077
  cat > .env <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%MZ). See .env.example for every option.
CHIMERA_WEBHOOK_SECRET=$(gen 48)
CHIMERA_SEED=$(gen)
CHIMERA_CANARY_SECRET=$(gen)
CHIMERA_PUBLIC_BASE_URL=${PUBLIC_URL}
CHIMERA_PUBLIC_PORT=${PORT}
CHIMERA_PROFILE=${CHIMERA_PROFILE:-aws-prod-root}
CHIMERA_SERVER_NAME=${CHIMERA_SERVER_NAME:-prod-iam-broker}
CHIMERA_SERVER_VERSION=3.2.1
CHIMERA_ALERT_MIN_SEVERITY=medium
RESPONDER_ADMIN_PASSWORD=$(gen)
RESPONDER_MODE=${CHIMERA_MODE:-approve}
RESPONDER_TRIGGER_SEVERITY=high
RESPONDER_ACTIONS=blocklist
RESPONDER_FEED_TOKEN=$(gen)
RESPONDER_PUBLIC_URL=http://127.0.0.1:9000
EOF
  [ -n "${CHIMERA_DISCORD_WEBHOOK:-}" ] && echo "RESPONDER_DISCORD_WEBHOOK_URL=${CHIMERA_DISCORD_WEBHOOK}" >> .env
  [ -n "${CHIMERA_SLACK_WEBHOOK:-}" ] && echo "RESPONDER_SLACK_WEBHOOK_URL=${CHIMERA_SLACK_WEBHOOK}" >> .env
  umask 022
else
  say "Keeping existing configuration ($DIR/.env)"
fi
chmod 600 .env

# 6. Optional private HTTPS link to the dashboard. The decoy never sees this tunnel.
if [ "$TUNNEL" = yes ]; then
  cat > docker-compose.override.yml <<'EOF'
services:
  tunnel:
    image: cloudflare/cloudflared:latest
    command: ["tunnel", "--no-autoupdate", "--url", "http://responder:9000"]
    networks: [soc]
    restart: unless-stopped
    depends_on: [responder]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
EOF
else
  rm -f docker-compose.override.yml
fi

# 7. Open the decoy port in the host firewall (cloud firewalls are separate: see the summary).
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="${PORT}/tcp" && firewall-cmd -q --reload
elif command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qE -- '-j (REJECT|DROP)'; then
  # e.g. Oracle Cloud images, which reject everything but SSH.
  iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$PORT" -j ACCEPT
  if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null; then
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    pkg_install iptables-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  fi
fi

# 8. Images: pull the published release, or build from source if it is not available.
say "Fetching container images (first run takes a few minutes)"
if ! docker compose pull -q 2>/dev/null; then
  warn "published image not available; building from source instead"
  docker compose pull -q --ignore-buildable 2>/dev/null || true
  docker compose build -q
fi

# 9. Start on every boot, and write ACCESS.txt (+ notify) once the dashboard link is known.
cat > "$DIR/announce.sh" <<'EOF'
#!/bin/bash
# Started by chimera.service. Brings the stack up and records how to reach the dashboard.
set -u
cd "$(dirname "$0")"
docker compose up -d --remove-orphans
URL=""
if [ -f docker-compose.override.yml ]; then
  for _ in $(seq 1 36); do
    # Quick-tunnel names are hyphenated words; this skips api.trycloudflare.com in error lines.
    URL="$(docker compose logs tunnel 2>/dev/null | grep -oE 'https://[a-z0-9]+(-[a-z0-9]+)+\.trycloudflare\.com' | tail -1)"
    [ -n "$URL" ] && break
    sleep 5
  done
fi
if [ -n "$URL" ]; then
  if ! grep -q "^RESPONDER_PUBLIC_URL=${URL}$" .env; then
    sed -i "s|^RESPONDER_PUBLIC_URL=.*|RESPONDER_PUBLIC_URL=${URL}|" .env
    docker compose up -d responder
  fi
else
  URL="ssh -L 9000:127.0.0.1:9000 <user>@<this server>, then open http://127.0.0.1:9000"
fi
PW="$(grep '^RESPONDER_ADMIN_PASSWORD=' .env | cut -d= -f2-)"
DECOY="$(grep '^CHIMERA_PUBLIC_BASE_URL=' .env | cut -d= -f2-)/mcp"
umask 077
printf 'Dashboard: %s\nUser:      admin\nPassword:  %s\nDecoy MCP: %s\n' "$URL" "$PW" "$DECOY" > ACCESS.txt
for KEY in RESPONDER_DISCORD_WEBHOOK_URL RESPONDER_SLACK_WEBHOOK_URL; do
  HOOK="$(grep "^${KEY}=" .env | cut -d= -f2-)"
  [ -n "$HOOK" ] || continue
  MSG="Chimera is running on $(hostname). Dashboard: ${URL} (user admin). Decoy MCP endpoint: ${DECOY}. The password is in ACCESS.txt on the server."
  python3 - "$KEY" "$HOOK" "$MSG" <<'PY' || true
import json, sys, urllib.request
key, hook, msg = sys.argv[1:]
body = {"content": msg, "allowed_mentions": {"parse": []}} if "DISCORD" in key else {"text": msg}
req = urllib.request.Request(hook, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": "chimera-installer"})
urllib.request.urlopen(req, timeout=15)
PY
done
EOF
chmod 700 "$DIR/announce.sh"

cat > /etc/systemd/system/chimera.service <<EOF
[Unit]
Description=Project Chimera MCP honeypot
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$DIR
ExecStart=$DIR/announce.sh
ExecStop=/bin/sh -c 'docker compose down'
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF

# 10. A small control command for day-to-day use.
cat > /usr/local/bin/chimera-ctl <<EOF
#!/bin/bash
# chimera-ctl: manage the Project Chimera install in $DIR
set -e
cd "$DIR"
case "\${1:-help}" in
  status)    docker compose ps ;;
  logs)      shift; docker compose logs --tail=100 -f "\$@" ;;
  access)    cat ACCESS.txt ;;
  bait)      shift; docker compose exec -T honeypot chimera bait "\$@" ;;
  restart)   systemctl restart chimera ;;
  update)    curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | CHIMERA_DIR="$DIR" CHIMERA_TUNNEL="\$( [ -f docker-compose.override.yml ] && echo yes || echo no )" bash ;;
  uninstall) read -rp "Remove Chimera and delete its recorded events? [y/N] " a; [ "\$a" = y ] || exit 1
             systemctl disable --now chimera; docker compose down -v; rm -f /etc/systemd/system/chimera.service /usr/local/bin/chimera-ctl
             echo "Removed. Configuration and code remain in $DIR (delete it to finish)." ;;
  *) echo "usage: chimera-ctl status|logs [service]|access|bait [--format claude|cursor|vscode]|restart|update|uninstall" ;;
esac
EOF
chmod 755 /usr/local/bin/chimera-ctl

systemctl daemon-reload
systemctl enable chimera.service >/dev/null 2>&1
say "Starting Chimera"
systemctl restart chimera.service

# 11. Health check and summary.
ok=0
for _ in $(seq 1 30); do
  if curl -fsS -m 3 -o /dev/null "http://127.0.0.1:${PORT}/healthz" 2>/dev/null \
     || curl -sS -m 3 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/mcp" 2>/dev/null | grep -qE '^[2-4]'; then
    ok=1; break
  fi
  sleep 2
done
[ "$ok" = 1 ] || warn "decoy did not answer on port $PORT yet; check: chimera-ctl status"

trap - ERR
DECOY="$(grep '^CHIMERA_PUBLIC_BASE_URL=' .env | cut -d= -f2-)/mcp"
cat <<EOF

  Project Chimera is running.

  Decoy MCP endpoint   ${DECOY}
  Blue Team dashboard  see: sudo chimera-ctl access   (user admin)
  Plant the bait       sudo chimera-ctl bait            (prints a ready .mcp.json)
  Manage               chimera-ctl status | logs | update | uninstall

  Cloud firewall: allow inbound TCP ${PORT} to this server (AWS security group,
  Azure NSG, GCP firewall rule, Oracle security list). Keep 9000 closed.

EOF
