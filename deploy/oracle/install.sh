#!/bin/bash
# Project Chimera on an Oracle Cloud "Always Free" Ubuntu server.
# Used as cloud-init user data by provision.sh and the oracle-capacity workflow
# (or paste it as the "Cloud-init script" in the Oracle console).
# It runs the standard one-line installer; the only line to edit is DISCORD_WEBHOOK.
DISCORD_WEBHOOK="PASTE_YOUR_DISCORD_WEBHOOK_URL_HERE"

set -euo pipefail
[[ "$DISCORD_WEBHOOK" == https://* ]] && export CHIMERA_DISCORD_WEBHOOK="$DISCORD_WEBHOOK"
for i in 1 2 3 4 5; do
  # cloud-init can start before the network is fully up.
  curl -fsSL https://raw.githubusercontent.com/xsignon-secure/Chimera/main/install.sh -o /root/chimera-install.sh && break
  sleep $((i * 10))
done
bash /root/chimera-install.sh
