#!/bin/bash
# Project Chimera: create a free Oracle Cloud server running Chimera.
# Run in Oracle Cloud Shell (top bar >_ icon), which is already signed in:
#   curl -fsSLO https://raw.githubusercontent.com/xsignon-secure/Honeypot-MCP/main/deploy/oracle/provision.sh
#   bash provision.sh                      # optionally: DISCORD_WEBHOOK=https://discord.com/api/webhooks/... bash provision.sh
# Uses only Always Free resources (Ampere A1 1 OCPU / 6 GB, or E2.1.Micro), in the root compartment.
set -euo pipefail
C="${OCI_COMPARTMENT:-${OCI_TENANCY:?run this in Oracle Cloud Shell}}"
NAME="chimera"
RAW="https://raw.githubusercontent.com/xsignon-secure/Honeypot-MCP/${CHIMERA_REF:-main}/deploy/oracle/install.sh"
say() { printf '\n==> %s\n' "$*"; }
q() { oci "$@" --raw-output 2>/dev/null; }

say "Installer"
curl -fsSL "$RAW" -o chimera-install.sh
if [ -n "${DISCORD_WEBHOOK:-}" ]; then
  sed -i "s|^DISCORD_WEBHOOK=.*|DISCORD_WEBHOOK=\"${DISCORD_WEBHOOK}\"|" chimera-install.sh
fi

say "SSH key for maintenance (kept in Cloud Shell: ~/.ssh/chimera)"
[ -f ~/.ssh/chimera ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/chimera -C chimera-admin >/dev/null

say "Network"
VCN=$(q network vcn list --compartment-id "$C" --display-name "$NAME-vcn" --lifecycle-state AVAILABLE --query 'data[0].id')
if [ -z "$VCN" ] || [ "$VCN" = "null" ]; then
  VCN=$(q network vcn create --compartment-id "$C" --cidr-blocks '["10.20.0.0/16"]' --display-name "$NAME-vcn" \
        --dns-label chimeravcn --wait-for-state AVAILABLE --query 'data.id')
fi
IGW=$(q network internet-gateway list --compartment-id "$C" --vcn-id "$VCN" --query 'data[0].id')
if [ -z "$IGW" ] || [ "$IGW" = "null" ]; then
  IGW=$(q network internet-gateway create --compartment-id "$C" --vcn-id "$VCN" --is-enabled true \
        --display-name "$NAME-igw" --wait-for-state AVAILABLE --query 'data.id')
fi
RT=$(q network vcn get --vcn-id "$VCN" --query 'data."default-route-table-id"')
oci network route-table update --rt-id "$RT" --force >/dev/null \
  --route-rules "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$IGW\"}]"
SL=$(q network vcn get --vcn-id "$VCN" --query 'data."default-security-list-id"')
oci network security-list update --security-list-id "$SL" --force >/dev/null --ingress-security-rules '[
  {"source":"0.0.0.0/0","protocol":"6","isStateless":false,"description":"SSH (admin)","tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},
  {"source":"0.0.0.0/0","protocol":"6","isStateless":false,"description":"Chimera decoy MCP","tcpOptions":{"destinationPortRange":{"min":8000,"max":8000}}},
  {"source":"0.0.0.0/0","protocol":"1","isStateless":false,"icmpOptions":{"type":3,"code":4}}
]'
SUB=$(q network subnet list --compartment-id "$C" --vcn-id "$VCN" --display-name "$NAME-subnet" --query 'data[0].id')
if [ -z "$SUB" ] || [ "$SUB" = "null" ]; then
  SUB=$(q network subnet create --compartment-id "$C" --vcn-id "$VCN" --cidr-block 10.20.0.0/24 \
        --display-name "$NAME-subnet" --dns-label pub --wait-for-state AVAILABLE --query 'data.id')
fi

say "Server"
INST=$(q compute instance list --compartment-id "$C" --display-name "$NAME" --lifecycle-state RUNNING --query 'data[0].id')
if [ -z "$INST" ] || [ "$INST" = "null" ]; then
  ADS=$(q iam availability-domain list --compartment-id "$C" --query 'data[].name' | tr -d '[]",')
  for SHAPE in VM.Standard.A1.Flex VM.Standard.E2.1.Micro; do
    IMG=$(q compute image list --compartment-id "$C" --operating-system "Canonical Ubuntu" --operating-system-version "24.04" \
          --shape "$SHAPE" --sort-by TIMECREATED --sort-order DESC --query 'data[0].id')
    [ -z "$IMG" ] || [ "$IMG" = "null" ] && continue
    EXTRA=()
    [ "$SHAPE" = "VM.Standard.A1.Flex" ] && EXTRA=(--shape-config '{"ocpus":1,"memoryInGBs":6}')
    for AD in $ADS; do
      echo "trying $SHAPE in $AD"
      if INST=$(oci compute instance launch --compartment-id "$C" --availability-domain "$AD" --shape "$SHAPE" "${EXTRA[@]}" \
            --image-id "$IMG" --subnet-id "$SUB" --assign-public-ip true --display-name "$NAME" \
            --ssh-authorized-keys-file ~/.ssh/chimera.pub --user-data-file chimera-install.sh \
            --wait-for-state RUNNING --max-wait-seconds 900 --query 'data.id' --raw-output 2>/tmp/launch.err); then
        break 2
      fi
      INST=""
      grep -o '"message": "[^"]*"' /tmp/launch.err | head -1 || true
    done
  done
fi
[ -n "$INST" ] || { echo "No free capacity right now. Run this again in a few minutes."; exit 1; }
IP=$(q compute instance list-vnics --instance-id "$INST" --query 'data[0]."public-ip"')
echo "$IP" > ~/chimera-ip.txt
say "Done. Server $IP is installing Chimera (about 10 minutes)."
echo "Decoy:  http://$IP:8000/mcp"
echo "Access: ssh -i ~/.ssh/chimera ubuntu@$IP 'sudo cat /opt/chimera/ACCESS.txt'"
