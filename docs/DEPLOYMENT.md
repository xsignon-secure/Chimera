# Deployment guide

Everything below is free. You need a Linux host (a small VM, 1 vCPU and 1 GB RAM, is plenty), Docker with Compose v2, and optionally a free canarytokens.org account and a Slack or Discord channel.

## 1. Configure

```bash
cp .env.example .env
python3 -c "import secrets; [print(n + '=' + secrets.token_hex(32)) for n in ('CHIMERA_WEBHOOK_SECRET','CHIMERA_SEED','CHIMERA_CANARY_SECRET')]"
```

Paste the three generated lines into `.env`, then set:

* `RESPONDER_ADMIN_PASSWORD`: the dashboard login (user `admin`).
* `CHIMERA_PUBLIC_BASE_URL`: the URL attackers use to reach the decoy, e.g. `http://mcp-aws-prod.corp.example:8000`. URL canaries are built from it.
* `CHIMERA_PROFILE`: `aws-prod-root`, `internal-admin` or `full`.
* `RESPONDER_PROTECTED_NETWORKS`: gateways, DNS, domain controllers, jump hosts, the SIEM, and any NAT egress addresses.

## 2. (Optional) real Canarytokens

1. At <https://canarytokens.org>, create an **AWS keys** token. Give it your email or a webhook, and a memo such as "chimera-1".
2. Download the credentials file. Repeat for as many keys as you want; 5 to 10 is a good pool.
3. Concatenate them into one file and copy it into the honeypot volume:

```bash
cat credentials* > canarytokens.ini
docker compose cp canarytokens.ini honeypot:/data/canarytokens.ini
```

4. Set `CHIMERA_CANARYTOKENS_FILE=/data/canarytokens.ini` and run `docker compose up -d`.

When a canarytokens.org alert arrives, run `docker compose exec honeypot chimera canaries | grep <AKIA…>` to see which session and IP stole that key.

## 3. Start

```bash
docker compose up -d --build
docker compose ps        # honeypot and responder should be "healthy"
```

Behind a TLS-inspecting corporate proxy, build with its CA: `docker build --secret id=ca,src=/path/ca.pem -t chimera:1.0.0 .`

## 4. Make it discoverable (the bait)

A honeypot only works if attackers find it. Make it findable the way a real internal server would be:

* Register it in your internal MCP registry or gateway under its profile name.
* Add a `.mcp.json` or `claude_desktop_config.json` entry pointing at it in a repo, wiki page or shared drive an intruder would browse. The file is itself a breadcrumb.
* Create a DNS name such as `mcp-aws-prod.corp.example`.
* Keep it out of the configs of legitimate agents and users.

## 5. Choose a containment backend

| Goal | Setting |
|---|---|
| Firewall blocks the attacker | `RESPONDER_ACTIONS=blocklist` and `RESPONDER_FEED_TOKEN`. Point your firewall's URL alias or external feed at `http://<responder>:9000/feeds/blocklist.txt?token=…`. |
| EDR host isolation or NAC quarantine | `RESPONDER_ACTIONS=webhook` plus `RESPONDER_ACTION_WEBHOOK_URL` pointing at Shuffle, n8n or Tines. Payload: `{"action":"isolate","target_ip":…,"incident_id":…,"context":{…}}`, signed with `X-Chimera-Signature`. |
| Wazuh | `RESPONDER_ACTIONS=wazuh` and `RESPONDER_WAZUH_*`. The default command `!firewall-drop` blocks the source IP on the selected agents. |

Start with `RESPONDER_MODE=approve`, or `dry_run` for a week of observation. Move to `auto` once you trust the signal.

## 6. Feed your SIEM

* **Logs:** `docker compose logs honeypot` emits one JSON event per line. Ship them with Filebeat, Vector or Fluent Bit, or read `/data/events.jsonl` from the volume.
* **CEF/syslog:** set `CHIMERA_SYSLOG_TARGET=collector:514` and give the honeypot a network that reaches only the collector.
* **Threat intel:** `chimera export-stix <session_id>` produces a STIX 2.1 bundle for MISP or OpenCTI.

## 7. Day-2 operations

* **Backups:** back up the `honeypot-data` and `responder-data` volumes (SQLite and JSONL).
* **Upgrades:** run `git pull && docker compose up -d --build`. The data stays on the volumes.
* **Testing:** `claude mcp add --transport http decoy http://<host>:8000/mcp`, then ask the agent for the break-glass password. An incident should appear within seconds.
* **Kubernetes:** run the same image. Give the honeypot pod a `NetworkPolicy` that denies all egress except to the responder service on port 9000, and allows ingress only from your ingress controller.
