# Deployment guide

Everything below is free. You need a Linux host (a small VM, 1 vCPU and 1 GB RAM, is plenty), Docker with Compose v2, and optionally a free canarytokens.org account and a Slack or Discord channel.

> **Fastest path:** `curl -fsSL https://raw.githubusercontent.com/xsignon-secure/Honeypot-MCP/main/install.sh | sudo bash` does steps 1 to 3 for you on a fresh Linux server (see the README). The rest of this guide covers manual setup and the integrations.

## Releasing (maintainers)

Tag a version that matches `pyproject.toml` and push it: `git tag v1.0.0 && git push origin v1.0.0`. The `release` workflow builds `ghcr.io/xsignon-secure/chimera:<version>` and `:latest` for amd64 and arm64, smoke-tests it, and creates a GitHub Release with `install.sh`. The first time, open the package's settings on GitHub (Packages → chimera → Package settings) and set its visibility to **Public** so installs can pull it anonymously. Until then the installer builds from source automatically.

## 1. Configure

```bash
cp .env.example .env
python3 -c "import secrets; [print(n + '=' + secrets.token_hex(32)) for n in ('CHIMERA_WEBHOOK_SECRET','CHIMERA_SEED','CHIMERA_CANARY_SECRET')]"
```

Paste the three generated lines into `.env`, then set:

* `RESPONDER_ADMIN_PASSWORD`: the dashboard login (user `admin`).
* `CHIMERA_PUBLIC_BASE_URL`: the URL attackers use to reach the decoy, e.g. `http://mcp-aws-prod.corp.example:8000`. URL canaries are built from it.
* `CHIMERA_PROFILE`: `aws-prod-root`, `internal-admin` or `full`.
* `CHIMERA_SERVER_NAME` (recommended): a name that fits your company, e.g. `acme-prod-iam-broker`. A unique name means attackers cannot recognise your decoy from a public list.
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
* Add a `.mcp.json` or `claude_desktop_config.json` entry pointing at it in a repo, wiki page or shared drive an intruder would browse. The file is itself a breadcrumb. Generate it with `docker compose exec honeypot chimera bait > .mcp.json` (`--format cursor` or `--format vscode` for other clients).
* Create a DNS name such as `mcp-aws-prod.corp.example`.
* Keep it out of the configs of legitimate agents and users.

## 5. Choose a containment backend

| Goal | Setting |
|---|---|
| Firewall blocks the attacker | `RESPONDER_ACTIONS=blocklist` and `RESPONDER_FEED_TOKEN`. Point your firewall's URL alias or external feed at `http://<responder>:9000/feeds/blocklist.txt?token=…`. |
| EDR host isolation or NAC quarantine | `RESPONDER_ACTIONS=webhook` plus `RESPONDER_ACTION_WEBHOOK_URL` pointing at Shuffle, n8n or Tines. Payload: `{"action":"isolate","target_ip":…,"incident_id":…,"context":{…}}`, signed with `X-Chimera-Signature`. |
| Wazuh | `RESPONDER_ACTIONS=wazuh` and `RESPONDER_WAZUH_*`. See [Wazuh](#wazuh) below. |

Start with `RESPONDER_MODE=approve`, or `dry_run` for a week of observation. Move to `auto` once you trust the signal.

### Wazuh

Tested against a real Wazuh 4.14.10 manager and agent: an approved incident put `DROP` rules for the attacker's IP into the agent's `INPUT` and `FORWARD` chains within seconds, and Wazuh removed them by itself when the timeout ended.

1. On the Wazuh manager, add a timed response to `/var/ossec/etc/ossec.conf` and restart the manager. The `rules_id` is a placeholder so Wazuh never fires it by itself; Chimera triggers it through the API.

   ```xml
   <ossec_config>
     <active-response>
       <disabled>no</disabled>
       <command>firewall-drop</command>
       <location>local</location>
       <rules_id>100900</rules_id>
       <timeout>3600</timeout>
     </active-response>
   </ossec_config>
   ```

2. Set in `.env`:

   ```
   RESPONDER_ACTIONS=blocklist,wazuh
   RESPONDER_WAZUH_URL=https://wazuh-manager.corp.example:55000
   RESPONDER_WAZUH_USER=<API user with active-response:command permission>
   RESPONDER_WAZUH_PASSWORD=...
   RESPONDER_WAZUH_COMMAND=firewall-drop3600     # "firewall-drop" + the timeout above
   RESPONDER_WAZUH_AGENTS=001,002                 # gateways / web servers that should drop the attacker, or "all"
   ```

3. Give the responder a route to the manager (put the manager's network or address on the `soc` side).

The Wazuh API has no "undo" call, so **Release** relies on that timeout. With the bare script `RESPONDER_WAZUH_COMMAND=!firewall-drop` (no manager change needed) blocks are permanent; the dashboard marks the release step ✗ and prints the `iptables -D` command to run on the agents. If Wazuh answers but no agent was blocked (wrong agent id, command not defined on the manager, agent offline), the incident shows **failed** with Wazuh's reason, so you never believe a host is contained when it is not.

## 6. Feed your SIEM

* **Logs:** `docker compose logs honeypot` emits one JSON event per line. Ship them with Filebeat, Vector or Fluent Bit, or read `/data/events.jsonl` from the volume.
* **CEF/syslog:** set `CHIMERA_SYSLOG_TARGET=collector:514` and give the honeypot a network that reaches only the collector.
* **Threat intel:** `chimera export-stix <session_id>` produces a STIX 2.1 bundle for MISP or OpenCTI.

## 7. Day-2 operations

* **Backups:** back up the `honeypot-data` and `responder-data` volumes (SQLite and JSONL).
* **Upgrades:** run `git pull && docker compose up -d --build`. The data stays on the volumes.
* **Testing:** `claude mcp add --transport http decoy http://<host>:8000/mcp`, then ask the agent for the break-glass password. An incident should appear within seconds.
* **Kubernetes:** run the same image. Give the honeypot pod a `NetworkPolicy` that denies all egress except to the responder service on port 9000, and allows ingress only from your ingress controller. Set `RESPONDER_ALERTS_ONLY_NETWORKS` to the honeypot pod CIDR, and pass the honeypot only its `CHIMERA_*` variables.
* **IPv6:** publish the decoy on IPv4. Docker forwards IPv6 clients from the edge gateway address, which hides the attacker's real IP.
