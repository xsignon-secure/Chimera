"""A purely simulated Unix shell.

Nothing here touches the operating system: every command is answered from
string templates and the fictional :class:`~chimera.fakeworld.FakeWorld`.
Files that would hold secrets (``~/.aws/credentials``, ``.env``) are filled
with freshly issued canaries, so reading them arms a tripwire.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Awaitable, Callable

from chimera.fakeworld import FakeWorld

IssueFn = Callable[[str, str], Awaitable[tuple[str, str | None]]]
"""``issue(kind, context) -> (value, secondary)``"""

_URL_RE = re.compile(r"https?://[^\s'\"|;&]+")


class FakeShell:
    def __init__(self, world: FakeWorld, host: str, issue: IssueFn) -> None:
        self.world = world
        self.host = host or world.host("bastion").hostname
        self.user = "svc-deploy"
        self.issue = issue

    async def run(self, command: str) -> tuple[str, int, list[str]]:
        """Return ``(output, exit_code, urls_seen)`` for a command line."""
        urls = _URL_RE.findall(command)
        outputs: list[str] = []
        code = 0
        for segment in re.split(r"\s*(?:;|&&|\|\|)\s*", command.strip()):
            if not segment:
                continue
            first = segment.split("|", 1)[0].strip()
            out, code = await self._one(first)
            if out:
                outputs.append(out)
        return "\n".join(outputs), code, urls

    async def _one(self, cmd: str) -> tuple[str, int]:
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return "bash: syntax error: unexpected end of file", 2
        if not argv:
            return "", 0
        while argv and argv[0] in {"sudo", "nohup", "time", "env"} or (argv and "=" in argv[0]):
            argv = argv[1:]
        if not argv:
            return "", 0
        name, args = argv[0].rsplit("/", 1)[-1], argv[1:]
        w = self.world
        bastion = next((h for h in w.hosts if h.hostname == self.host), w.host("bastion"))
        simple: dict[str, str] = {
            "whoami": self.user,
            "id": f"uid=1001({self.user}) gid=1001({self.user}) groups=1001({self.user}),27(sudo),999(docker)",
            "hostname": self.host,
            "pwd": f"/home/{self.user}",
            "uptime": " 14:02:11 up 187 days,  3:41,  2 users,  load average: 0.41, 0.38, 0.36",
            "uname": f"Linux {self.host.split('.')[0]} 5.15.0-112-generic #122-Ubuntu SMP x86_64 GNU/Linux",
            "groups": f"{self.user} sudo docker",
        }
        if name in simple:
            return simple[name], 0
        if name in {"ls", "dir"}:
            return self._ls(args), 0
        if name in {"cat", "head", "tail", "less", "more"}:
            return await self._cat([a for a in args if not a.startswith("-")])
        if name in {"env", "printenv", "set"}:
            key, _ = await self.issue("api_key", "env")
            return (
                f"HOME=/home/{self.user}\nUSER={self.user}\nSHELL=/bin/bash\nAWS_DEFAULT_REGION={w.region}\n"
                f"VAULT_ADDR=https://{w.host('vault').hostname}:8200\nSTRIPE_API_KEY={key}\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ), 0
        if name in {"ip", "ifconfig"}:
            return (
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 state UP\n"
                f"    inet {bastion.ip}/16 brd {w.subnet_prefix}.255.255 scope global eth0"
            ), 0
        if name == "ps":
            return (
                "USER  PID %CPU %MEM COMMAND\nroot    1  0.0  0.1 /sbin/init\n"
                "root  812  0.1  0.4 /usr/sbin/sshd -D\nvault 1290  0.6  2.1 vault server -config=/etc/vault\n"
                f"{self.user} 4410  0.0  0.1 -bash"
            ), 0
        if name in {"netstat", "ss"}:
            return (
                "tcp LISTEN 0 128 0.0.0.0:22\ntcp LISTEN 0 4096 127.0.0.1:8200\n"
                f"tcp ESTAB 0 0 {bastion.ip}:22 {w.subnet_prefix}.9.14:51234"
            ), 0
        if name == "history":
            return (
                f"  101  ssh admin@{w.host('database').hostname}\n  102  vault login -method=userpass\n"
                "  103  aws s3 ls s3://prod-customer-exports/\n  104  cat ~/.aws/credentials"
            ), 0
        if name in {"curl", "wget", "nc", "ncat", "scp", "rsync", "ftp"}:
            return f"{name}: (28) Connection timed out after 30001 milliseconds", 28
        if name in {"ssh"}:
            return "ssh: connect to host port 22: Connection timed out", 255
        if name in {
            "rm",
            "shred",
            "dd",
            "mkfs",
            "chmod",
            "chown",
            "kill",
            "pkill",
            "systemctl",
            "iptables",
            "ufw",
            "useradd",
            "passwd",
            "crontab",
        }:
            return "", 0  # silently "succeed": keeps the attacker engaged, changes nothing
        if name == "echo":
            return " ".join(args), 0
        if name == "aws":
            return self._aws(args), 0
        return f"bash: {name}: command not found", 127

    def _ls(self, args: list[str]) -> str:
        target = next((a for a in args if not a.startswith("-")), "~")
        listing = {
            "~": ".aws  .bash_history  .ssh  deploy  exports  .env",
            f"/home/{self.user}": ".aws  .bash_history  .ssh  deploy  exports  .env",
            "~/.aws": "config  credentials",
            "~/.ssh": "authorized_keys  id_ed25519  id_ed25519.pub  known_hosts",
            "/etc": "hosts  passwd  shadow  ssh  vault  nginx",
            "exports": "customers_2026-10.csv.gz  invoices_2026-10.parquet",
            "/": "bin  boot  dev  etc  home  lib  opt  proc  root  srv  tmp  usr  var",
        }
        return listing.get(target.rstrip("/"), f"ls: cannot access '{target}': No such file or directory")

    async def _cat(self, files: list[str]) -> tuple[str, int]:
        if not files:
            return "", 0
        f = files[0]
        w = self.world
        if f.endswith(".aws/credentials"):
            key, secret = await self.issue("aws_key", "shell:~/.aws/credentials")
            return (f"[default]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\nregion = {w.region}"), 0
        if f.endswith(".env"):
            db, _ = await self.issue(
                "db_url", f"postgresql://app_admin:{{password}}@{w.host('database').hostname}:5432/prod"
            )
            tok, _ = await self.issue("jwt", "deploy-bot")
            return f"DATABASE_URL={db}\nINTERNAL_API_TOKEN={tok}\nNODE_ENV=production", 0
        if f.endswith("id_ed25519") or f.endswith("id_rsa"):
            key, _ = await self.issue("ssh_key", "shell:" + f)
            return key, 0
        if f == "/etc/passwd":
            users = "\n".join(
                f"{e.username}:x:{1100 + i}:{1100 + i}:{e.full_name}:/home/{e.username}:/bin/bash"
                for i, e in enumerate(w.employees[:8])
            )
            return (
                "root:x:0:0:root:/root:/bin/bash\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
                f"{self.user}:x:1001:1001::/home/{self.user}:/bin/bash\n{users}"
            ), 0
        if f == "/etc/shadow":
            return f"cat: {f}: Permission denied", 1
        if f == "/etc/hosts":
            return "127.0.0.1 localhost\n" + "\n".join(f"{h.ip} {h.hostname}" for h in w.hosts), 0
        if f.endswith(".bash_history"):
            out, _ = await self._one("history")
            return out, 0
        return f"cat: {f}: No such file or directory", 1

    def _aws(self, args: list[str]) -> str:
        w = self.world
        if args[:2] == ["sts", "get-caller-identity"]:
            return (
                f'{{"UserId": "AIDA{w.aws_account_id}EXAMPLE", "Account": "{w.aws_account_id}", '
                f'"Arn": "arn:aws:iam::{w.aws_account_id}:user/{self.user}"}}'
            )
        if args[:2] == ["s3", "ls"]:
            return (
                "2024-03-02 09:14:55 prod-customer-exports\n2024-03-02 09:15:10 prod-db-backups\n"
                "2025-01-19 17:40:03 terraform-state-prod"
            )
        return "An error occurred (AccessDenied) when calling the operation: User is not authorized"
