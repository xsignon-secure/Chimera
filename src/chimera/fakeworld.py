"""A consistent, entirely fictional environment derived from the deployment seed.

Attackers (human or AI) cross-check answers. A decoy that returns a different
hostname every call is trivially fingerprinted, so every fact here is derived
deterministically from ``Settings.seed``: the same deployment always tells the
same story, while two deployments never share one.

No value here refers to a real system. Addresses come from RFC 1918 private
ranges, so nothing an attacker learns points at real infrastructure.
"""

from __future__ import annotations

import hashlib
import random
from functools import cached_property

from pydantic import BaseModel

_FIRST = [
    "alex",
    "priya",
    "jordan",
    "mei",
    "omar",
    "sofia",
    "daniel",
    "aisha",
    "lucas",
    "hana",
    "marcus",
    "elena",
    "ravi",
    "nora",
    "tomas",
    "yuki",
    "sam",
    "leila",
    "victor",
    "grace",
]
_LAST = [
    "chen",
    "patel",
    "garcia",
    "nguyen",
    "kim",
    "okafor",
    "silva",
    "muller",
    "haddad",
    "ito",
    "kowalski",
    "reyes",
    "singh",
    "larsen",
    "moreau",
    "ivanova",
    "brooks",
    "tanaka",
    "ali",
    "fischer",
]
_COMPANY_A = ["Northwind", "Bluecrest", "Ironleaf", "Helio", "Quarry", "Lumen", "Cobalt", "Ardent"]
_COMPANY_B = ["Systems", "Labs", "Logistics", "Health", "Capital", "Dynamics", "Analytics", "Networks"]
_ROLES = ["platform-admin", "sre", "data-engineer", "backend-dev", "secops", "dba", "ml-engineer"]
_SERVICES = ["billing", "payments", "auth", "orders", "analytics", "search", "ledger", "crm", "etl"]
_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"]


class Employee(BaseModel):
    employee_id: str
    username: str
    full_name: str
    email: str
    role: str
    mfa_enabled: bool


class Host(BaseModel):
    hostname: str
    ip: str
    role: str
    os: str


class FakeWorld:
    def __init__(self, seed: str) -> None:
        self.seed = seed

    def rng(self, *scope: str) -> random.Random:
        """A deterministic RNG for a named scope (stable across restarts)."""
        material = "|".join((self.seed, *scope)).encode()
        return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))

    @cached_property
    def company(self) -> str:
        r = self.rng("company")
        return f"{r.choice(_COMPANY_A)} {r.choice(_COMPANY_B)}"

    @cached_property
    def domain(self) -> str:
        return self.company.lower().replace(" ", "") + ".internal"

    @cached_property
    def aws_account_id(self) -> str:
        r = self.rng("aws-account")
        return str(r.randint(10**11, 10**12 - 1))

    @cached_property
    def region(self) -> str:
        return self.rng("region").choice(_REGIONS)

    @cached_property
    def subnet_prefix(self) -> str:
        r = self.rng("subnet")
        return f"10.{r.randint(16, 250)}"

    @cached_property
    def employees(self) -> list[Employee]:
        r = self.rng("employees")
        people: list[Employee] = []
        used: set[str] = set()
        while len(people) < 24:
            first, last = r.choice(_FIRST), r.choice(_LAST)
            username = f"{first[0]}{last}"
            if username in used:
                continue
            used.add(username)
            people.append(
                Employee(
                    employee_id=f"EMP-{r.randint(1000, 9999)}",
                    username=username,
                    full_name=f"{first.title()} {last.title()}",
                    email=f"{first}.{last}@{self.domain.replace('.internal', '.com')}",
                    role=r.choice(_ROLES),
                    mfa_enabled=r.random() > 0.35,
                )
            )
        return people

    @cached_property
    def hosts(self) -> list[Host]:
        r = self.rng("hosts")
        out = [
            Host(
                hostname=f"bastion-01.{self.domain}",
                ip=f"{self.subnet_prefix}.0.5",
                role="bastion",
                os="Ubuntu 22.04.4 LTS",
            ),
            Host(
                hostname=f"vault-01.{self.domain}",
                ip=f"{self.subnet_prefix}.2.10",
                role="vault",
                os="Ubuntu 22.04.4 LTS",
            ),
            Host(
                hostname=f"pg-primary.{self.domain}", ip=f"{self.subnet_prefix}.3.21", role="database", os="Debian 12"
            ),
        ]
        for svc in r.sample(_SERVICES, 5):
            out.append(
                Host(
                    hostname=f"{svc}-{r.randint(1, 4):02d}.{self.domain}",
                    ip=f"{self.subnet_prefix}.{r.randint(4, 40)}.{r.randint(2, 250)}",
                    role=svc,
                    os=r.choice(["Ubuntu 22.04.4 LTS", "Amazon Linux 2023", "Debian 12"]),
                )
            )
        return out

    def host(self, role: str) -> Host:
        for h in self.hosts:
            if h.role == role:
                return h
        return self.hosts[0]

    def employee(self, key: str) -> Employee:
        """Look up an employee by id/username, or deterministically map unknown keys to one."""
        for e in self.employees:
            if key and key.lower() in {e.employee_id.lower(), e.username.lower(), e.email.lower()}:
                return e
        idx = int(hashlib.sha256(f"{self.seed}|{key}".encode()).hexdigest(), 16) % len(self.employees)
        return self.employees[idx]

    @cached_property
    def admins(self) -> list[Employee]:
        return [e for e in self.employees if e.role in {"platform-admin", "sre", "secops", "dba"}][
            :6
        ] or self.employees[:4]

    @cached_property
    def services(self) -> list[str]:
        return [h.role for h in self.hosts if h.role not in {"bastion", "vault", "database"}]
