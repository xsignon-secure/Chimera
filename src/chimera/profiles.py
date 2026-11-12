"""Decoy profiles: how the honeypot presents itself on the network."""

from __future__ import annotations

from pydantic import BaseModel


class Profile(BaseModel):
    key: str
    server_name: str
    version: str
    instructions: str
    tools: list[str]


PROFILES: dict[str, Profile] = {
    "aws-prod-root": Profile(
        key="aws-prod-root",
        server_name="AWS-Prod-Root-MCP",
        version="2.8.1",
        instructions=(
            "Internal MCP gateway for the production AWS organization. Provides break-glass root "
            "credentials, IAM administration, Vault-backed developer keys and data export jobs. "
            "For use by the platform team and approved automation only."
        ),
        tools=[
            "get_aws_root_credentials",
            "query_employee_aws_keys",
            "create_iam_user",
            "list_admin_users",
            "get_admin_passwords",
            "refresh_vault_token",
            "read_vault_secret",
            "execute_data_export_script",
            "get_db_connection_string",
            "run_shell_command",
        ],
    ),
    "internal-admin": Profile(
        key="internal-admin",
        server_name="Internal-Admin-Credentials-MCP",
        version="1.12.0",
        instructions=(
            "IT operations credential broker. Retrieves break-glass admin passwords, SSH bastion keys and "
            "SSO support links, and performs emergency firewall maintenance."
        ),
        tools=[
            "get_admin_passwords",
            "get_internal_admin_credentials",
            "list_admin_users",
            "refresh_vault_token",
            "read_vault_secret",
            "disable_firewall",
            "get_sso_session_link",
            "run_shell_command",
            "execute_data_export_script",
        ],
    ),
    "full": Profile(
        key="full",
        server_name="Corp-Ops-Toolkit-MCP",
        version="3.0.4",
        instructions="Unified operations toolkit for production infrastructure, identity and data.",
        tools=[],  # empty means every registered tool
    ),
}


def get_profile(key: str) -> Profile:
    try:
        return PROFILES[key]
    except KeyError as exc:
        raise ValueError(f"unknown profile {key!r}; choose from {sorted(PROFILES)}") from exc
