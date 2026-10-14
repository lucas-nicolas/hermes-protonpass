"""Proton Pass secret sources for Hermes Agent (pass-cli)."""

from __future__ import annotations

from .cli import register_cli
from .protonpass import ProtonPassSource, ProtonPassVaultSource

__all__ = ["ProtonPassSource", "ProtonPassVaultSource", "register"]


def register(ctx) -> None:
    ctx.register_secret_source(ProtonPassSource())
    ctx.register_secret_source(ProtonPassVaultSource())
    ctx.register_cli_command(
        name="protonpass",
        help="Proton Pass secret source (setup/status/token/set/remove/sync/disable)",
        description="Resolve Hermes credentials from Proton Pass through pass-cli.",
        setup_fn=register_cli,
    )
