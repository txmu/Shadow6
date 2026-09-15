"""Dependency-light config generation for the local network benchmark.

The benchmark must not import the full Auto-Orchestrator application: that
module includes optional UI/SSH dependencies which are unavailable on some
BSD runners.  Keep this path limited to the signed JSON contract used by the
Go and Rust cores.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return public, private


def generate_configs(output: Path, target_port: int, broker_port: int, engine: str) -> None:
    """Write broker/agent/client configs consumed by a local core trio."""
    output.mkdir(parents=True, exist_ok=True)
    broker_pub, broker_private = _keypair()
    agent_pub, agent_private = _keypair()
    client_pub, client_private = _keypair()
    transport = "quic" if engine == "shadow6-rust" else "kcp"
    scheme = "ws"
    broker_url = f"{scheme}://127.0.0.1:{broker_port}/ws"
    prefix = f"it-shadow6-{engine.removeprefix('shadow6-')}"
    broker = {
        "role": "broker",
        "broker": {
            "listen_addr": f"127.0.0.1:{broker_port}",
            "private_key": broker_private,
            "agents": [{"id": f"{prefix}-agent", "pubkey": agent_pub}],
            "clients": [{"id": f"{prefix}-client", "pubkey": client_pub,
                         "allowed_agents": [f"{prefix}-agent"]}],
            "webhook_url": "",
            "stealth_mode": False,
        },
    }
    agent = {
        "role": "agent",
        "agent": {
            "id": f"{prefix}-agent",
            "broker_addrs": [broker_url],
            "broker_pubkey": broker_pub,
            "private_key": agent_private,
            "target_port": target_port,
            "auto_close_after": 30,
            "allow_local_discovery": False,
            "client_pubkeys": {f"{prefix}-client": client_pub},
            "transport": transport,
        },
    }
    client = {
        "role": "client",
        "client": {
            "id": f"{prefix}-client",
            "broker_addrs": [broker_url],
            "broker_pubkey": broker_pub,
            "private_key": client_private,
            "target_agent": f"{prefix}-agent",
            "agent_pubkey": agent_pub,
            "on_success": "",
            "allow_local_discovery": False,
            "transport": transport,
        },
    }
    for role, document in (("broker", broker), ("agent", agent), ("client", client)):
        path = output / f"{prefix}-{role}.json"
        path.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
        path.chmod(0o600)
