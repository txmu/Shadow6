"""Configuration/CLI adapters for native datagram trios, without wire codecs."""
import json
import os
import socket
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DATAGRAM_CORES = {"shadow6-hare", "shadow6-carp", "shadow6-idris", "shadow6-pony"}


def generate_commands(engine: str, binary: Path, root: Path, target_port: int,
                      role_reservations: dict | None = None):
    family = socket.AF_INET6 if engine == "shadow6-hare" else socket.AF_INET
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    reservations = []
    try:
        # Hold all reservations together, including Hare's fixed listen+1 port.
        for _ in range(5):
            s = socket.socket(family, socket.SOCK_DGRAM)
            reservations.append(s)
            s.bind((host, 0))
        broker, agent, client, app, upstream = [s.getsockname()[1] for s in reservations]
        if engine == "shadow6-hare":
            reservations[2].close()
            for _ in range(100):
                c = socket.socket(family, socket.SOCK_DGRAM)
                a = socket.socket(family, socket.SOCK_DGRAM)
                try:
                    c.bind((host, 0)); client = c.getsockname()[1]
                    if client == 65535:
                        raise OSError("no following port")
                    a.bind((host, client + 1)); app = client + 1
                except OSError:
                    c.close(); a.close()
                    continue
                reservations.extend((c, a))
                break
            else:
                raise RuntimeError("cannot reserve Hare application port pair")
        seeds = {role: os.urandom(32) for role in ("agent", "client", "broker")}
        pubs = {role: Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw) for role, seed in seeds.items()}
        binding = os.urandom(32)
        commands = {}
        root.mkdir(parents=True, exist_ok=True)
        for role in ("broker", "agent", "client"):
            path = root / f"{role}.config"
            if engine == "shadow6-hare":
                if role == "broker":
                    config = dict(role=role, listen_port=broker, target_port=agent,
                                  client_port=client, peer_public_key=pubs["client"].hex(),
                                  agent_public_key=pubs["agent"].hex())
                else:
                    config = dict(role=role, private_key=seeds[role].hex(),
                                  peer_public_key=pubs["client" if role == "agent" else "agent"].hex(),
                                  listen_port=agent if role == "agent" else client,
                                  target_port=target_port if role == "agent" else broker)
                path.write_text(json.dumps(config), encoding="utf-8")
                command = [str(binary), "--config", str(path)]
            elif engine == "shadow6-pony":
                listen, peer, application = {
                    "broker": (broker, agent, upstream),
                    "agent": (agent, upstream, target_port),
                    "client": (client, broker, app),
                }[role]
                config = dict(role=role, listen_port=listen, peer_port=peer,
                              application_port=application, private_key=seeds[role].hex(),
                              peer_public_key=pubs["client" if role == "agent" else "agent"].hex())
                path.write_text(json.dumps(config), encoding="utf-8")
                command = [str(binary), "--config", str(path)]
            else:
                material = (bytes(32) + pubs["client"] + pubs["agent"] if role == "broker" else
                            seeds[role] + pubs["client" if role == "agent" else "agent"] + binding)
                path.write_bytes(material)
                local, peer, application = {
                    "broker": (broker, client, agent),
                    "agent": (agent, broker, target_port),
                    "client": (client, broker, app),
                }[role]
                if engine == "shadow6-carp":
                    command = [str(binary), f"--{role}", str(path), str(local), str(peer), str(application)]
                else:
                    command = [str(binary), "--chain", role, host, str(local), host,
                               str(peer), host, str(application), str(path), "1000000"]
            path.chmod(0o600)
            commands[role] = command
        if role_reservations is not None:
            role_reservations["broker"] = [reservations[0]]
            role_reservations["agent"] = [reservations[1]]
            if engine == "shadow6-hare":
                role_reservations["client"] = reservations[-2:]
            else:
                role_reservations["client"] = [reservations[2], reservations[3]]
            if engine == "shadow6-pony":
                role_reservations["broker"].append(reservations[4])
        return commands, (host, app)
    finally:
        retained = {sock for group in (role_reservations or {}).values() for sock in group}
        for reservation in reservations:
            if reservation not in retained:
                reservation.close()
