"""Canonical native node configuration, independent of fleet scheduling/SSH.

Fleet controllers supply already coordinated identities/keys and epoch material.
No keys, topology policy or toolchain are chosen by this pure realization helper.
"""
import ipaddress
import re
from .topology_contract import engine_id, selected_engine, check_topology

from .profile_registry import topology_profile, transport_map

TRANSPORTS = transport_map(configuration=True)

def format_host_port(host: str, port: int) -> str:
    """Format literal IPv6 and ordinary hosts for socket/URL authority use."""
    host = str(host).strip()
    if not host or any(character in host for character in "[]/%\r\n\x00"):
        raise ValueError(f"invalid host: {host!r}")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError(f"invalid host: {host!r}")
        return f"{host}:{port}"
    return f"[{parsed}]:{port}" if parsed.version == 6 else f"{parsed}:{port}"


def realize_native_node(*, topo, node, core_engine, broker_pub, broker_priv,
                        agents_data, clients_data, agent_keys, client_keys,
                        broker_url, native_configs, sni):
    global_cfg = topo.get('global', {})
    stealth = global_cfg.get('stealth_mode', True)
    agent_names = [n['name'] for n in topo['nodes'] if n['type'] == 'agent']
    if 'shadow6-' + engine_id(core_engine) not in TRANSPORTS:
        raise ValueError('unsupported native realization engine')
    check_topology([{'role':n['type'], 'core':selected_engine([e for e in n['engines'] if e in TRANSPORTS],n['type'])}
                    for n in topo['nodes']],engine=core_engine)
    profile = topology_profile(engine_id(core_engine), global_cfg)
    config_data = {"role": node['type']}

    if node['type'] == 'broker':
        config_data['broker'] = {
            "listen_addr": format_host_port(node.get('listen_host', '127.0.0.1' if core_engine == 'shadow6-gleam' else '0.0.0.0'), int(node.get("listen_port",4433))),
            "private_key": broker_priv,
            "agents": agents_data,
            "clients": clients_data,
            "webhook_url": "",
            "stealth_mode": stealth
        }
    elif node['type'] == 'agent':
        _, priv = agent_keys[node['name']]
        config_data['agent'] = {
            "id": node['name'],
            "broker_addrs": [broker_url],
            "broker_pubkey": broker_pub,
            "private_key": priv,
            "target_port": int(node.get("target_port", 22)),
            "auto_close_after": int(node.get("auto_close_after", 7200)),
            "allow_local_discovery": bool(node.get("allow_local_discovery", False)),
            "client_pubkeys": {name: keys[0] for name, keys in client_keys.items()},
        }
        if core_engine == "shadow6-rust":
            config_data['agent'].update({
                "sni": sni,
                "alpn": "shadow6/1",
                "transport": "quic",
            })
        else:
            config_data['agent']["transport"] = profile['configTransport']
    elif node['type'] == 'client':
        _, priv = client_keys[node['name']]

        target_agent = node.get("target_agent", agent_names[0] if agent_names else "")
        if target_agent not in agent_keys:
            raise ValueError(f"client {node['name']} references unknown agent {target_agent!r}")

        config_data['client'] = {
            "id": node['name'],
            "broker_addrs": [broker_url],
            "broker_pubkey": broker_pub,
            "private_key": priv,
            "target_agent": target_agent,
            "agent_pubkey": agent_keys[target_agent][0],
            "on_success": node.get("on_success", ""),
            "allow_local_discovery": bool(node.get("allow_local_discovery", False)),
            "transport": profile['configTransport'],
        }

    if core_engine == "shadow6-go" and node['type'] in {"agent", "client"}:
        # Go KCP FEC is disabled explicitly; the Go Core validates 0..246.
        config_data[node['type']]["kcp_parity_shards"] = 0

    if core_engine == "shadow6-ada":
        domains = {item["name"]: item.get("domain", "default") for item in topo["nodes"]}
        config_data[node["type"]]["domain"] = domains[node["name"]]
        if node["type"] == "broker":
            for entry in agents_data + clients_data:
                entry["domain"] = domains[entry["id"]]
        elif node["type"] == "agent":
            allowed = {entry["id"] for entry in clients_data if node["name"] in entry["allowed_agents"]}
            config_data["agent"]["client_pubkeys"] = {name: client_keys[name][0] for name in allowed}
            config_data["agent"]["client_domains"] = {name: domains[name] for name in allowed}
        else:
            config_data["client"]["target_domain"] = domains[target_agent]

    if native_configs:
        config_data = native_configs[node['name']]

    role_config = config_data.get(node['type'])
    if isinstance(role_config, dict) and 'transport' in role_config and role_config['transport'] != profile['configTransport']:
        raise ValueError('ProfileConfigMismatch: native transport differs from Profile')

    if core_engine == "shadow6-gleam":
        for other_role in ("broker", "agent", "client"):
            config_data.setdefault(other_role, None)

    return config_data
