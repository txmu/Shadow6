# Shadow6 Gate

Gate is an independently built TCP/UDP path to a Broker. It is included by
default but refuses to run until a strict configuration sets `enabled:true`.
It never loads into either Core and does not replace Qubes/qrexec isolation.

TCP peers mutually authenticate with Ed25519, establish ephemeral X25519 keys,
and protect bounded frames with AES-GCM. UDP datagrams carry an Ed25519 identity,
timestamp and cryptographic nonce; use the Broker's encrypted transport or
WireGuard when UDP payload confidentiality is required.

MTD ports are selected from the configured high range. Each authenticated TCP
session receives an encrypted current/next-port notice before data forwarding.
If negotiation is unavailable, all peers independently derive the same port
from the sorted public-key set and UTC rotation slot. Servers rebind on the next
slot; clients keep a stable loopback `listen_port` while choosing the current
remote port for each connection.

Open policy is explicit: `unconditional`, `timed`, or `conditional` (CIDRs and
optional windows). Generate an owner-only disabled template and keys with:

Use `role:client` as a stable loopback Client pre-proxy, `role:server` as the
Agent/Broker rear proxy, and one or more `role:relay` nodes for authenticated
middle hops. `remote_hosts` and `upstreams` accept up to 16 endpoints with
`round_robin` or cryptographically randomized selection, providing multi-Gate
and multi-Broker load distribution/failover without changing Core wire formats.

`portmap.py` generates strict one-to-one logical maps from ports to addresses
inside `240.0.0.0/4`. These addresses are Gate identifiers only: Shadow6 never
changes OS routes or claims universal E-class routing support.

```sh
Gate/shadow6-gate --gen-key
Gate/shadow6-gate --init-config /absolute/path/gate.json --role server
Gate/shadow6-gate --config /absolute/path/gate.json --check-config
```

The Android APK packages Gate as `libshadow6_gate.so` and starts it directly
from app-private configuration; Termux and third-party VPN applications are not
required.
