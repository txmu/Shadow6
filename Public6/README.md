# Public6

Public6 is the explicit all-components Shadow6 suite. It includes the twelve
independent Core families when their toolchains are enabled, compiles every
optional Core feature, and leaves jurisdiction-specific compliance actions
disabled. Core-Go and Core-Rust remain alternative
stacks: peers must use the same Core family and exact Core version.

Only that Core identity is a compatibility gate. Crosed level, application
protocols, optional transports, capability lists, isolation flags, and
namespaced extensions may all differ. Public6 negotiates their intersection;
an absent or incompatible optional item is disabled without rejecting the base
Core connection. Local authorization, signed Crosed grants, domain policy, and
Plugin capability checks still apply independently.

Extensions are bounded namespaced data offers. Extension code remains a signed,
isolated, out-of-process Plugin and is never loaded into a Core process.

Use `make public6` for the explicit suite build. It preserves full-feature Core
artifacts as `Core-Go/shadow6-go-public6` and
`Core-Rust/shadow6-rust-public6`, then restores the least-privileged default
Core binaries. Use `shadow6-public profile`, `shadow6-public offer REPORT`, and
`shadow6-public negotiate LOCAL PEER` for the suite contract.

## Virtual Broker compatibility layer

`virtual_broker.py` is an optional out-of-process Public6 front layer for a
shared service. It does not translate Core wire protocols and does not decrypt
tenant payloads. A short Ed25519-signed admission record declares the client's
Core family; the layer maps it only to an installed real Broker of that same
family and then relays opaque E2EE bytes. A keyed virtual identity prevents
exposing deployment keys to tenants.

Tenants choose `default-approved` or `approval-required`; approvals are a
bounded startup catalog. Each tenant has independent connection and token-
bucket byte quotas, so constrained datagram Cores cannot evict another
tenant's sessions even when S6NA is disabled. Configuration requires loopback
real-Broker targets and a loopback listener behind both Guard and Gate. The
admission replay index expires entries in deadline order and caps live entries
at 65,536. Verified public keys are cached at startup; relay copies use bounded
write buffering and a shared per-tenant byte budget in both directions. The
C11Relay control socket is declared for the supervised deployment boundary.
No Core process or Core protocol is modified. The supplied hardened systemd
unit refuses to run without Guard and Gate services.

Anonymous access is an explicit per-port TCP listener on the configured
loopback host. Set `anonymous_listeners` to entries such as
`{"port": 7446, "tenant": "example", "core": "go"}`. This skips only the
Virtual Broker admission record; the listener remains behind Guard and Gate
and uses that tenant's connection and byte quotas. Every port maps to one
tenant and Core route. The default list is empty. Operator-configured ports
must be unique and between 1 and 65535.
An anonymous-only tenant may set `public_keys` to an empty list; tenants with
no anonymous listener still require at least one Ed25519 public key.

Pony, Hare, Carp and Idris may use `datagram_listeners` entries with `port`,
`tenant`, `core`, `carrier` (`gate` or `s6na`), and `anonymous` (boolean).
Example: `{"port": 7447, "tenant": "example", "core": "hare",
"carrier": "gate", "anonymous": false}`. Each listener is loopback-only
and forwards bounded request datagrams to a dedicated same-Core native
Broker UDP endpoint. Gate mode returns at most one reply per request, matching
Gate's transaction behavior. S6NA mode pins one upstream UDP socket to each
client source until the idle deadline, so ACK and data replies can share a
session. Signed
requests begin with a 2-byte big-endian admission JSON length, the existing
signed admission JSON, and then the opaque Core datagram. A fresh nonce is
needed for each datagram. Anonymous mode sends the opaque Core datagram alone.
The Gate ingress must authenticate remote peers before forwarding to the local
listener; S6NA mode requires an independently configured S6NA carrier and key.
The Virtual Broker cannot verify the Gate envelope or S6NA AEAD after those
layers have unwrapped it. It keeps the tenant quota and no public listener.
Gate itself retains UDP semantics; this relay does not convert Gate UDP to TCP
or add stream reliability. S6NA provides reliable messages through its own
adapter. Both modes leave the native Core wire format opaque.

Use `shadow6 virtual-broker --config FILE --check` for a read-only check.
The Control Center exposes the same validation to AI tools as
`virtual_broker.validate` with `{"config":"/absolute/path/config.json"}`;
it never opens a listener or changes configuration.

### Virtual Client, Virtual Agent, and 40-character invitations

`shadow6 virtual-client` and `shadow6 virtual-agent` are loopback admission
proxies. Each accepts one native Core family selected in an owner-only config,
creates a fresh nonce and short Ed25519-signed admission record for every TCP
connection or UDP datagram, and sends it through a separately configured local
Gate client. They do not execute Core, Guard, or Gate commands. Run one proxy
per selected Core and role; point that Core's broker endpoint at the proxy's
loopback listener. The broker's real Core endpoint must use the same family.
UDP through Gate follows Gate's one-reply-per-request behavior; only the four
documented native datagram families have Virtual Broker datagram listeners.

`shadow6 join-code issue --mode ipv4-https --host PUBLIC_IPV4 --port HTTPS_PORT`
creates a 40-character base64url invitation. It is a **per-invite client
credential**, not the Broker or Gate server private key. Separate Ed25519 keys
for Gate and Virtual Broker admission are derived from the code. Anyone holding
it can impersonate that invitee, so deliver it privately, store it in an
owner-only secret store, and revoke it by removing both derived public keys
from the server configurations. Never reuse one code for unrelated people.

`shadow6 join-code provision --mode ipv4-https --host PUBLIC_IPV4 --port
HTTPS_PORT --public-host PUBLIC_IPV4 --tenant TENANT --broker-config BROKER.json
--gate go=GATE.json --native-key go=NATIVE_BROKER_PUBLIC_HEX
--agent go=AGENT_ID:AGENT_PUBLIC_HEX --output-dir NEW_DIR` creates a reviewable private bundle:
the code, a Virtual Broker config copy with the admission public key and
approvals, a Gate config copy with the Gate client public key, a native Core
authorization catalog with distinct Client/Agent public keys, and a public
profile named by the code's SHA-256 lookup ID. Inputs must be owner-only and
already configured. It does not start or reload services. Activate the checked
config copies explicitly after reviewing the changes and place the profile at
`/.well-known/shadow6/LOOKUP_ID.json` on the advertised HTTPS origin. Its TLS
certificate must validate for the IPv4 address. Public-node Gate servers use a
fixed port with `mtd.enabled:false`; adding a peer key to a rotating Gate
changes the rotation result and would disconnect existing peers. Gate still
authenticates each peer and protects TCP frames.

The other two modes use the same 40-character format:

- `directory`: host profiles on an operator-selected trusted HTTPS directory;
  configure that directory once on each client.
- `manual`: supply an owner-only profile over a separately authenticated
  channel; Android also requires the full Gate public key as a manual pin.

On a desktop, `shadow6 join-code install CODE --core go --role client
--output-dir NEW_DIR` fetches and validates the profile (add `--directory URL`
or `--profile FILE --pin GATE_PUBLIC_KEY` for the respective modes) and writes owner-only Gate and
Virtual Peer configs. Check them with `shadow6-gate --config gate.json
--check-config` and `shadow6 virtual-client --config virtual-peer.json --check`.
Then start the Gate, Virtual Peer, and same-family native Core under your
supervisor. The generated proxy listens at `127.0.0.1:1087`; Gate listens at
`127.0.0.1:1086`. `core.seed` is a distinct per-family, per-role native Core
identity derived from the code; put it in the Core's owner-only configuration
using that family's documented format. The operator must apply the generated
native authorization catalog to the real Broker and Agent ACLs before the
invitee connects. The code contains no Broker or Agent server private key.

Android can import all three code modes into its encrypted app-private secret
store and validates the bounded HTTPS or manually pinned profile. When a
compatible native Core is installed in the APK, its Client or Agent screen can
select **Use saved public node**. That starts the packaged Gate, a bounded
loopback Virtual Peer, and the selected same-family Core with the profile's
pinned native Broker key. The native Core still needs its own local identity;
the public Broker and Agent ACLs must authorize it. Android's Virtual Peer uses
the platform Ed25519 provider, which is standard on Android 13+; older releases
fail closed if no provider is available. Android packages only the Core families
enabled for that APK/ABI. The full 12-family benchmark and platform builds run
in Actions; an invitation cannot add a Core binary missing from a platform.

An offer has this strict versioned form:

```json
{
  "schema_version": 1,
  "suite": "public6",
  "core": {"family": "shadow6-go", "version": "1.1.0"},
  "applications": {"shadow.chat": [1, 2]},
  "dimensions": {"transport.optional": ["kcp", "quic"], "crosed.level": ["5"]},
  "extensions": {"org.example.codec": [1, 3]}
}
```

Application and extension maps negotiate the highest shared version. Generic
dimensions negotiate all shared values. A map may be empty, and keys or values
present on only one peer are ignored. Consequently two same-Core peers with no
common application, Crosed, transport, or extension values are still base-
compatible. Offers are limited to 1 MiB, reject floats and unknown top-level
fields, bound every collection/string, and reject symlink input files.

### Virtual Broker runtime and concurrency

The executable uses the same installed-runtime selection as S6NA: prefer Python
3.14 free-threaded with compatible cryptography, otherwise fall back to a working
GIL runtime (Python 3.11+). Set `SHADOW6_PYTHON` for an explicit interpreter and
`PYTHON_GIL=1` to test a free-threaded build with its GIL enabled. Probes inspect
GIL state after dependency imports; startup does not install packages or force
incompatible extensions into no-GIL operation.

Replay admission reserves nonces under a lock, after signature verification,
so concurrent submissions cannot accept the same credential twice. Replay state
is capped at 65,536 live entries and expires through a heap. Relay connections,
shared tenant rate accounting and connection quotas remain owned by one asyncio
event loop per Broker. Do not share a Broker's relay across event loops. Both GIL
modes use the same authentication and resource limits; no-GIL mode is not an
implicit multi-process or multi-loop deployment.

CI benchmarks both modes with identical workloads on Linux, macOS and Windows
x64. Windows covers the portable in-memory-config relay; production configuration
loading still requires POSIX ownership, mode and no-follow file protections and
is not claimed as a Windows deployment path.
