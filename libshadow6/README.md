# libshadow6

`libshadow6` is the application facade for a locally managed Shadow6
deployment. The versioned direct attachment API and C/C++ application ABI are
documented in [Application SDK](../docs/application-sdk.md). `connect_handle()`
returns a structured handle and native socket/fd; it does not forward packets.
`ControlClient` optionally reuses a persistent loopback control connection.

The legacy capsule API It asks Control Center for registered Core boundaries, selects a
matching client boundary, starts a capability capsule, returns its loopback
endpoint, and owns the capsule until the session or facade closes. It does not
implement a Core wire protocol.

The reference facade is Core-explicit. Call `resolve()` to inspect candidates,
then call `open(core=..., config=..., require=...)`; multiple compatible Cores
produce `AmbiguousCoreSelection` and are never resolved by ordering.

```python
from libshadow6 import Shadow6

s6 = Shadow6()
print(s6.features())
print(s6.features("pony"))
print(s6.call("guide", "--lang", "en"))

with Shadow6() as s6:
    session = s6.open(
        {"kind": "stream", "reliable": True, "ordered": True},
        core="rust",
        config="/etc/shadow6/client.json",
    )
    print(session.core, session.endpoint)
    # Connect application data to session.endpoint["host"] / ["port"].
```

`features()` returns one `shadow6.features.v1` object containing the default
Go, Rust, and Gate reports. `features(component)` returns that component's
report. The facade asks the CLI for its aggregate JSON form; it does not parse
concatenated JSON documents.

`make install` places the package under the selected Python interpreter's
standard `lib/pythonX.Y/site-packages` directory, so `from libshadow6 import
Shadow6` works with that interpreter after installation. Set `SHADOW6_CLI` when
the executable is outside `PATH`. Calls use the instance's executable directly
and do not modify process-global environment variables. The package fails
closed when no installed CLI is available. `open()` selects only Control Center
registered Core entries whose client boundary matches every key in `require`;
matching metadata does not mean the Core wire protocols are interchangeable.
Core-owned stream and UDP datagram boundaries provide their actual listener
endpoint. Gleam Micro-Mux is advertised as best-effort, unordered UDP; request
it explicitly with `kind="message"`, `mode="localhost-udp-datagram-proxy"`,
and `reliable=False`. A `seqpacket-fd` message boundary requires an explicit
`port`, `protocol`, and loopback `host`. Pass the
Core config as `config` or set `SHADOW6_CONFIG`. Capsule start requires the
local Control Center registry and its explicit mutation authorization. Closing
the session or leaving the facade context stops its capsule; Control Center TTL
cleanup is the abandoned-client backstop. Sessions also expose `status()`,
`pause()`, and `resume()` through the same Control Center lifecycle methods.

`Shadow6.open_application(name)` attaches through the Profile selected and
locked by the Named Service. The application does not pass a Core or Profile
name. If the lock contains S6NA material, the facade selects that adapter
automatically and allocates a free stream on its shared pinned UDP endpoint;
otherwise it opens the Native Profile's observed local endpoint. S6NA supports
all thirteen Native Profiles, including the distinct Gleam Micro-Mux policy.
The Native Core wire protocol and its declared application boundary remain
unchanged.

S6NA sessions share one transport endpoint instead of binding one UDP socket
per application. Separate calls receive distinct stream IDs, bounded receive
queues, and independent close behavior. `send_record()` and `receive_record()`
preserve message boundaries; `send()` and `receive()` provide a byte stream
facade for stream Profiles. Frame credit remains visible through
`application_credit()`, and exhausted credit raises `S6NA_BACKPRESSURE`.
`Shadow6.connect_native(name)` selects the local Core endpoint explicitly;
`open_credited_for_service(name)` remains available when an application needs
record-level S6NA control. Both peers provision the same owner-only 32-byte
key and matching pinned UDP configuration through a trusted channel.

Keep deployment in a strict `shadow6.deployment.v1` manifest and run
`shadow6 deployment validate` and `shadow6 deployment plan` before opening an
application session. The facade consumes the Core's declared boundary through
`S6ABI/1`; separately shipped Core names are accepted when their signed report
declares a compatible boundary. This is capability selection, not native wire
protocol negotiation.

## Named Service connections

`Shadow6.connection_plan("home/nas")` returns the same structured plan as `shadow6 connect home/nas --json`. `with Shadow6().connect("home/nas") as session:` actually attaches to the Profile's process-owned, observed stream or message boundary. Use `session.send(bytes)` and `session.receive()`; unsupported boundaries raise a capability error. This session is bounded to 300s/16MiB and 30s socket inactivity. S6P1 owns intent, S6AR1 control transport, S6ABI application boundaries; local PID/config/digests stay outside S6P1. See [service connections](../docs/service-connections.md).

## Versioned handles and peers

`connect_handle` now exposes the locked native or credited S6NA socket through
the same versioned handle. `peer(name, fallback_services=[...])` supplies explicit
same-policy fallback, cancellation and reconnect; it does not implement seamless
migration or SDK ICE. The POSIX C ABI prefers SCM_RIGHTS FD Gateway handoff and
retains Python fallback. Windows uses the explicit native socket.share/fromshare
backend instead of fd integers. See [ownership, bounds and platform assumptions](../docs/application-sdk.md).
