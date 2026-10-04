# libshadow6

`libshadow6` is the Python application facade for a locally managed Shadow6
deployment. It asks Control Center for registered Core boundaries, selects a
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

For an explicitly configured S6NA companion, `Shadow6.open_credited(path)`
opens a separate bounded application attachment from an owner-only
`shadow6.s6na-attachment.v1` document. It requires absolute pinned UDP
endpoints, an owner-only 32-byte key file, and a selected S6NA family. The
returned `CreditedSession` exposes `application_credit()`, whole-record
`send_record()` and bounded `receive_record()`; exhausted frame credit raises
`S6NA_BACKPRESSURE`, and closing invalidates queued credit. This companion
does not alter or infer Named Service/Core wire compatibility. Both peers need
matching local configurations and the same secret key, provisioned through a
separate trusted channel.

Keep deployment in a strict `shadow6.deployment.v1` manifest and run
`shadow6 deployment validate` and `shadow6 deployment plan` before opening an
application session. The facade consumes the Core's declared boundary through
`S6ABI/1`; separately shipped Core names are accepted when their signed report
declares a compatible boundary. This is capability selection, not native wire
protocol negotiation.

## Named Service connections

`Shadow6.connection_plan("home/nas")` returns the same structured plan as `shadow6 connect home/nas --json`. `with Shadow6().connect("home/nas") as session:` actually attaches to a process-owned, structured-ready loopback TCP client application proxy. Use `session.send(bytes)` and `session.receive()`; unsupported boundaries raise a capability error. This session is bounded to 300s/16MiB and 30s socket inactivity. S6P1 owns intent, S6AR1 control transport, S6ABI application boundaries; local PID/config/digests stay outside S6P1. See [service connections](../docs/service-connections.md).
