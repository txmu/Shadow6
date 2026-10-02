# libshadow6

`libshadow6` is the Python application facade for a locally managed Shadow6
deployment. It asks Control Center for registered Core boundaries, selects a
matching client boundary, starts a capability capsule, returns its loopback
endpoint, and owns the capsule until the session or facade closes. It does not
implement a Core wire protocol.

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
