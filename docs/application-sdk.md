# Application SDK: direct native attachments (v1)

An operator binds a Named Service to an explicit Core and Native Profile using
`shadow6 setup`. Applications select that service; changing its locked Profile
does not add a Core branch to application networking code. The canonical
ServiceRegistry still performs material/lock/HostBudget admission. No SDK
operation chooses a different Core, relocks drift, or substitutes a relay.

`Shadow6.connect_handle(name, timeout=10, cancellation=threading.Event(),
require={...})` obtains the canonical connection plan and opens its observed
ApplicationBoundary. It returns `ConnectionHandle`, with a frozen versioned
`BoundaryDescriptor`, `socket`, borrowed `fileno()`, caller-owned `dup_fd()`,
`describe()`, canonical `status()`, and idempotent `close()`/`disconnect()`.
There are at most 64 attachments and pending connects per facade. Capability
and ownership tests are distinct from real transport verification.

For a persistent control connection, explicitly create
`ControlClient(token_file, port=9466)` and pass `Shadow6(control=client)`.
The backend remains loopback-only and bearer-authenticated. The caller owns
and closes this control client separately. `profiles()`, `service_status()` and
`lifecycle(method, params)` reuse dispatcher operations. Lifecycle mutations
require the same explicit confirmation and reviewed digests as other adapters.
There is no implicit create/run/stop associated with attachment lifetime.
Legacy `connect`, `open_application`, `open`, and credited APIs remain intact.

The data path is the returned native socket, with no CLI/JSON/RPC per packet.
Use `send/recv`, `recv_into`, scatter/gather, and the application's own event
loop. This avoids SDK forwarding and unnecessary user-space copies; it does
not claim kernel zero-copy for every socket or Core.

| Logical boundary | Realization | Application semantics |
| --- | --- | --- |
| stream | localhost-tcp-proxy | bytes; application supplies framing |
| message | localhost-udp-datagram-proxy | one datagram per send; best effort, unordered |
| message | seqpacket-fd | one bounded record per send; owner-checked Unix attachment handshake |

`reliable`, `ordered`, and `freshness_preferred` are nullable: null means the
Profile does not promise that capability. A local seqpacket socket does not
prove native end-to-end reliability. Requirements match declared capabilities;
unknown cannot satisfy a true or false requirement. Oversize and EOF behavior
remain the Native Profile's contract. In particular, seqpacket empty records
mean drain/EOF; UDP empty datagrams remain datagrams. Raw record reads must use
`recvmsg` and reject `MSG_TRUNC`. No record-to-stream conversion is implicit.

The descriptor schema is in `libshadow6/schemas`. Descriptor v1 is immutable
metadata; handle v1 includes current SDK lifecycle state, the locked binding,
endpoint, runtime identity, and canonical readiness evidence. Peer/session
identity is null when the authority does not publish it; local PID identity is
not presented as authenticated remote identity. WebRTC envelope readiness is
admitted by the existing ServiceRegistry's current authenticated transport
observation, rather than by the SDK probing a port.

The original fd is borrowed until close. `dup_fd()` creates a non-inheritable
reference owned by the caller. Duplicates share socket queues/options and can
keep an attachment alive after the handle closes; applications must close all
of them. Python control operations are serialized, but applications must
synchronize data I/O, changing blocking flags, and close. Each facade owns its
new handles; facade close closes attachments, never the Named Service runtime.
No finalizer stops a service. Process exit releases owned OS descriptors.
Do not fork with live SDK/control objects; close inherited descriptors in the
child and create a fresh facade. A direct fd does not have the web terminal's
300-second/16-MiB facade budget; native Profile and deployment limits still
apply. Applications own queue/record limits after handoff.

Build the C/C++ application attachment interface with
`make -C libshadow6/native check` (POSIX, pthreads, Python development headers
and libpython). `shadow6.h` negotiates `S6_APPLICATION_ABI_V1`; descriptor
queries use caller-sized buffers. It embeds the same Python control facade and
hands the application a native fd. This is an application ABI, not a shared
native data ABI for twelve Cores. The interpreter remains alive; do not unload
libpython or finalize it before destroying handles. C destroy must be serialized
against every use of that pointer. Windows HANDLE integration is not implemented.

`libshadow6/examples/direct.c` demonstrates connection/descriptor/fd ownership;
`libshadow6/examples/game.py` owns a bounded 60Hz event loop and stream framing.
Run the latter against a real operator-provisioned echo peer. Matchmaking and
session material provisioning remain the application's integration with the
existing explicit deployment workflow.

The direct handle currently rejects a locked S6NA credited facade with
`DirectBoundaryUnavailable`; it never bypasses the locked adapter. Existing
`open_application()` supplies that facade. A transferable direct S6NA local
boundary, remote authenticated identity publication, negotiated mixed reliable
control/unreliable game flows, and explicit relay fallback orchestration require
additional implementation and verification. NAT rebinding and seamless session
migration are not claimed.

The existing thirteen-Profile Named Service integration gate exercises both
legacy attachments and the direct handle with real installed artifacts, native
trios, payload correctness, 60Hz ticks, process restart and cleanup. It does not
by itself establish WAN or NAT traversal evidence. Test Lab's Native and legal S6EPE worker paths also consume this handle, send
60Hz bounded state updates and, only with declared reliability, intermittent
control records. They publish loss/latency and unsupported control-flow
capabilities separately and retain existing WAN/PCAP/artifact admission. The
full WAN matrix requires CI execution; local loopback verification does not
prove that matrix or NAT traversal.
