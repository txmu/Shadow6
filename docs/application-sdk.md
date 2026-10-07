# Application SDK and handle ownership (v1)

Operators choose an explicit Core and Profile and provision a Named Service.
Applications consume its Application Boundary through `Shadow6.connect_handle`
or `Shadow6.peer`; application networking has no Core selection branch. The
existing ServiceRegistry remains the material, lock, policy and admission
authority. Attachments do not create, relock or stop an independent service.

```python
from libshadow6 import Shadow6

with Shadow6() as sdk, sdk.peer("home/game") as peer:
    handle = peer.connect(timeout=10)
    print(handle.describe())
    # Use handle.socket with the application's own framing/event loop.
```

`ConnectionHandle` owns its attachment. `fileno()` is borrowed until close;
`dup_fd()` returns a caller-owned non-inheritable POSIX duplicate. Duplicates
share socket queues/flags and can survive handle close. Close every duplicate
and serialize I/O, flag changes and destruction. `close()` is idempotent, and
facade close closes its attachments. Neither action stops the Named Service.
`status()` checks the current canonical lock and observable socket failures.
Remote identity remains null when the authority has no authenticated remote
identity to publish; a local PID is not a remote authentication claim.

## Native ABI and transfer backends

Build only the small C/C++ attachment library with
`make -C libshadow6/native check`. It requires POSIX, pthreads and Python
embedding headers/libpython. It builds on Linux and macOS. `shadow6.h`
negotiates `S6_APPLICATION_ABI_V1`; descriptor queries copy versioned JSON into
caller-sized buffers. This ABI does not make twelve Core wire formats compatible.

With `SHADOW6_CONTROL_SOCKET` and `SHADOW6_CONTROL_TOKEN_FILE`, C and Python
prefer the existing FD Gateway. It executes a fresh canonical connection review
and `connect_execute`, checks the local peer UID, and transfers exactly one
socket using SCM_RIGHTS. Linux uses Unix seqpacket control messages; macOS uses
bounded length-prefixed Unix stream control messages. The credential is a
stable owner-controlled mode-0600 regular file, and the socket and parent are
owner-only. Each request has a cryptographic nonce and bounded issuance window;
replays and malformed/truncated/extra-descriptor responses fail closed. Receiving
code closes all unaccepted descriptors. A raw transferred descriptor starts
blocking and non-inheritable; the application chooses its own polling policy.

`s6_connection_open_with_options` accepts a 1..30000 ms timeout and an optional
borrowed POSIX cancellation fd. Readability cancels without consuming or
closing that fd. The old `s6_connection_open` remains a 30-second convenience
entry. Destroy must be serialized against all uses of its connection pointer.

Without a configured FD Gateway, the C ABI retains the Python control fallback.
It initializes Python only when necessary and leaves the interpreter alive;
never finalize/unload Python with live fallback handles. Python also retains
its local observed-boundary fallback. With both gateway variables and
`SHADOW6_APPLICATION_LIBRARY`, Python wraps the same C ABI; Test Lab uses this
mode. Load only a trusted SDK build/artifact. The wrapper snapshots the bounded,
owner-controlled library before loading so path replacement cannot substitute
bytes between validation and loading.

Windows uses `ConnectionHandle.export_handle` and
`WindowsHandleTransfer.receive`, wrapping the actual
WSADuplicateSocket/socket.share/socket.fromshare backend. It checks the explicit
recipient PID and same-user process tokens, authenticates the transfer with a
private control-session credential and expected nonce, enforces a 30-second
expiry, and rejects replay. The recipient owns and closes the returned socket.
Transport the bounded transfer document through the application's already
authenticated private control channel. It is not a file descriptor integer or
an automatic network listener. The POSIX C library is not a Windows DLL; the
Windows handle backend is verified by a Windows kernel/process CI test.

Named Service supervision still requires Linux pidfd and owned runtime
observations. macOS SCM_RIGHTS and Windows handle transfer do not imply a
portable replacement for that supervisor. Native Core platform/transport limits
remain those in each Core README; no hypervisor or NAT capability is inferred.

## Boundary semantics and S6NA

| Kind | Realization | Data and framing |
| --- | --- | --- |
| stream | localhost-tcp-proxy | Native bytes; application framing |
| message | localhost-udp-datagram-proxy | Native bounded datagrams |
| message | seqpacket-fd | Owned bounded native record attachment |
| stream/message | credited-socket | Bounded local socket over the locked S6NA credited session |

`BoundaryDescriptor` publishes kind, realization, semantics, maximum record,
nullable reliability/order/freshness capabilities, ownership and `data_path`.
A local socket does not add native delivery guarantees. Unknown capabilities
cannot satisfy a requested true/false guarantee. Raw message reads must reject
truncation and preserve one record per send. Native seqpacket empty records
retain their declared EOF semantics; UDP empty datagrams are not stream EOF.

A locked S6NA path is consumed through `connect_handle` without bypassing S6NA.
Its bounded worker uses the existing CreditedSession/CreditedPool transport and
credit accounting, with one pending record per direction and bounded socket
buffers. It stops consuming local writes while S6NA has exhausted credits;
local socket queues supply application backpressure. Stream chunks fit the
available frame window; message maxima also respect that window. Profiles'
reliability declarations are preserved. S6NA requires nonempty data records.

`data_path=s6na-credited-socket` distinguishes this forwarding path from
`native-socket`; it is not zero-copy. At most 64 workers are live, with a
300-second/16-MiB boundary budget. Closing a stream fd ends its worker; local
UDP record sockets have no close notification and use explicit handle close or
the finite lifetime. Transferred credited sessions remain tracked for canonical
service stop/remove. Direct Python credited handles additionally check the
service lock/state periodically. Raw native fd handoff has no Web terminal
byte/time budget; deployment and native Profile limits still apply.

## Peer connection state

`PeerConnection` supports idle/planning/connecting/connected/path-failed/
degraded/cancelled/failed/closed states with bounded event history. `cancel()`
and external cancellation events cancel an attempt; `disconnect()` prevents a
late result from being published and closes a completed attachment.
`reconnect()` closes the old attachment and explicitly opens a fresh one.
Late success after timeout/cancellation is closed. Authority queries and local
attachment opens use a bounded pool of sixteen pending operations; timeout
returns promptly and late operations release their capacity when they finish. A naturally drained native
one-flow service may need an operator restart before reconnection.

Fallback services are explicit, distinct and bounded to four. Only declared
retryable path failures trigger fallback. The candidate must match the primary
Core, Profile, S6P1 context and security-policy digest. Actual opened handles
are checked against the reviewed lock/binding, and reconnect pins the original
security identity. A policy/Profile change requires a new peer object and an
explicitly reviewed operator deployment. Network failure produces degraded
state; status never reconnects silently. Matchmaking accepts only an existing
validated S6P1 envelope. Seamless migration and SDK ICE are unsupported.

The real Web/config/ABI integration test uses an existing Go/KCP artifact,
authenticated HTTP and native processes. The thirteen-Profile Named gate and
Test Lab's native/legal S6EPE workers verify native application payloads and
60Hz traffic. Test Lab additionally uses C ABI/SCM_RIGHTS in the owned WAN
namespaces, retaining exact echo, flow ownership and PCAP checks. Loopback
verification alone does not establish WAN, NAT traversal or remote deployment.
