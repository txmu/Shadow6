# LLM Lifecycle

`service.connect` remains a read-only `shadow6.connection-plan.v1` resolver. It never opens a socket, starts a Core, or claims a session. LLM intent is recorded as a reviewed plan; runtime truth comes only from the canonical Named Service status and its authenticated runtime observation.

The controlled lifecycle is:

1. Resolve and review `service.connect`; retain the digest of the exact returned plan, its material digest, and its DeploymentLock digest.
2. Execute `service.connect_execute` with `confirmed: true` and all three digests. The registry re-resolves the plan in one transaction and rejects plan, material, or lock drift (`ReviewedPlanChanged`, `ReviewedMaterialChanged`, or `ReviewedLockChanged`).
3. When the reviewed runtime is `application-ready` and advertises a supported local stream/message attachment, `connect_execute` opens that existing attachment through `open_local_session` and returns a short-lived opaque process-local capability handle. `sessionState=connected` is returned only after this real attachment succeeds. Listener-only readiness returns `transport-ready`; application readiness without a supported local launcher returns `application-ready` and no handle.
4. Use `service.session_read`, `service.session_write`, and `service.session_close` for bounded data-plane access. These operations use the already-approved bearer capability and therefore do not ask the human to reconfirm each chunk, but they still require the adapter to have been started with `--allow-mutations`.
5. End the whole Named Service lifecycle with `service.disconnect`, again requiring explicit confirmation and the reviewed lock digest. Disconnect/stop/restart/remove close all process-local handles for that service before the canonical runtime is stopped.

The session handle is not persisted and contains no fd, socket path, or endpoint secret. The process owns at most 64 handles. Existing native session limits remain authoritative: at most 300 seconds and 16 MiB per local session. Control RPC adds a 5 second per-operation timeout, at most 65536 bytes per read, and at most 32768 decoded bytes per write. Message boundaries are preserved: one `session_write` is one application record, and `session_read` returns exactly one record; callers must request a read bound at least as large as the Profile's `maxRecord`. Stream reads are ordinary bounded byte chunks. EOF closes the handle. Expired handles are reaped lazily and process exit closes all remaining handles.

The Control API, MCP, OpenAI function, LSP, JSONL, and HTTP adapters keep their existing read-only defaults. All four session methods (`connect_execute`, read, write, close) require the adapter to be started with `--allow-mutations`. Only `connect_execute` requires the original explicit human confirmation; the returned random handle is the bounded capability for subsequent session I/O. Core and Profile bindings, DeploymentLock, runtime observation, and the existing `LocalSession`/`LocalMessageSession` implementations are reused directly; no persistent Agent state model is introduced.

A reviewed connect request remains explicit:

```json
{
  "method": "service.connect_execute",
  "params": {
    "name": "home/nas",
    "confirmed": true,
    "expected_plan_digest": "sha256:<reviewed-plan-digest>",
    "expected_material_digest": "sha256:<reviewed-material-digest>",
    "expected_lock_digest": "sha256:<reviewed-lock-digest>"
  }
}
```

A successful local attachment adds:

```json
{
  "sessionState": "connected",
  "session": {
    "schema": "shadow6.application-session.v1",
    "handle": "<opaque-random-capability>",
    "boundary": "stream",
    "recordPreserving": false,
    "lifetimeRemainingMs": 299000,
    "bytesRemaining": 16777216,
    "maxReadBytes": 65536,
    "maxWriteBytes": 32768
  }
}
```

Read bytes with:

```json
{"method":"service.session_read","params":{"handle":"<handle>","max_bytes":32768,"timeout_ms":5000}}
```

The result carries `dataBase64`, `eof`, and the remaining budgets. Write bytes with strict base64:

```json
{"method":"service.session_write","params":{"handle":"<handle>","data_base64":"aGVsbG8=","timeout_ms":5000}}
```

Close just the attachment with `service.session_close`; closing the same handle again is harmless. `service.disconnect` is different: it is the explicitly confirmed Named Service operation and stops the canonical runtime after closing all handles bound to that service.

CI should exercise plan/confirm/attach/read/write/EOF/close/disconnect; stream and record-preserving message behavior; adapter read-only rejection; invalid/expired handles and bounds; cleanup on stop/restart/remove; and rejection after changing any reviewed material, lock, or plan digest.
