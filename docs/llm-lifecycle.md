# LLM Lifecycle

`service.connect` remains a read-only `shadow6.connection-plan.v1` resolver. It never opens a socket, starts a Core, or claims a session. LLM intent is recorded as a reviewed plan; runtime truth comes only from the canonical service status and its authenticated runtime observation.

The controlled lifecycle is:

1. Resolve and review `service.connect`; retain the digest of the exact returned plan, its material digest, and its DeploymentLock digest.
2. Execute `service.connect_execute` with `confirmed: true` and all three digests. The registry re-resolves the plan in one transaction and rejects plan, material, or lock drift (`ReviewedPlanChanged`, `ReviewedMaterialChanged`, or `ReviewedLockChanged`).
3. Treat success as a session only when the returned status contains a valid runtime observation. A plan or process-alive state is not session evidence.
4. End the lifecycle with `service.disconnect`, again requiring explicit confirmation and the reviewed lock digest. This uses the canonical stop/runtime cleanup path.

The Control API, MCP, OpenAI function, LSP, JSONL, and HTTP adapters keep their existing read-only defaults. Mutating lifecycle calls require the adapter to be started with `--allow-mutations`; confirmation is still mandatory in the request. Core and Profile bindings, DeploymentLock, and runtime observation are reused directly, and no Agent state model is introduced.

CI should exercise plan, confirm, execute, observe, and disconnect, plus rejection after changing any reviewed material, lock, or plan digest.

The request shape is intentionally explicit:

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

The returned object is the canonical service status with a
`runtimeObservation` and `sessionState`. To close it, submit
`service.disconnect` with `confirmed: true` and the same reviewed lock digest.
Adapters remain read-only unless started with `--allow-mutations`; that flag
does not replace human confirmation or digest checks.
