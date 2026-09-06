# Shadow6 component hands and eyes

The eyes create a local, read-only inventory for Core-Go, Core-Rust, Guard,
Relay, Orchestrator, Detector, Plugins, Crosed, the application layer, and the
assistant infrastructure. A snapshot contains source/binary digests, modes,
Core feature contracts, exact matching running PIDs, and a stable snapshot ID.
`drift` compares trusted snapshots without treating ordinary PID changes as
source or binary drift.

The hands execute only six fixed runbooks: `build`, `test`, `check`, `audit`,
`integration-test`, and `package-release`. Execution requires an Ed25519-signed
plan bound to the exact repository path, action, 16-byte nonce, key ID, and a
validity window of at most five minutes. Plans are single-use through a locked
owner-only replay journal. There is no command, argument, or shell-text field.

```sh
.venv/bin/python Infrastructure-Assistants/shadow6_infra.py observe \
  --output /tmp/shadow6-baseline.json
.venv/bin/python Infrastructure-Assistants/shadow6_infra.py drift \
  --baseline /tmp/shadow6-baseline.json
```

Generate an approval key with the security assistant, then create and execute a
short-lived runbook plan:

```sh
.venv/bin/python Security-Assistants/shadow6_security.py ledger-keygen \
  --private-key /secure/runbook.pem --public-key /secure/runbook.pub.json
.venv/bin/python Infrastructure-Assistants/shadow6_infra.py plan \
  --action audit --private-key /secure/runbook.pem --output /tmp/audit-plan.json
.venv/bin/python Infrastructure-Assistants/shadow6_infra.py execute \
  --plan /tmp/audit-plan.json --public-key /secure/runbook.pub.json
```
