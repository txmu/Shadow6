# Native Ziokt support

Default disabled, independently shipped. `shadow6 ziokt capabilities` reports
the local contract without starting a listener or creating Ziokt state.

Private configuration is `~/.config/shadow6/ziokt.json`, or selected explicitly
with `shadow6 ziokt --config FILE`. Start from `config.example.json`, retain mode
0600, and explicitly set enabled to true only for the intended federation and
provider IDs. Writes also require `allow_mutations`, exact `allowed_operations`
and `allowed_resources`; all default to denied. Fixed native service lifecycle,
signed package install/activation, and explicit cold checkpoint/restore use a
durable prepare/commit journal, leases, postconditions and outbox. A configured
`coordinator_public_key` additionally requires signed monotonic fencing terms.

`shadow6 ziokt rpc --stdio` consumes one bounded JSONL request plus EOF. The
service inventory reuses the native ServiceRegistry validator without invoking
its locking/migration decorators, reports stored metadata, and excludes native
configuration, credentials, PID and endpoint contents. No Core wire protocol or
default feature level is changed.

Ziokt consumes every Core/Profile through the original libshadow6 application
boundary. Core selection and native guarantees stay with the original authority.
Restoring a checkpoint reconstructs stopped services; new native locks and an
explicit start are required. Native admitted peripheral and privacy materials
are preserved without starting their processes or lowering policy requirements.

The vendored protocol is synchronized from Ziokt/spec/provider_runtime.py during
development; running Shadow6 never needs the Ziokt checkout. `make ziokt-test`
tests native routing, disabled behavior, exact framing and installed layout.
