# Native Ziokt support

Default disabled, independently shipped. `shadow6 ziokt capabilities` reports
the local contract without starting a listener or creating Ziokt state.

Private configuration is `~/.config/shadow6/ziokt.json`, or selected explicitly
with `shadow6 ziokt --config FILE`. Start from `config.example.json`, retain mode
0600, and explicitly set enabled to true only for the intended federation and
provider IDs. Writes remain unsupported by the initial read-only profile.

`shadow6 ziokt rpc --stdio` consumes one bounded JSONL request plus EOF. The
service inventory reuses the native ServiceRegistry validator without invoking
its locking/migration decorators, reports stored metadata, and excludes native
configuration, credentials, PID and endpoint contents. No Core wire protocol or
default feature level is changed.

The vendored protocol is synchronized from Ziokt/spec/provider_runtime.py during
development; running Shadow6 never needs the Ziokt checkout. `make ziokt-test`
tests native routing, disabled behavior, exact framing and installed layout.
