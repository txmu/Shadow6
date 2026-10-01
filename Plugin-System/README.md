# Shadow6 plugin system

The signed out-of-process Plugin boundary grew out of the late-August
platform refactor and was integrated into the Extension contract during the
2026-09-01 to 2026-09-06 transition. It remains a runtime component contract
rather than a Native Core ABI: plugin changes do not require recompiling a Core.

Plugins are separately executed JSON processors. They never load into the Go,
Rust, Guard, Relay, Detector, or Orchestrator process. Every launch verifies:

- an exact versioned manifest schema;
- the entrypoint SHA-256 digest;
- an Ed25519 signature from `trusted_signers.json`;
- owner-only mutation of manifest, trust store, and entrypoint;
- a deny-by-default capability grant;
- request/output sizes, CPU time, memory, file descriptors, child processes,
  wall-clock timeout, and Linux `no_new_privs`;
- a separate user/network/IPC/UTS namespace, so plugins cannot use the host
  network directly.

The protocol is one JSON object on stdin and one JSON object on stdout. Host
events use `shadow6.plugin.v1` and named hooks such as `hook.mtd.before` and
`hook.mtd.after`. New host APIs should be mediated by a narrow capability—not
by giving a plugin arbitrary access to the orchestrator internals.

Commands:

```sh
.venv/bin/python Plugin-System/shadow6_plugins.py list
.venv/bin/python Plugin-System/shadow6_plugins.py verify maze-runner
.venv/bin/python Plugin-System/shadow6_plugins.py game number-guess
.venv/bin/python Plugin-System/shadow6_plugins.py game rock-paper-scissors
.venv/bin/python Plugin-System/shadow6_plugins.py game maze-runner
```

To create a plugin, copy one bundled directory, choose a unique lowercase ID,
declare only required capabilities/hooks, and keep the entrypoint below 1 MiB.
Generate an Ed25519 key outside the repository, add its raw public key to a
deployment-specific trust store, then sign:

```sh
openssl genpkey -algorithm ED25519 -out plugin-signing-key.pem
.venv/bin/python Plugin-System/sign_plugin.py plugins/my-plugin/plugin.json \
  --private-key plugin-signing-key.pem --signer my-organization
```

Do not distribute the signing private key. Treat adding a trust-store signer as
a security-sensitive administrative action.

## Extension and Slot integration

`Extension-System` is the only combined entrypoint. It verifies the Crosed
request and its `shadow.extension` application frame before calling
`Slot-System`; Slot bindings then require the provider's signed manifest to
declare the selected slot as both capability and hook. Use `shadow6-extensions`
or Control Center's `extensions.invoke` for the complete transaction. Calling a
plugin executable directly does not grant it extension or Core privileges.

The manifest, trust store, binding file and entrypoint are all bounded,
owner-controlled inputs. Keep the signing key outside the repository and make
trust-store changes an explicit deployment action. A missing signature,
capability, hook, provider, sandbox prerequisite, or approval is a hard deny.
