# Shadow6 plugin system

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
