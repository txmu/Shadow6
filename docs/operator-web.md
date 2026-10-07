# Operator Web surface

`shadow6 web` explicitly starts a loopback Control Center with its mutation gate
and a separately authenticated gateway at `http://127.0.0.1:9467/`. Existing
MCP/LSP/JSONL/HTTP adapters retain their defaults. `--open-browser` optionally
opens the page. The command prints a one-time pairing code, valid for ten
minutes. Pairing issues an HttpOnly SameSite=Strict cookie; JavaScript keeps
only the CSRF nonce and short-lived application session capability in memory.
The browser never receives the backend bearer credential. Gateway restart
invalidates all Web sessions. This is one instance/one Operator, with no RBAC.

`shadow6 web init` prepares owner-only state under
`~/.local/share/shadow6/web`; `--state-dir` is an operator CLI choice, not a
browser path selector. State directories require mode 0700; credential files
require stable owner-controlled regular files, no symlink, mode 0600, bounded
size and checks after opening. Operator pairing and backend credentials differ.
Serving generates a fresh pairing credential; it never changes service locks.

The gateway accepts only GET/HEAD/POST on fixed routes. Its upstream is always
`127.0.0.1:<backend-port>` and its backend headers are freshly constructed:
client bearer, forwarding and hop-by-hop headers are discarded. It rejects
Upgrade, arbitrary upstream selection, redirects, cross-origin requests and
unsupported HTTP methods. POST requires the exact Origin and, after pairing,
a session-bound CSRF nonce. Requests/responses, connections, concurrency,
pairing attempts and global request rate are bounded. No CDN, CORS, arbitrary
filesystem browser, shell, or component-specific control API is added.

The six navigation entries are Overview, Services, Connect, Profiles, Lab and
System. Services displays observed readiness and limit evidence and opens an
operator workspace. Run/stop/restart/apply/remove use server-authoritative
method metadata, explicit confirmation and the reviewed lock. Remove requires
typing the service name. Changed lock/material/plan digests are never retried.
`service.connection_review` provides the authoritative execution digests before
Connect. The terminal distinguishes byte chunks from message records, supports
Text/Hex/Base64, displays remaining time/bytes, and performs only one outstanding
bounded long-poll read. Closing its attachment does not stop a Named Service.
Page exit attempts session close; backend TTL remains the cleanup backstop.
The System page runs the canonical read-only doctor and can revoke Web sessions.

The gateway's session table is memory-only, at most 16 entries, with a 30-minute
idle timeout and 12-hour absolute lifetime. HTTPS uses `__Host-shadow6_session`;
loopback HTTP uses a separately named non-Secure cookie because HTTP cannot set
a usable Secure cookie. Non-loopback listening requires explicit TLS certificate
and key, using stdlib/OpenSSL TLS. No unauthenticated mode exists. Host authority
must match the actual local address and port; DNS virtual hosts are not supported.
The backend still binds only loopback. Prefer deployment through an explicitly
configured Shadow6 service when remote access is needed; `web expose` automation
is not implemented.

This Operator surface is an incremental implementation. Typed config-store
forms/create wizard, semantic configuration diffs, configuration save/relock,
activity history, Test Lab report ingestion and evidence drilldowns are not yet
implemented. The Lab page says when no verified report is attached rather than
inventing PASS counts. Services configuration remains on the canonical CLI.
Mobile service tables become stacked cards; visual browser/assistive-technology
verification is still required in addition to HTTP and JavaScript checks.
