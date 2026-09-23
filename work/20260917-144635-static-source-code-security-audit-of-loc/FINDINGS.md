# Shadow6 static security review — recorded findings

Scope: local source audit (offline). No target was contacted; all probes were
run against locally built Core binaries with locally generated Ed25519 keys
under /tmp. Case root: this directory.

## F1 (Medium) — Crosed grants a requested level even when no capability is granted
- Evidence: probe_grant.py case [A]. With a trust policy of max_level=5 but
  capabilities=["observe.version"], a signed request with
  requested_level=5 and capabilities=[] returned:
    go   -> status=granted level=5 caps=<empty/None>
    rust -> status=granted level=5 caps=[]
- Expected: the grant is defined as the intersection of build features, signed
  request, per-Mod level, capability allowlist and domain policy (AGENTS.md
  architecture invariants). An empty grant should deny, or drop granted_level.
- Impact: a Mod holding no capability is issued granted_level=5. Latent today:
  Extension-System/shadow6_extensions.py requires transport.application to be
  present in granted_capabilities, so it does not currently consume a bare
  level-5 grant. Any future consumer reading granted_level alone would
  over-trust.
- Fix direction: `granted_level := max(crosedCapabilityLevels[c] for c in granted)`
  when capabilities are requested, and return status="denied" (reason
  "no requested capability is granted") for an empty requested list.

## F2 (Low) — Crosed request signature is not replay-protected
- Evidence: probe_grant.py case [D]. The byte-identical signed request
  (same nonce, same issued_at) was accepted twice by both cores → status=granted
  both times.
- Contrast: Application-Layer/shadow_protocols.py implements ReplayWindow with
  bounded capacity, and Core-Go/main_test.go asserts a replayed local-discovery
  request receives no second offer. Crosed is the outlier.
- Contributing factor: request nonce is 16 bytes but it is NOT bound into the
  signed payload (crosedSignedPayload for Go/Rust omit the nonce; crosedctl
  likewise). The nonce is unused for uniqueness, so it cannot be used as a
  replay key despite the field's name.
- Residual risk is bounded by the ±300 s validity window and by the fact that
  requests are owner-only files (mode 0600) rather than network input.
- Fix direction: maintain bounded replay state (seen nonce+Mod, bounded
  capacity, expiry) persisted for at least the validity window; bind the nonce
  into the signed payload.

## F3 (Informational) — float rejection is fail-closed but inconsistent
- Both cores do reject floats on the signed path: Rust with an explicit
  "Crosed numbers must be portable integers" error, Go via writePortableJSON
  (json.Number.Int64()) which makes crosedSignedPayload return nil and the
  request fails signature verification. Empirically verified.
- Gap: Go's validateStrictJSON (Core-Go/strict_json.go) performs no float check,
  so on non-signature paths (config.go decodeStrict) a float is parsed and then
  silently truncated by Go's float64→int64 conversion in the typed decode.
  Rust's strict JSON accepts f64 only if finite/representable, and Python
  rejects floats outright (Application-Layer/shadow_protocols.py).
- Fix direction: add the float rejection to the shared Go strict JSON walk so
  all three languages agree.

## F4 (Pre-existing, not a code vuln) — Core-Nim audit failure
- `make audit` reports FAIL for Core-Nim/shadow6-nim and shadow6-nim-crosed:
  "error while loading shared libraries: libdatachannel.so.0.23".
  Summary 78 passed, 2 failed, 1 skipped. The Nim cores are the only Cores that
  link libdatachannel dynamically, which also conflicts with the
  no-shared-library-dependency hardening expectation. Outside this review's scope.

## Verified controls (selected)
- Crosed grant intersection: per-Mod policy, signature, level, capability
  allowlist and Qubes domain policy all enforced; unauthorized capability and
  disallowed cross-domain both denied on both cores (probe case [C]).
- Qubes fail-closed: absent domains normalize to "default"; partially specified
  cross-domain requests fail closed.
- Go/Rust L5 feature reports match: level 5, app_transport true,
  qubes_isolation true, utf8 true, identical 10-capability list.
- Owner-only secret handling: readOwnerOnlyFile and the Python/Crosed
  equivalents use Lstat + secureConfigFile/secureConfigPath, recheck via
  os.SameFile after open, enforce size bounds.
- Control Center: loopback-only, bearer auth (32..4096 visible ASCII),
  duplicate Authorization rejected, WWW-Authenticate realm, read-only by
  default with explicit --allow-mutations, ABC monotonic transaction.
- Plugin System: Ed25519 signer + sha256 code digest verified before start,
  manifest field set exact, plugin root symlink/ownership checks, directory
  escape checks, setrlimit CPU/AS/FSIZE/NOFILE/NPROC, unshare --user --net
  --ipc --uts --pid --fork isolation. Plugins are not loaded in-core.
- Service-Init: all four escaping contexts correct (shlex.quote for shell,
  systemd "%%" escaping, xml.sax.saxutils with quote entities for launchd
  plist, Guile Scheme backslash/quote escaping); paths must be absolute with
  no control characters; name constrained by SAFE_NAME_RE.
- Webhook URL validation matches between Go and Rust (absolute HTTPS, no
  credentials, no fragment, length and CR/LF/NUL bounds).
- Plugins and packaged artifacts: all bundled plugin manifests and code
  digests verified; shadow6_audit.py --source-only 6 passed / 0 failed.
