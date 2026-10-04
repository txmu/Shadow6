# Install, run and named services / 安装与命名服务

Native Profile source contracts are available through `shadow6 core profiles`
or `shadow6 core profiles gleam`. Gleam secure-stream and Micro-Mux have
separate Profile IDs and attachment semantics. Profile selection is currently
integrated into fleet/native realization and Named Service ProfileBinding.
The local message adapter has focused supervisor/library/stdio tests; real
all-Profile and credited attachment lifecycle remains an implementation gate.
The source catalog must not be interpreted as thirteen available Named Service
implementations. See [the active requirement ledger](native-profile-runtime-plan.md).

The goal is one explicit lifecycle: install → init → setup → lock/apply → run →
connect/status → restart/stop/remove. A named service always selects a Core;
a name never silently selects or migrates a protocol family.

目标是贯通安装、配置、运行、连接和维护。默认 native 隐私模式、L0 Core 和关闭的
Gate 不会因安装或注册服务而升级权限。Named Service 目前使用 Linux pidfd 管理实际
进程；其他平台继续使用各 Core 原生命令与 Service-Init。

## Install existing artifacts

From a source checkout, use `.venv/bin/python CLI/shadow6.py` instead of
`shadow6` until installation is complete. Use Python 3 when no venv exists.

```sh
# Inspect available artifacts; this does not install or activate a service.
.venv/bin/python CLI/shadow6.py install --json
# Install already-built products; no compile, download or service activation.
.venv/bin/python CLI/shadow6.py install --prefix /home/admin/shadow6-local
# Equivalent staging operation for packaging/validation:
make install-prebuilt DESTDIR=/absolute/staging/directory PREFIX=/usr/local
```

Choose a writable prefix. `--prefix` and `--destdir` accept absolute ASCII paths
containing letters, digits, slash, dot, underscore and hyphen. `make install`
retains the build-then-install workflow; `install-prebuilt` fails when a selected
required artifact is missing. Select the intended components with `BUILD_*`.
It neither starts Gate nor changes host service/firewall configuration.

`install --json` also reports all 13 installed Profile probes and actionable
runtime-prerequisite diagnostics. `shadow6 core profiles [CORE] --installed`
runs these bounded probes without compiling or installing anything. Compilers
are build prerequisites, never prerequisites for an already installed runtime.
Feature/prerequisite admission is not proof of an arbitrary deployment's
credentials, connectivity, or real all-Profile lifecycle CI success.

安装树更新只接受空目录或带正确 `.shadow6-tree` 标记的既有安装目录；不会因为一个
不相关目录恰好含有 Makefile 就清空它。安装只处理已有制品，旧制品仍需在后续正式
发布流程中重建和审计。

## Prepare and run

Prepare the native configuration using the selected Core's README first. The
small binding document references that file; it is not the native config itself.
Both must be regular files owned by the current account, mode `0600`, with no
symlink or extra hard link. Prefer absolute paths in native configuration too.

```sh
umask 077
mkdir -p "$HOME/.config/shadow6"
# First create /absolute/path/core.json using the selected Core's documented schema.
printf '%s\n' '{"config_path":"/absolute/path/core.json"}' > "$HOME/.config/shadow6/binding.json"
chmod 600 /absolute/path/core.json "$HOME/.config/shadow6/binding.json"
shadow6 init --json
shadow6 setup home/nas --core go --profile go-kcp --config "$HOME/.config/shadow6/binding.json" --ttl 3600
shadow6 run home/nas
shadow6 status home/nas
shadow6 doctor home/nas
shadow6 connect home/nas
shadow6 restart home/nas
shadow6 stop home/nas
shadow6 remove home/nas
```

The equivalent granular path is `service create`, `service lock`, `service apply`
and `service run`. `setup` prepares and applies the locked deployment without
starting it; `setup --run` explicitly also starts it. `run` requires an existing
DeploymentLock and never chooses or repairs a Profile.
`service configure NAME --core CORE --profile PROFILE --config BINDING` requires
the service to be stopped. A previously locked service receives replacement
material validation before its old binding/lock is invalidated; failed admission
keeps the original approved record. Reconfiguration then needs explicit
`lock`/`apply` followed by `run`. Repeating an identical
`setup` or `run` reuses a living process. A different binding or privacy policy
requires explicit reconfiguration. Native configuration contents, binary bytes,
ProfileBinding contract digest, S6P1 logical context, privacy mode and peripheral
specification contribute to drift checks. Native broker TLS file references
(Ada/Nim/D), envelope TLS files and Guard broker-shield TLS files are included
in the lock and checked before spawn and before readiness acknowledgement.

Core catalog listing avoids hashing every installed binary. Binding a selected Core computes its binary digest, then the lock checks that digest again before applying and running.

The registry defaults to `~/.config/shadow6/services.json`; set
`SHADOW6_SERVICE_REGISTRY` for an isolated registry. Writes are atomic and
serialized with a 12-second lock acquisition limit. Each registry permits at
most 128 services; each run has a 30..86400-second lifetime (default 3600).
The supervisor terminates the Core and optional envelope when either process
exits or the lifetime expires. `stop` signals only the recorded PID after checking
its Linux boot/process-start identity and acquiring a pidfd.

Named services embed a strictly validated S6P1 `protocolContext` and keep logical
role/routes/identity/credentials there. Runtime endpoints come from process-owned
sockets and validated native ready events. Startup never acknowledges a live PID
alone: clients require an owned application endpoint; other roles require owned
native listeners. A process-only historical observation stays degraded and
`connect NAME` rejects it. Runtime status rechecks CoreBinding, DeploymentLock,
ProfileBinding, material digests and process identity before exposing observations.
Binding/material drift produces `stale`; an unexpected early component/supervisor
exit produces `failed`. `doctor NAME` checks the same material and observation
plus a bounded actual feature-report probe, without building or activating anything. Unsupported
transport/application readiness stays unknown. `connect NAME` and S6P1/invitation sources share one
connection-plan resolver; safe observed client streams support `--stdio`.
Local message attachments use `--records` and library `send_record`/`receive_record`.
The four inherited-FD Profiles use a private supervisor-owned seqpacket relay
with one active attachment and one pending record per direction. Micro-Mux
retains best-effort UDP records and explicitly rejects EOF/half-close.
These adapters carry opaque application records and do not change native wire.
See [the full context, topology and lifecycle contract](service-connections.md).
The native Service-Init track can generate an explicit backend definition from
the same locked component runner with `shadow6 init --system SYSTEM --named-service NAME`; `shadow6 init --system SYSTEM --capabilities` reports
that backend's available and partial guarantees. Generated definitions are not
activated implicitly. Linux local supervision uses pidfd, boot/start identity,
component ownership, `/proc` socket ownership and bounded ready events. Native
service managers on other platforms own activation and restart policy; exact
process identity and owned socket observation are explicitly reported as
degraded or unavailable, and the runner fails closed when it cannot provide an
equivalent observation. No platform reports ready from a manager's active bit
or a live PID alone.

Carp and Idris use the normalized `shadow6 native-config` document described in
[the native configuration guide](native-tooling.md), translated into their
fixed positional CLI contracts. Other families receive `--config FILE` using
their own configuration format. No caller-supplied executable or shell command
is accepted by Named Service.

Native stdout is consumed with bounded buffers for ready events; other output is discarded; on startup failure, run the
Core's documented `--check-config` or native foreground command for diagnostics.
Secret-bearing output is not copied into the registry or telemetry.

## Privacy and telemetry

Build the optional envelope explicitly with `make privacy-envelope` when OCaml,
Dune and Digestif are installed. See [the envelope guide](privacy-envelope.md)
for both ends of the path, limits and wire version.

```sh
shadow6 setup home/private --core go --config "$HOME/.config/shadow6/binding.json" \
  --privacy envelope --envelope-config /absolute/path/server.conf \
  --metrics /absolute/path/server.metrics --ttl 3600
shadow6 run home/private
shadow6 privacy-envelope status --metrics /absolute/path/server.metrics
shadow6 service status home/private
```

TLS Carrier certificate, private key and CA digests are local DeploymentLock
material. The same files are rechecked before launch and during supervision;
replacement requires explicit reconfiguration. S6P1 contains no local TLS file
paths or digests. See [TLS Carrier configuration](privacy-envelope.md#standard-tls-carrier).

The `--metrics` path must match `metrics_path` in the envelope configuration.
For the read-only Control Center API, configure `SHADOW6_ENVELOPE_METRICS` in its
operator environment, then call `privacy-envelope.status` with empty parameters.
RPC clients cannot choose arbitrary metrics files. No telemetry is sent off-host.

未配置、文件尚未生成、超过五秒未更新分别报告 `not-configured`、`unavailable`、
`stale`。它们不是“观测到零”。计数来源于 OCaml 运行时，启动一个服务不会凭空增加
认证会话数。指标只有 schema、采样时间和允许的聚合整数，没有密钥、正文、服务名
或原生协议数据。`shadow6 privacy` 继续提供不含采样时间的可分享健康摘要。

Earlier simulated registry records are not proof of running processes. Back up
an old registry, inspect it locally, and explicitly recreate services in a new
private registry; never adopt a PID from an unverified legacy record.

## Implementation and verification status

The lifecycle and EPE E2E goals remain active. Current implementation provides
actual local process supervision and actual aggregate observations. Remaining
work includes portable process supervision outside Linux, native ready-event
endpoint discovery for every family, the WebRTC-specific envelope adapter and
native ready-event support on every family. S6EPE v3 now implements mandatory
outer encryption and a dedicated Linux SCTP message adapter; see its versioned
envelope guide. Linux observation includes actual process-owned one-to-one SCTP
listeners, distinguishes bound sockets from listeners, and checks the envelope
upstream against the declared transport. This does not declare a Core's
application boundary or certify twelve-Core message interoperability. The
remaining capabilities are not represented as verified controls.
The [review record](review-2026-10-03.md) lists the checks actually run and the
existing binary/audit limitations.
