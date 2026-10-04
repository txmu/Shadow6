"""Single bounded HostBudget / LimitResolver / LimitResolution authority.

Protocol maxima, implementation capacity, operator intent and host ceilings
are distinct. A request for an unenforceable change fails rather than becoming
a fictitious effective limit. Running jobs retain their locked resolution.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys

MAX_INTEGER = 2**53 - 1


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def integer(value, name, minimum=1):
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise ValueError('InvalidLimitInteger: ' + name)
    return value


def bounded_read(path):
    try:
        with Path(path).open('rb') as handle: data = handle.read(4097)
    except FileNotFoundError:
        return None
    if len(data) > 4096:
        raise ValueError('HostBudgetInputTooLarge')
    return data.decode('ascii').strip()


@dataclass(frozen=True)
class HostBudget:
    memory_bytes: int
    fd_ceiling: int
    cpu_units: int
    platform: str
    memory_sources: tuple[str, ...] = ()
    fd_sources: tuple[str, ...] = ()
    cpu_sources: tuple[str, ...] = ()

    def __post_init__(self):
        for name in ('memory_bytes', 'fd_ceiling', 'cpu_units'):
            integer(getattr(self, name), name)
        if not isinstance(self.platform, str) or not 1 <= len(self.platform) <= 64:
            raise ValueError('InvalidHostBudgetPlatform')
        for values in (self.memory_sources, self.fd_sources, self.cpu_sources):
            if not isinstance(values, tuple) or len(values) > 8 or any(
                    not isinstance(v, str) or not 1 <= len(v) <= 128 for v in values):
                raise ValueError('InvalidHostBudgetSources')

    def to_dict(self):
        return dict(schema='shadow6.host-budget.v1', platform=self.platform,
                    memory_bytes=self.memory_bytes, fd_ceiling=self.fd_ceiling,
                    cpu_units=self.cpu_units, memory_sources=list(self.memory_sources),
                    fd_sources=list(self.fd_sources), cpu_sources=list(self.cpu_sources))

    @classmethod
    def from_dict(cls, value):
        fields = {'schema', 'platform', 'memory_bytes', 'fd_ceiling', 'cpu_units',
                  'memory_sources', 'fd_sources', 'cpu_sources'}
        if not isinstance(value, dict) or set(value) != fields or value['schema'] != 'shadow6.host-budget.v1':
            raise ValueError('InvalidHostBudgetSchema')
        if any(not isinstance(value[n], list) for n in ('memory_sources', 'fd_sources', 'cpu_sources')):
            raise ValueError('InvalidHostBudgetSources')
        return cls(value['memory_bytes'], value['fd_ceiling'], value['cpu_units'], value['platform'],
                   *(tuple(value[n]) for n in ('memory_sources', 'fd_sources', 'cpu_sources')))

    @classmethod
    def capture(cls, *, cgroup_root=Path('/sys/fs/cgroup'), proc_root=Path('/proc')):
        """Read finite host ceilings, including our own container hierarchy."""
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            physical = int(os.sysconf('SC_PHYS_PAGES')) * int(os.sysconf('SC_PAGE_SIZE'))
        except (ImportError, ValueError, OSError) as error:
            raise ValueError('HostBudgetUnavailable: platform resource backend required') from error
        fd_limits = [v for v in (soft, hard) if v != resource.RLIM_INFINITY and v > 0]
        kernel_fds = bounded_read(Path(proc_root) / 'sys/fs/nr_open') if sys.platform == 'linux' else None
        if kernel_fds is not None: fd_limits.append(integer(int(kernel_fds), 'kernel fd ceiling'))
        if not fd_limits:
            raise ValueError('HostBudgetUnavailable: finite descriptor ceiling required')
        memory = [integer(physical, 'physical RAM')]
        cpu = integer(os.cpu_count() or 1, 'host CPU')
        memory_sources, cpu_sources = ['physical-ram'], ['online-cpus']
        if hasattr(os, 'sched_getaffinity'):
            cpu = min(cpu, integer(len(os.sched_getaffinity(0)), 'CPU affinity'))
            cpu_sources.append('process-affinity')
        if sys.platform == 'linux':
            memberships = bounded_read(Path(proc_root) / 'self/cgroup')
            ancestors = []
            if memberships is not None:
                for row in memberships.splitlines():
                    parts = row.split(':', 2)
                    if len(parts) != 3: raise ValueError('InvalidHostCgroupMembership')
                    if parts[0] == '0' and parts[1] == '':
                        relative = Path(parts[2].lstrip('/'))
                        if '..' in relative.parts: raise ValueError('InvalidHostCgroupMembership')
                        current = Path(cgroup_root) / relative
                        while True:
                            ancestors.append(current)
                            if current == Path(cgroup_root): break
                            current = current.parent
            if not ancestors: ancestors = [Path(cgroup_root)]
            if len(ancestors) > 64: raise ValueError('HostCgroupHierarchyLimit')
            for parent in ancestors:
                maximum = bounded_read(parent / 'memory.max')
                if maximum is not None and maximum != 'max':
                    memory.append(integer(int(maximum), 'cgroup memory'))
                    if 'cgroup-v2' not in memory_sources: memory_sources.append('cgroup-v2')
                quota = bounded_read(parent / 'cpu.max')
                if quota:
                    values = quota.split()
                    if len(values) != 2: raise ValueError('InvalidHostCPUQuota')
                    period = integer(int(values[1]), 'CPU quota period')
                    if values[0] != 'max':
                        allocation = integer(int(values[0]), 'CPU quota')
                        # Integer scheduling units; a fractional CPU still
                        # admits one bounded worker, never zero/unlimited.
                        cpu = min(cpu, (allocation + period - 1) // period)
                        if 'cgroup-v2' not in cpu_sources: cpu_sources.append('cgroup-v2')
            # Legacy v1 paths are controller-specific; huge kernel sentinels
            # cannot increase the independently finite physical RAM ceiling.
            legacy = bounded_read(Path(cgroup_root) / 'memory/memory.limit_in_bytes')
            if legacy is not None:
                legacy_value = int(legacy)
                if legacy_value < 1: raise ValueError('InvalidHostMemoryLimit')
                memory.append(min(legacy_value, physical))
                memory_sources.append('cgroup-v1')
        return cls(min(memory), min(fd_limits), cpu, sys.platform,
                   tuple(memory_sources), ('rlimit-nofile',) + (('kernel-nr-open',) if kernel_fds else ()),
                   tuple(cpu_sources))


def validate_policy(value):
    if value is None: value = {'mode': 'safe', 'operator_overrides': {}}
    if (not isinstance(value, dict) or set(value) != {'mode', 'operator_overrides'}
            or value['mode'] not in ('safe', 'elastic', 'custom')
            or not isinstance(value['operator_overrides'], dict) or len(value['operator_overrides']) > 64):
        raise ValueError('InvalidLimitsPolicy')
    if value['mode'] != 'custom' and value['operator_overrides']:
        raise ValueError('OperatorOverridesRequireCustomMode')
    for name, requested in value['operator_overrides'].items():
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            raise ValueError('InvalidLimitDimension')
        integer(requested, name)
    return json.loads(canonical(value))


@dataclass(frozen=True)
class LimitResolution:
    document: dict

    def to_dict(self):
        return json.loads(canonical(self.document))

    @property
    def digest(self):
        return 'sha256:' + hashlib.sha256(canonical(self.document)).hexdigest()


class LimitResolver:
    def resolve_components(self, inputs, *, host: HostBudget, process_fds: int):
        """Bound Gate/S6EPE resource settings against the locked host budget.

        Component schemas remain owned by their implementations. This shared
        layer reads only their declared concurrency/frame ceilings and rejects
        plans whose conservative descriptor or memory estimate exceeds the
        same host snapshot and inherited supervisor descriptor ceiling.
        """
        if not isinstance(inputs, dict) or set(inputs) - {'gate', 'envelope', 'guard', 'credited'}:
            raise ValueError('InvalidComponentLimitsInput')
        process_fds = integer(process_fds, 'process_fds')
        output = {}

        def limit(row, name, default, low, high):
            value = row.get(name, default)
            if type(value) is not int or not low <= value <= high:
                raise ValueError('InvalidComponentLimit: ' + name)
            return value

        gate = inputs.get('gate')
        if gate is not None:
            if not isinstance(gate, dict): raise ValueError('InvalidGateLimitConfig')
            values = gate.get('limits', {})
            if not isinstance(values, dict) or set(values) - {'max_connections','max_frame_bytes','idle_seconds'}:
                raise ValueError('InvalidGateLimitConfig')
            connections = limit(values, 'max_connections', 128, 1, 4096)
            frame = limit(values, 'max_frame_bytes', 65507, 1024, 65507)
            idle = limit(values, 'idle_seconds', 120, 5, 86400)
            fds = 16 + 2 * connections
            memory = connections * frame
            output['gate'] = dict(max_connections=connections, max_frame_bytes=frame,
                idle_seconds=idle, estimated_fds=fds, estimated_memory_bytes=memory,
                enforced_by='Gate.config.limits')

        envelope = inputs.get('envelope')
        if envelope is not None:
            if not isinstance(envelope, dict): raise ValueError('InvalidEnvelopeLimitConfig')
            def number(name, default, low, high):
                raw = envelope.get(name, str(default))
                if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal():
                    raise ValueError('InvalidComponentLimit: ' + name)
                value = int(raw)
                if not low <= value <= high: raise ValueError('InvalidComponentLimit: ' + name)
                return value
            sessions = number('max_sessions', 32, 1, 128)
            preauth = number('max_preauth', 16, 1, 128)
            frame = number('max_frame', 16384, 256, 65507)
            idle = number('idle_timeout', 30, 1, 300)
            if preauth > sessions: raise ValueError('EnvelopePreauthExceedsSessions')
            fds = 16 + 2 * sessions
            memory = 2 * sessions * frame
            output['envelope'] = dict(max_sessions=sessions, max_preauth=preauth,
                max_frame=frame, idle_timeout=idle, estimated_fds=fds,
                estimated_memory_bytes=memory,
                enforced_by='S6EPE.config.max_sessions/max_preauth/max_frame')
        guard = inputs.get('guard')
        if guard is not None:
            guard_fields = {'role','target_backend','spa_config','lpd_limiter','anti_probe',
                            'stealth_timing','broker_shield'}
            if not isinstance(guard, dict) or set(guard) - guard_fields:
                raise ValueError('InvalidGuardLimitConfig')
            features = {
                name: guard.get(name, {}) for name in
                ('spa_config','lpd_limiter','anti_probe','stealth_timing','broker_shield')}
            if any(not isinstance(value, dict) for value in features.values()):
                raise ValueError('InvalidGuardLimitConfig')
            feature_fields = {
                'spa_config': {'enabled','listen_host','secret','knock_port','public_tcp_port','agent_tcp_port','unlock_window'},
                'lpd_limiter': {'enabled','rate','burst','public_port','agent_port'},
                'anti_probe': {'enabled','public_port','local_port','max_fails','ban_duration_sec'},
                'stealth_timing': {'enabled','broker_wss_addr','server_name','chaff_interval_ms','jitter_min_ms','jitter_max_ms'},
                'broker_shield': {'enabled','public_host','public_port','local_broker_port','secret_path','max_conn_per_ip','tls_cert_file','tls_key_file'},
            }
            if any(set(features[name]) - allowed for name, allowed in feature_fields.items()):
                raise ValueError('InvalidGuardLimitConfig')
            enabled = {}
            for name, value in features.items():
                active = value.get('enabled', False)
                if type(active) is not bool:
                    raise ValueError('InvalidGuardLimitConfig')
                enabled[name] = active
            if guard.get('role') not in ('agent_guard','client_guard','broker_guard'):
                raise ValueError('InvalidGuardLimitConfig')
            if guard['role'] == 'agent_guard' and not any(
                    enabled[name] for name in ('spa_config','lpd_limiter','anti_probe')):
                raise ValueError('InvalidGuardLimitConfig')
            if guard['role'] == 'client_guard' and not enabled['stealth_timing']:
                raise ValueError('InvalidGuardLimitConfig')
            if guard['role'] == 'broker_guard' and not enabled['broker_shield']:
                raise ValueError('InvalidGuardLimitConfig')
            tracked = 0
            if enabled['spa_config']: tracked += 2 * 50_000
            if enabled['lpd_limiter']: tracked += 50_000
            if enabled['anti_probe']: tracked += 3 * 50_000
            broker = features['broker_shield']
            per_ip = broker.get('max_conn_per_ip', 0)
            if type(per_ip) is not int or not 0 <= per_ip <= 10_000:
                raise ValueError('InvalidGuardLimitConfig')
            if enabled['broker_shield']:
                per_ip = per_ip or 64
                if per_ip < 1: raise ValueError('InvalidGuardLimitConfig')
            else:
                per_ip = 0
            # Guard's fixed ceilings are enforced in Guard/main.go. Its SPA,
            # LPD and BrokerShield each have separate 256-slot pools. SPA
            # copies both directions, LPD allocates bounded request/reply
            # datagrams, and BrokerShield admits bounded HTTP/WebSocket streams.
            # These conservative estimates are planning bounds, not RSS claims.
            spa_connections = 256 if enabled['spa_config'] else 0
            broker_connections = 256 if enabled['broker_shield'] else 0
            datagram_workers = 256 if enabled['lpd_limiter'] else 0
            active_connections = spa_connections + broker_connections
            listeners = (2 * int(enabled['spa_config']) +
                         2 * int(enabled['lpd_limiter']) +
                         int(enabled['anti_probe']) +
                         int(enabled['broker_shield']))
            fds = (16 + listeners + 2 * spa_connections + datagram_workers +
                   2 * broker_connections)
            # SPA: two 32 KiB io.Copy buffers and bounded connection state.
            # Broker: 16 KiB max headers, two 32 KiB relay buffers and state.
            # LPD: two <=4 KiB datagrams plus bounded worker state.
            tracked += broker_connections  # BrokerShield's per-host counter map.
            memory = (tracked * 512 + spa_connections * 80 * 1024 +
                      broker_connections * 96 * 1024 + datagram_workers * 16 * 1024)
            output['guard'] = dict(
                max_tracked_ips=50_000,
                max_active_connections=active_connections,
                max_active_datagram_workers=datagram_workers,
                max_connections_per_ip=per_ip if enabled['broker_shield'] else 0,
                tracked_state_entries=tracked,
                estimated_fds=fds,
                estimated_memory_bytes=memory,
                enforced_by='Guard.maxTrackedIPs/SPA-slots/BrokerShield-boundedListener')
        credited = inputs.get('credited')
        if credited is not None:
            fields = {'schema','core','key_file','bind','peer','side','stream','limits'}
            if (not isinstance(credited, dict) or set(credited) - fields or
                    not {'schema','core','key_file','bind','peer'} <= set(credited) or
                    credited['schema'] != 'shadow6.s6na-attachment.v1'):
                raise ValueError('InvalidCreditedLimitConfig')
            limits = credited.get('limits', {})
            limit_fields = {'max_message','max_streams','max_inflight','max_window',
                            'reassembly_seconds','max_extensions','payload_bytes','window_frames'}
            if not isinstance(limits, dict) or set(limits) - limit_fields:
                raise ValueError('InvalidCreditedLimitConfig')
            bounds = {
                'max_message': (16 * 1024 * 1024, 1024, 256 * 1024 * 1024),
                'max_streams': (64, 1, 4096),
                'max_inflight': (16 * 1024 * 1024, 1024, 512 * 1024 * 1024),
                'max_window': (64, 1, 4096),
                'reassembly_seconds': (30, 1, 300),
                'max_extensions': (16, 0, 128),
                'payload_bytes': (0, 0, 65536),
                'window_frames': (0, 0, 4096),
            }
            resolved = {name: limit(limits, name, default, low, high)
                        for name, (default, low, high) in bounds.items()}
            if (resolved['max_inflight'] < resolved['max_message'] or
                    (resolved['payload_bytes'] != 0 and resolved['payload_bytes'] < 64)):
                raise ValueError('InvalidCreditedLimitConfig')
            # A connected companion owns one UDP socket. The S6NA adapter
            # bounds queued outbound and reassembly bytes separately; pending
            # frames and maps are added as conservative metadata overhead.
            payload = resolved['payload_bytes'] or 65536
            window = min(resolved['max_window'], resolved['window_frames'] or 64)
            memory = (2 * resolved['max_inflight'] + window * (payload + 128) +
                      8192 * 512 + resolved['max_streams'] * 256)
            output['credited'] = dict(
                max_message=resolved['max_message'], max_streams=resolved['max_streams'],
                max_inflight=resolved['max_inflight'], max_window=resolved['max_window'],
                reassembly_seconds=resolved['reassembly_seconds'],
                max_extensions=resolved['max_extensions'], payload_bytes=payload,
                window_frames=window, estimated_fds=17,
                estimated_memory_bytes=memory,
                enforced_by='S6NA.Limits/DataFrameCredit/UDP-peer-pin')
        # Components run as separate supervised processes and receive the
        # same per-process RLIMIT. Check both the busiest child and the total
        # planned descriptor footprint; memory is cumulative across the set.
        peak_fds = max((row['estimated_fds'] for row in output.values()), default=0)
        total_fds = sum(row['estimated_fds'] for row in output.values())
        total_memory = sum(row['estimated_memory_bytes'] for row in output.values())
        if peak_fds > process_fds:
            raise ValueError('ComponentLimitExceedsProcessFds')
        if total_fds > host.fd_ceiling:
            raise ValueError('ComponentLimitExceedsHostFds')
        if total_memory > host.memory_bytes // 2:
            raise ValueError('ComponentLimitExceedsHostMemory')
        return dict(schema='shadow6.component-limit-resolution.v1',
            process_fds=process_fds, estimated_peak_process_fds=peak_fds,
            estimated_total_fds=total_fds, estimated_total_memory_bytes=total_memory,
            host_budget=host.to_dict(), components=output)

    def validate_components(self, resolution, inputs, *, host: HostBudget, process_fds: int):
        if not isinstance(resolution, dict) or set(resolution) != {
                'schema','process_fds','estimated_peak_process_fds',
                'estimated_total_fds','estimated_total_memory_bytes',
                'host_budget','components'}:
            raise ValueError('InvalidComponentLimitsSchema')
        expected = self.resolve_components(inputs, host=host, process_fds=process_fds)
        if canonical(expected) != canonical(resolution):
            raise ValueError('ComponentLimitsDrift')
        return expected

    def resolve(self, profile, policy=None, host=None):
        policy = validate_policy(policy); host = host or HostBudget.capture()
        model = profile.get('limit_model')
        required = {'schema', 'hard_protocol_limits', 'safe_defaults', 'recommended_limits',
                    'capacity_models', 'enforced_by'}
        if not isinstance(model, dict) or set(model) != required or model['schema'] != 'shadow6.profile-limits.v1':
            raise ValueError('InvalidProfileLimitsModel')
        names = set(model['safe_defaults'])
        if any(set(model[key]) != names for key in required - {'schema'}):
            raise ValueError('LimitDimensionMismatch')
        if set(policy['operator_overrides']) - names:
            raise ValueError('UnknownLimitOverride')
        rows, effective = {}, {}
        for name in sorted(names):
            safe = integer(model['safe_defaults'][name], name)
            recommended = integer(model['recommended_limits'][name], name)
            hard = model['hard_protocol_limits'][name]
            if hard is not None: integer(hard, name)
            capacity = model['capacity_models'][name]
            if not isinstance(capacity, dict) or set(capacity) != {'memory_per_unit', 'fds_per_unit', 'native_ceiling', 'mutable'}:
                raise ValueError('InvalidCapacityModel')
            memory_cost = integer(capacity['memory_per_unit'], name, 0)
            fd_cost = integer(capacity['fds_per_unit'], name, 0)
            native = capacity['native_ceiling']
            if native is not None: integer(native, name)
            if type(capacity['mutable']) is not bool: raise ValueError('InvalidLimitMutability')
            ceilings = [MAX_INTEGER]
            # Reserve half RAM and 64 descriptors for runtime/crypto/stdio;
            # this is a declared capacity estimate, not a memory attestation.
            if memory_cost: ceilings.append(host.memory_bytes // 2 // memory_cost)
            if fd_cost: ceilings.append(max(0, host.fd_ceiling - 64) // fd_cost)
            if native is not None: ceilings.append(native)
            host_ceiling = min(ceilings)
            request = policy['operator_overrides'].get(name)
            candidate = request if request is not None else (
                safe if policy['mode'] in ('safe', 'custom') else min(MAX_INTEGER, recommended * host.cpu_units))
            if request is not None and ((hard is not None and request > hard) or request > host_ceiling):
                raise ValueError('LimitRequestExceedsCeiling: ' + name)
            value = min(candidate, host_ceiling, hard if hard is not None else MAX_INTEGER)
            if value < 1: raise ValueError('HostBudgetInsufficient: ' + name)
            if not capacity['mutable'] and value != safe:
                raise ValueError('LimitNotRuntimeConfigurable: ' + name)
            enforcer = model['enforced_by'][name]
            if not isinstance(enforcer, str) or not enforcer:
                raise ValueError('MissingLimitEnforcer: ' + name)
            effective[name] = value
            rows[name] = dict(safe_default=safe, recommended=recommended,
                operator_request=request, host_derived_ceiling=host_ceiling,
                hard_protocol_limit=hard, implementation_ceiling=native,
                effective=value, source=('operator' if request is not None else policy['mode']),
                enforced_by=enforcer, enforcement='required-before-ready')
        return LimitResolution(dict(schema='shadow6.limit-resolution.v1', profile=profile['id'],
            mode=policy['mode'], policy=policy, host_budget=host.to_dict(),
            dimensions=rows, effective_limits=effective,
            model_digest='sha256:' + hashlib.sha256(canonical(model)).hexdigest()))

    def validate(self, resolution, profile, policy=None, *, check_host=False):
        if not isinstance(resolution, dict) or set(resolution) != {
            'schema', 'profile', 'mode', 'policy', 'host_budget', 'dimensions', 'effective_limits', 'model_digest'}:
            raise ValueError('InvalidLimitResolutionSchema')
        host = HostBudget.from_dict(resolution['host_budget'])
        expected = self.resolve(profile, policy if policy is not None else resolution['policy'], host).to_dict()
        if canonical(expected) != canonical(resolution): raise ValueError('LimitResolutionDrift')
        if check_host and HostBudget.capture().to_dict() != host.to_dict():
            raise ValueError('HostBudgetDrift: stop and explicitly relock; no dynamic shrink')
        return expected
