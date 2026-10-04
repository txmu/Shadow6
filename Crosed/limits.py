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
