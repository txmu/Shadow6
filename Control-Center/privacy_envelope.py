"""Allowlisted local envelope observations; never invent runtime counters."""
from dataclasses import dataclass
import time
from pathlib import Path
import sys

@dataclass
class EnvelopeMetrics:
    preauth_rejections: int = 0
    replay_rejections: int = 0
    resource_rejections: int = 0
    sessions: int = 0
    authenticated_sessions: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    def public(self):
        return {"schema":"shadow6.privacy-envelope-status.v1", "sessions":self.sessions,
                "authenticated_sessions":self.authenticated_sessions,
                "preauth_rejection_count":self.preauth_rejections,
                "replay_rejection_count":self.replay_rejections,
                "resource_limit_rejection_count":self.resource_rejections,
                "bytes_in":self.bytes_in, "bytes_out":self.bytes_out}


def read_metrics(path=None):
    if path is None:
        return {"schema":"shadow6.privacy-envelope-status.v1", "observation":"not-configured"}
    try:
        from service_storage import private_read, strict_json
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'Deployment'))
        from service_storage import private_read, strict_json
    try:
        value = strict_json(private_read(path, 16384))
    except FileNotFoundError:
        return {"schema":"shadow6.privacy-envelope-status.v1", "observation":"unavailable"}
    counters = set(EnvelopeMetrics().public()) - {'schema'}
    if not isinstance(value,dict):raise ValueError('invalid envelope metrics schema')
    extra = set()
    schemas = {f'shadow6.privacy-envelope-status.v{version}' for version in range(1,7)}
    if value.get('schema') in schemas - {'shadow6.privacy-envelope-status.v1'}:
        counters |= {'records_in','records_out','timeout_count','shaping_overhead_bytes'}
        extra = {'shaping_enabled'}
        if type(value.get('shaping_enabled')) is not bool:raise ValueError('invalid envelope shaping flag')
    if value.get('schema') == 'shadow6.privacy-envelope-status.v3':
        extra |= {'carrier','wire_appearance'}
        if value.get('carrier') != 'tls' or value.get('wire_appearance') != 'standard-tls13':
            raise ValueError('invalid envelope carrier observation')
    if value.get('schema') == 'shadow6.privacy-envelope-status.v4':
        counters |= {'native_send_abandonment_count','session_rejection_count'}
        extra |= {'carrier','wire_appearance'}
        if value.get('carrier') != 'sctp' or value.get('wire_appearance') != 'standard-sctp':
            raise ValueError('invalid envelope message carrier observation')
    if value.get('schema') == 'shadow6.privacy-envelope-status.v5':
        counters |= {'native_send_abandonment_count','session_rejection_count'}
        extra |= {'carrier','wire_appearance'}
        if value.get('carrier') != 'webrtc' or value.get('wire_appearance') != 'standard-webrtc-datachannel':
            raise ValueError('invalid envelope DataChannel carrier observation')
    if value.get('schema') == 'shadow6.privacy-envelope-status.v6':
        counters |= {'native_send_abandonment_count','session_rejection_count','active_sessions'}
        extra |= {'carrier','wire_appearance'}
        if value.get('carrier') != 'webrtc' or value.get('wire_appearance') != 'standard-webrtc-datachannel':
            raise ValueError('invalid envelope DataChannel carrier observation')
    if set(value) != counters | {'schema', 'observed_at'} | extra or value.get('schema') not in schemas:
        raise ValueError('invalid envelope metrics schema')
    if any(type(value[k]) is not int or not 0 <= value[k] <= 2**53-1 for k in counters | {'observed_at'}):
        raise ValueError('invalid envelope metric')
    if value.get('schema') == 'shadow6.privacy-envelope-status.v6' and value['active_sessions']>value['authenticated_sessions']:
        raise ValueError('invalid active WebRTC session count')
    age = int(time.time()) - value['observed_at']
    return {**value, 'observation': 'current' if 0 <= age <= 5 else 'stale'}


def compatibility(core):
    datagram = {'go', 'rust', 'zig', 'd', 'pony', 'hare', 'carp', 'idris'}
    stream = {'gleam', 'ada'}
    if core not in datagram | stream | {'nim', 'cpp'}:
        raise ValueError('unknown Core identity')
    return {'core':core, 'supported':core not in {'nim', 'cpp'}, 'mode':'datagram' if core in datagram else 'stream' if core in stream else None,
            'reason':'explicit matching local endpoint required; native interoperability and E2E remain Core-specific' if core not in {'nim', 'cpp'} else 'Native WebRTC/SCTP endpoint mapping requires a separate adapter; a TCP application boundary must be selected explicitly'}
