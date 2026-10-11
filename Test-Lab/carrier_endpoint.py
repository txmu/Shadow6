"""Fixed, bounded echo fixtures and typed Agent-target attachments for S6EPE.

These are Lab workload attachments, not production native-protocol providers.
Core record attachments retain records; stream attachments retain ordered bytes.
Only the owned loopback endpoint can be exposed by this process.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import socket
import struct
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'Deployment'))
from service_storage import private_read, strict_json, atomic_write
from service_runtime import identity
from profile_registry import select_profile, profile_digest

MAX_RECORD = 8192
KINDS = {'echo-tcp', 'echo-udp', 'echo-record-stream', 'echo-sctp',
         'stream-to-datagram', 'record-to-stream', 'stream-to-sctp', 'forward-stream', 'forward-record'}

def configuration(data):
    value = strict_json(data)
    fields = {'schema', 'kind', 'core', 'profile', 'profileDigest', 'port', 'host',
              'peerPort', 'peerHost', 'namespaceIdentity', 'metrics', 'ttl', 'maxRecord'}
    if not isinstance(value, dict) or set(value) != fields or value['schema'] != 'shadow6.lab-carrier-attachment.v2':
        raise ValueError('unknown Lab attachment schema/fields')
    profile = select_profile(value['core'], value['profile'])
    if value['profileDigest'] != profile_digest(profile): raise ValueError('Lab attachment Profile drift')
    if value['kind'] not in KINDS or value['host'] not in {'127.0.0.1', '::1', '198.18.6.2'}:
        raise ValueError('Lab attachment must use a fixed kind and loopback host')
    if value['host'] == '198.18.6.2' and value['kind'] not in {'echo-tcp', 'echo-udp'}:
        raise ValueError('WAN bind is only available for the controlled Native target')
    forward = value['kind'] in {'forward-stream', 'forward-record'}
    if value['peerHost'] != ('198.18.6.2' if forward else '127.0.0.1'):
        raise ValueError('attachment peer must match its owned network placement')
    if value['namespaceIdentity'] != os.readlink('/proc/self/ns/net'):
        raise ValueError('attachment namespace identity mismatch')
    for key in ('port', 'peerPort'):
        if type(value[key]) is not int or not 1 <= value[key] <= 65535: raise ValueError('invalid attachment port')
    if type(value['ttl']) is not int or not 1 <= value['ttl'] <= 300: raise ValueError('attachment lifetime bound')
    if type(value['maxRecord']) is not int or not 1 <= value['maxRecord'] <= MAX_RECORD:
        raise ValueError('attachment record bound')
    if not isinstance(value['metrics'], str) or not Path(value['metrics']).is_absolute():
        raise ValueError('attachment metrics path must be absolute')
    message = profile['applicationBoundary']['kind'] == 'message'
    if value['kind'] in {'record-to-stream', 'forward-record'} and not message:
        raise ValueError('record attachment requires an authoritative message boundary')
    if value['kind'] in {'stream-to-datagram', 'stream-to-sctp', 'forward-stream'} and message:
        raise ValueError('stream attachment cannot consume an authoritative message boundary')
    return value

def exact(connection, size):
    if not 0 <= size <= MAX_RECORD: raise ValueError('record budget exceeded')
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk: raise EOFError('short record')
        result.extend(chunk)
    return bytes(result)

def sctp_socket():
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)
    connection.setsockopt(132, 2, struct.pack('=4H', 4, 4, 4, 0))
    connection.setsockopt(132, 11, bytes([1]) + bytes(13))
    return connection

def sctp_send(connection, data):
    if not 1 <= len(data) <= MAX_RECORD: raise ValueError('SCTP record bound')
    # Linux sctp_sndrcvinfo: negotiated channel 0, reliable, ordered, PPID 0.
    info = struct.pack('=HHHHIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if connection.sendmsg([data], [(132, 1, info)]) != len(data):
        raise OSError('SCTP whole-message send refused')

def sctp_receive(connection, limit):
    data, ancillary, flags, _ = connection.recvmsg(limit, 256)
    if not data: raise EOFError('SCTP association closed')
    if flags & (socket.MSG_TRUNC | 0x8000) or not flags & socket.MSG_EOR:
        raise ValueError('SCTP truncated/non-message event rejected')
    infos = [item for level, kind, item in ancillary if (level, kind) == (132, 1)]
    if len(infos) != 1 or len(infos[0]) != 32:
        raise ValueError('SCTP message metadata unavailable')
    stream, _, delivery = struct.unpack_from('=HHH', infos[0])
    ppid = struct.unpack_from('=I', infos[0], 8)[0]
    if stream != 0 or delivery & 1 or ppid != 0: raise ValueError('SCTP message policy mismatch')
    return data

def forward_records(listener, upstream, *, limit, deadline, stopping, count):
    """Forward one owned UDP peer without serializing records behind WAN RTT."""
    address = None
    while time.monotonic() < deadline and not stopping.is_set():
        ready, _, _ = select.select([listener, upstream], [], [], .25)
        for connection in ready:
            if connection is listener:
                data, sender = listener.recvfrom(limit + 1)
                if len(data) > limit: raise ValueError('UDP record bound exceeded')
                if address is None: address = sender
                if sender != address: raise ValueError('Native forward peer changed')
                if upstream.send(data) != len(data): raise OSError('partial record send')
            else:
                data = upstream.recv(limit + 1)
                if address is None or len(data) > limit:
                    raise ValueError('unexpected Native WAN record')
                listener.sendto(data, address)
                count(data)

def serve(config):
    kind, limit = config['kind'], config['maxRecord']
    udp = kind in {'echo-udp', 'record-to-stream', 'forward-record'}
    family = socket.AF_INET6 if config['host'] == '::1' else socket.AF_INET
    listener = sctp_socket() if kind == 'echo-sctp' else socket.socket(family,
        socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((config['host'], config['port']))
    listener.settimeout(.25)
    if not udp: listener.listen(4)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    metrics = {'schema': 'shadow6.lab-carrier-attachment-observation.v1',
        'pid': os.getpid(), 'processIdentity': identity(os.getpid()), 'kind': kind,
        'core': config['core'], 'profile': config['profile'], 'profileDigest': config['profileDigest'],
        'bytesIn': 0, 'bytesOut': 0, 'records': 0, 'failures': 0}
    lock = threading.Lock()
    def publish():
        with lock:
            atomic_write(config['metrics'], json.dumps({**metrics, 'observedAt': int(time.time())}, allow_nan=False).encode())
    def count(data):
        with lock:
            metrics['bytesIn'] += len(data); metrics['bytesOut'] += len(data); metrics['records'] += 1
        publish()
    def connected(peer):
        peer.settimeout(15)
        with peer:
            if kind in {'echo-tcp', 'echo-record-stream', 'echo-sctp'}:
                while not stopping.is_set():
                    if kind == 'echo-tcp':
                        data = peer.recv(limit)
                        if not data: return
                        peer.sendall(data)
                    elif kind == 'echo-record-stream':
                        data = exact(peer, struct.unpack('>I', exact(peer, 4))[0])
                        peer.sendall(struct.pack('>I', len(data)) + data)
                    else:
                        data = sctp_receive(peer, limit); sctp_send(peer, data)
                    count(data)
            else:
                upstream = sctp_socket() if kind == 'stream-to-sctp' else socket.socket(socket.AF_INET,
                    socket.SOCK_STREAM if kind == 'forward-stream' else socket.SOCK_DGRAM)
                with upstream:
                    upstream.settimeout(15); upstream.connect((config['peerHost'], config['peerPort']))
                    while not stopping.is_set():
                        data = peer.recv(limit)
                        if not data: return
                        if kind == 'stream-to-sctp':
                            sctp_send(upstream, data); reply = sctp_receive(upstream, limit)
                        elif kind == 'forward-stream':
                            upstream.sendall(data); reply = exact(upstream, len(data))
                        else:
                            if upstream.send(data) != len(data): raise OSError('partial UDP send')
                            reply = upstream.recv(limit + 1)
                        if reply != data: raise ValueError('carrier attachment exact echo mismatch')
                        peer.sendall(reply); count(data)
    def worker(peer):
        try: connected(peer)
        except EOFError: pass
        except (OSError, ValueError) as error:
            with lock: metrics['failures'] += 1
            if metrics['failures'] <= 4:
                print(f'{kind}: {type(error).__name__}: {error}', file=sys.stderr, flush=True)
            publish()
    active = []
    record_stream = None
    deadline = time.monotonic() + config['ttl']
    try:
        publish()
        print(json.dumps({'event': 'shadow6.lab-carrier-endpoint-ready.v1', **metrics,
            'host': config['host'], 'port': config['port'], 'transport': 'sctp' if kind == 'echo-sctp' else 'udp' if udp else 'tcp'}, allow_nan=False), flush=True)
        if kind == 'forward-record':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(.25)
                upstream.connect((config['peerHost'], config['peerPort']))
                forward_records(listener, upstream, limit=limit, deadline=deadline,
                    stopping=stopping, count=count)
            return
        while time.monotonic() < deadline and not stopping.is_set():
            active = [thread for thread in active if thread.is_alive()]
            try:
                if udp:
                    data, address = listener.recvfrom(limit + 1)
                    if len(data) > limit: raise ValueError('UDP record bound exceeded')
                    if kind == 'echo-udp': listener.sendto(data, address)
                    else:
                        if record_stream is None:
                            record_stream = socket.create_connection(('127.0.0.1', config['peerPort']), timeout=15)
                        record_stream.sendall(struct.pack('>I', len(data)) + data)
                        reply = exact(record_stream, struct.unpack('>I', exact(record_stream, 4))[0])
                        if reply != data: raise ValueError('message attachment exact echo mismatch')
                        listener.sendto(reply, address)
                    count(data)
                else:
                    peer, _ = listener.accept()
                    if len(active) >= 4: peer.close(); continue
                    thread = threading.Thread(target=worker, args=(peer,), daemon=True)
                    thread.start(); active.append(thread)
            except socket.timeout: continue
            except (OSError, ValueError):
                with lock: metrics['failures'] += 1
                publish()
    finally:
        stopping.set(); listener.close()
        if record_stream is not None: record_stream.close()
        for thread in active: thread.join(timeout=.5)
        publish()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    serve(configuration(private_read(args.config)))
