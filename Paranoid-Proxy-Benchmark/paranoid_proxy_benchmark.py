#!/usr/bin/env python3
"""Paranoid-Proxy-Benchmark: bounded checks of one explicit proxy and echo target.

Standalone Python standard library only. No discovery, scanning or source tree
is needed. Network tests require an operator-controlled byte-exact echo target.
Results are observations, never a certificate of security or availability.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlsplit

SIZES = (1, 63, 512, 978, 4096, 65536)
PATTERNS = ('random', 'zeros', 'counter')
CATALOG = [{'id': f'{pattern}-{size}-c{concurrency}', 'kind': 'echo',
            'bytes': size, 'pattern': pattern, 'concurrency': concurrency}
           for size in SIZES for pattern in PATTERNS for concurrency in (1, 4)]
CATALOG += [{'id': 'fragmented-writes', 'kind': 'fragmented', 'bytes': 512, 'concurrency': 1},
            {'id': 'half-close', 'kind': 'half-close', 'bytes': 512, 'concurrency': 1},
            {'id': 'reconnect-isolation', 'kind': 'reconnect', 'bytes': 512, 'concurrency': 1},
            {'id': 'invalid-proxy-version', 'kind': 'reject', 'variant': 0, 'concurrency': 1},
            {'id': 'invalid-proxy-command', 'kind': 'reject', 'variant': 1, 'concurrency': 1},
            {'id': 'invalid-proxy-address', 'kind': 'reject', 'variant': 2, 'concurrency': 1}]


# Opaque payload transparency: these do NOT assert that a remote node parses
# Shadow6 frames. Corpus follows framing/Unicode/JSON vectors in its suites.
CORPUS = {
    'utf8-nfc': '中文 é'.encode(), 'utf8-decomposed': 'e\u0301'.encode(),
    'invalid-utf8': b'\xff\xfe\xc0\xaf', 'embedded-nul': b'a\x00b',
    'duplicate-json': b'{"a":1,"a":2}', 'nonfinite-json': b'{"a":NaN}',
    'unknown-schema': b'{"protocol":"unknown","version":255}',
    'truncated-length': b'\x00\x00\x10\x00{}',
    'zero-length-header': bytes(4), 'oversize-length-header': b'\xff'*4,
    's6na-header': bytes.fromhex('53364e41010100000000000000000007000000000000002a000000010000000d'),
    'all-octets': bytes(range(256)), 'crlf': b'\r\n\r\n',
}
CATALOG += [{'id': 'opaque-' + name, 'kind': 'corpus', 'bytes': len(data),
             'corpus': name, 'concurrency': 1} for name, data in CORPUS.items()]
CATALOG += [{'id': 'persistent-stream', 'kind': 'persistent', 'bytes': 978, 'concurrency': 1},
            {'id': 'persistent-concurrent', 'kind': 'persistent', 'bytes': 978, 'concurrency': 4}]

# Generalize native framing/window tests into transparent transport properties.
# No remote Shadow6 parser, key schedule or internal implementation is assumed.
CATALOG += [{'id': f'boundary-{size}', 'kind': 'echo', 'bytes': size,
             'pattern': 'random', 'concurrency': 1}
            for size in (64, 511, 513, 977, 979, 1023, 1024, 1025,
                         16383, 16384, 16385, 32767, 32768, 32769, 65535)]
CATALOG += [{'id': f'fragment-{chunk}', 'kind': 'fragmented', 'bytes': 4096,
             'chunk': chunk, 'concurrency': 1} for chunk in (1, 63, 512, 978, 1024)]
CATALOG += [{'id': 'coalesced-records', 'kind': 'coalesced', 'bytes': 4096, 'concurrency': 1},
            {'id': 'repeated-identical-payloads', 'kind': 'repeated', 'bytes': 512, 'concurrency': 1},
            {'id': 'delayed-reader', 'kind': 'delayed', 'bytes': 65536, 'concurrency': 1},
            {'id': 'abort-and-recover', 'kind': 'abort', 'bytes': 512, 'concurrency': 1},
            {'id': 'sustained-bulk', 'kind': 'persistent', 'bytes': 65536, 'concurrency': 1},
            {'id': 'sustained-isolated-streams', 'kind': 'persistent', 'bytes': 65536, 'concurrency': 4}]

CATALOG += [{'id': name, 'kind': 'reject', 'variant': variant, 'concurrency': 1}
            for variant,name in enumerate(('nonzero-reserved-field','no-acceptable-method',
                'truncated-address-eof','zero-methods','truncated-ipv6-eof'),3)]

def contract_module():
    import sys
    here = Path(__file__).resolve().parent
    for directory in (here, here.parent / 'share/shadow6/tree/Paranoid-Proxy-Benchmark'):
        if (directory / 'ppb_contracts.py').is_file():
            sys.path.insert(0, str(directory))
            import ppb_contracts
            return ppb_contracts
    raise ValueError('contract bundle missing; use an installation or exported PPB directory')


def endpoint(text, schemes, allow_remote):
    url = urlsplit(text)
    if url.scheme not in schemes or url.username or url.password or url.path or url.query or url.fragment:
        raise ValueError('endpoint must be scheme://numeric-IP:port without credentials or path')
    host, port = url.hostname, url.port
    if not host or port is None or not 1 <= port <= 65535 or '%' in host:
        raise ValueError('invalid numeric endpoint')
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast or (not address.is_loopback and not allow_remote):
        raise ValueError('non-loopback endpoints require --allow-remote; wildcard/multicast prohibited')
    return url.scheme, str(address), port


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0: raise TimeoutError('case deadline')
    return value


def receive_exact(sock, count, deadline):
    if not 0 <= count <= 65536: raise ValueError('receive bound')
    result = bytearray()
    while len(result) < count:
        sock.settimeout(remaining(deadline))
        chunk = sock.recv(count - len(result))
        if not chunk: raise EOFError('truncated response')
        result.extend(chunk)
    return bytes(result)


def send(sock, data, deadline):
    sock.settimeout(remaining(deadline)); sock.sendall(data)


def negotiate(sock, scheme, target, deadline):
    _, host, port = target
    address = ipaddress.ip_address(host)
    if scheme == 'socks5':
        send(sock, b'\x05\x01\x00', deadline)
        if receive_exact(sock, 2, deadline) != b'\x05\x00':
            raise ValueError('SOCKS5 no-auth method was not accepted')
        send(sock, b'\x05\x01\x00' + (b'\x01' if address.version == 4 else b'\x04') + address.packed + port.to_bytes(2, 'big'), deadline)
        header = receive_exact(sock, 4, deadline)
        if header[:3] != b'\x05\x00\x00': raise ValueError('SOCKS5 CONNECT rejected or malformed')
        lengths = {1: 4, 4: 16}
        count = receive_exact(sock, 1, deadline)[0] if header[3] == 3 else lengths.get(header[3])
        if count is None or count == 0: raise ValueError('invalid SOCKS5 bound address')
        receive_exact(sock, count + 2, deadline)
    elif scheme in ('http', 'https'):
        authority = f'[{host}]:{port}' if address.version == 6 else f'{host}:{port}'
        send(sock, f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'), deadline)
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            if len(response) >= 8192: raise ValueError('HTTP header bound exceeded')
            response.extend(receive_exact(sock, 1, deadline))
        status = bytes(response).split(b'\r\n', 1)[0].split(b' ')
        if len(status) < 2 or status[0] not in (b'HTTP/1.0', b'HTTP/1.1') or status[1] != b'200':
            raise ValueError('HTTP CONNECT rejected or malformed')


def open_connection(node, target, deadline, ca_file=None, negotiate_proxy=True):
    scheme, host, port = node
    if scheme == 'udp':
        sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((host, port)); return sock
    sock = socket.create_connection((host, port), timeout=remaining(deadline))
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if scheme in ('tls', 'https'):
            context = ssl.create_default_context(cafile=ca_file)
            sock.settimeout(remaining(deadline))
            sock = context.wrap_socket(sock, server_hostname=host)
        if negotiate_proxy: negotiate(sock, scheme, target, deadline)
        return sock
    except BaseException:
        sock.close(); raise


def rejection(node, target, deadline, variant, ca_file):
    scheme = node[0]
    if scheme not in ('socks5', 'http', 'https'):
        return {'status': 'unsupported', 'reason': 'node has no proxy handshake'}
    with open_connection(node, target, deadline, ca_file, False) as sock:
        if scheme == 'socks5':
            if variant == 0: data = b'\x04\x01\x00'
            elif variant == 4: data = b'\x05\x01\xff'
            elif variant == 6: data = b'\x05\x00'
            else:
                send(sock, b'\x05\x01\x00', deadline)
                if receive_exact(sock, 2, deadline) != b'\x05\x00': raise ValueError('baseline negotiation failed')
                if variant == 1: data = b'\x05\xff\x00\x01\x7f\x00\x00\x01\x00\x01'
                elif variant == 2: data = b'\x05\x01\x00\xff'
                elif variant == 3:
                    address = ipaddress.ip_address(target[1])
                    data = b'\x05\x01\xff' + (b'\x01' if address.version == 4 else b'\x04') + address.packed + target[2].to_bytes(2,'big')
                elif variant == 5: data = b'\x05\x01\x00\x01\x7f'
                else: data = b'\x05\x01\x00\x04\x00'
        else:
            if variant >= 3: return {'status':'unsupported','reason':'SOCKS5-specific grammar vector'}
            data = (b'CONNECT invalid HTTP/9.9\r\n\r\n', b'INVALID * HTTP/1.1\r\nHost: localhost\r\n\r\n', b'CONNECT []:0 HTTP/1.1\r\n\r\n')[variant]
        send(sock, data, deadline)
        if variant in (5,7): sock.shutdown(socket.SHUT_WR)
        sock.settimeout(remaining(deadline))
        try: reply = sock.recv(8192)
        except ConnectionResetError: reply = b''
        except socket.timeout:
            return {'status': 'inconclusive', 'reason': 'no rejection before deadline'}
        if not reply: return {'status': 'pass', 'observation': 'connection closed'}
        if scheme == 'socks5':
            # Recognize explicit failures only; a partial response is inconclusive.
            rejected = reply[:2] == b'\x05\xff' if variant in (0,4,6) else len(reply) >= 4 and reply[0] == 5 and 1 <= reply[1] <= 8 and reply[2] == 0
        else:
            status = reply.split(b'\r\n', 1)[0].split(b' ')
            rejected = len(status) >= 2 and status[0] in (b'HTTP/1.0', b'HTTP/1.1') and len(status[1]) == 3 and status[1][:1] in (b'4', b'5') and status[1].isdigit()
        return {'status': 'pass' if rejected else 'inconclusive', 'observation': 'explicit rejection' if rejected else 'unrecognized response'}


def probe(case, node, target, deadline, ca_file, udp_limit=1200):
    if case['kind'] == 'reject': return rejection(node, target, deadline, case['variant'], ca_file)
    if node[0] == 'udp' and (case['bytes'] > udp_limit or case['kind'] in ('half-close', 'fragmented', 'coalesced', 'delayed')):
        return {'status': 'unsupported', 'reason': f'UDP payload limit {udp_limit} bytes; stream-only cases unsupported'}
    pattern = case.get('pattern', 'random'); size = case['bytes']
    payload = os.urandom(size) if pattern == 'random' else bytes(size) if pattern == 'zeros' else bytes(i % 256 for i in range(size))
    if case['kind'] == 'corpus': payload = CORPUS[case['corpus']]
    exchanges = 3 if case['kind'] in ('reconnect', 'abort') else 1
    total = 0
    started = time.monotonic()
    for _ in range(exchanges):
        if case['kind'] in ('reconnect','abort'): payload = os.urandom(size)
        if case['kind'] == 'abort':
            with open_connection(node, target, deadline, ca_file) as abandoned:
                send(abandoned, os.urandom(size), deadline)
            # Fresh connection must not inherit the abandoned response/session.
        with open_connection(node, target, deadline, ca_file) as sock:
            if case['kind'] in ('persistent', 'repeated'):
                for sequence in range(32):
                    block = payload if case['kind'] == 'repeated' else sequence.to_bytes(4, 'big') + os.urandom(size - 4)
                    send(sock, block, deadline)
                    if node[0] == 'udp':
                        sock.settimeout(remaining(deadline)); reply = sock.recv(size + 1)
                    else: reply = receive_exact(sock, size, deadline)
                    if reply != block: raise ValueError('persistent sequence/integrity mismatch')
                    total += size
            if case['kind'] == 'fragmented':
                chunk = case.get('chunk', 7)
                for offset in range(0, size, chunk): send(sock, payload[offset:offset + chunk], deadline)
            else: send(sock, payload, deadline)
            if case['kind'] == 'delayed':
                time.sleep(min(0.05, remaining(deadline)))
            if case['kind'] == 'half-close':
                if node[0] in ('tls', 'https'):
                    return {'status': 'unsupported', 'reason': 'TLS half-close requires protocol close_notify semantics'}
                sock.shutdown(socket.SHUT_WR)
            if node[0] == 'udp':
                sock.settimeout(remaining(deadline)); received = sock.recv(size + 1)
            elif case['kind'] == 'coalesced':
                parts = []
                # Read at boundaries unrelated to sender writes/packet sizes.
                for count in (1, 63, 978, 1024, size - 2066):
                    parts.append(receive_exact(sock, count, deadline))
                received = b''.join(parts)
            else: received = receive_exact(sock, size, deadline)
            if received != payload: raise ValueError('byte integrity failed')
            if case['kind'] == 'half-close':
                sock.settimeout(remaining(deadline))
                if sock.recv(1): raise ValueError('unexpected trailing bytes')
            total += len(received)
    elapsed = time.monotonic() - started
    return {'status': 'pass', 'bytes_received': total, 'seconds': elapsed,
            'receiver_bps': total * 8 / max(elapsed, 1e-9)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('catalog', 'run', 'contracts', 'export'))
    parser.add_argument('--suite', action='append', choices=('adapter','interop','application','public6','features','adversarial','slots','extensions','plugins'))
    parser.add_argument('--destination', type=Path, help='new directory for a portable contract bundle')
    parser.add_argument('--node', help='tcp/udp/tls/socks5/http/https://numeric-IP:port')
    parser.add_argument('--target', help='tcp://numeric-IP:port of operator-controlled echo target (required for proxy protocols)')
    parser.add_argument('--allow-remote', action='store_true')
    parser.add_argument('--ca-file')
    parser.add_argument('--case', action='append', choices=[x['id'] for x in CATALOG])
    parser.add_argument('--udp-limit', type=int, default=1200, help='maximum UDP payload, 1..65507 bytes (default 1200)')
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--budget', type=float, default=120)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'catalog':
        print(json.dumps({'schema': 'paranoid-proxy-benchmark.catalog.v1', 'cases': CATALOG, 'contract_suites': ['adapter','interop','application','public6','features','adversarial','slots','extensions','plugins'], 'network_scope': 'generic byte-transparent proxy and operator echo target; no Shadow6 dependency'}, indent=2)); return 0
    try:
        if not 1 <= args.udp_limit <= 65507: raise ValueError('--udp-limit must be 1..65507')
        if not math.isfinite(args.timeout) or not 0.1 <= args.timeout <= 10 or not math.isfinite(args.budget) or not 1 <= args.budget <= 300:
            raise ValueError('timeout must be 0.1..10 and budget 1..300 seconds')
        if args.action == 'export':
            if not args.destination: raise ValueError('--destination is required')
            contract_module().export(args.destination)
            print(json.dumps({'exported': str(args.destination)})); return 0
        if args.action == 'contracts':
            report = contract_module().run(args.suite, args.budget)
            encoded = json.dumps(report, indent=2) + '\n'
            if args.output:
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as handle: handle.write(encoded)
            else: print(encoded, end='')
            return 0 if all(row['status'] == 'pass' for row in report['results']) else 1
        if not args.node: raise ValueError('--node is required')
        node = endpoint(args.node, ('tcp', 'udp', 'tls', 'socks5', 'http', 'https'), args.allow_remote)
        if node[0] in ('socks5', 'http', 'https') and not args.target: raise ValueError('--target is required for proxy protocols')
        if args.target and node[0] not in ('socks5', 'http', 'https'): raise ValueError('--target applies only to proxy protocols')
        target = endpoint(args.target, ('tcp',), args.allow_remote) if args.target else node
        selected = [case for case in CATALOG if not args.case or case['id'] in args.case]
        end = time.monotonic() + args.budget
        rows = []
        for case in selected:
            if time.monotonic() >= end:
                rows.append({'id': case['id'], 'status': 'not-run', 'reason': 'total budget exhausted'}); continue
            deadline = min(end, time.monotonic() + args.timeout)
            with ThreadPoolExecutor(max_workers=case['concurrency']) as pool:
                futures = [pool.submit(probe, case, node, target, deadline, args.ca_file, args.udp_limit) for _ in range(case['concurrency'])]
                outcomes = []
                for future in futures:
                    try: outcomes.append(future.result())
                    except (OSError, ValueError, EOFError) as error:
                        outcomes.append({'status': 'fail', 'reason': str(error)[:256]})
            statuses = {x['status'] for x in outcomes}
            status = 'fail' if 'fail' in statuses else 'inconclusive' if 'inconclusive' in statuses else 'unsupported' if 'unsupported' in statuses else 'pass'
            rows.append({'id': case['id'], 'status': status, 'workers': outcomes})
        report = {'schema': 'paranoid-proxy-benchmark.v1', 'node': args.node, 'target': args.target,
                  'scope': 'one explicit node; bounded echo/proxy contract observations; no security or availability guarantee',
                  'results': rows, 'complete': not any(x['status'] == 'not-run' for x in rows)}
        encoded = (json.dumps(report, indent=2, allow_nan=False) + '\n').encode()
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as handle: handle.write(encoded)
        else: print(encoded.decode(), end='')
        return 0 if rows and all(x['status'] in ('pass', 'unsupported') for x in rows) and any(x['status'] == 'pass' for x in rows) else 1
    except (OSError, ValueError) as error:
        parser.exit(2, f'error: {error}\n')

if __name__ == '__main__': raise SystemExit(main())
