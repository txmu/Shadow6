#!/usr/bin/env python3
"""60Hz application-owned echo workload against an operator-bound service.

The game's matchmaking supplies the Named Service and native session material
through the canonical setup workflow; this example does not implement pairing.
Run against a real deployed echo peer, never a Core's native wire socket.
"""
import argparse
import selectors
import struct
import time
from libshadow6 import Shadow6


def run(name, seconds):
    with Shadow6() as facade, facade.connect_handle(name) as connection:
        boundary = connection.boundary
        sock = connection.socket
        sock.setblocking(False)
        print(connection.describe())
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        pending = bytearray()
        received = bytearray()
        sent, replies = {}, set()
        start = next_tick = time.monotonic()
        end = start + seconds
        sequence = 0
        try:
            while time.monotonic() < end:
                now = time.monotonic()
                if now >= next_tick:
                    # Application framing: sequence + monotonic timestamp. A
                    # stream has explicit fixed-size framing; records retain it.
                    payload = struct.pack('!Qd', sequence, now)
                    if boundary.semantics == 'stream':
                        pending.extend(payload)
                    else:
                        if len(payload) > boundary.max_record:
                            raise ValueError('workload exceeds record capability')
                        try:
                            count = sock.send(payload)
                            if count != len(payload): raise OSError('partial application record')
                            sent[sequence] = now
                        except BlockingIOError:
                            pass  # Application freshness policy drops a stale tick.
                    if boundary.semantics == 'stream': sent[sequence] = now
                    sequence += 1
                    next_tick += 1/60
                    # Do not emit an unbounded catch-up burst after a stall.
                    if next_tick < now: next_tick = now + 1/60
                if pending:
                    try: del pending[:sock.send(pending)]
                    except BlockingIOError: pass
                    if len(pending) > 65536: raise BufferError('bounded application queue exhausted')
                for _key, _events in selector.select(max(0, min(.005, next_tick-time.monotonic()))):
                    if boundary.semantics == 'stream':
                        chunk = sock.recv(65536)
                        if not chunk: raise EOFError('application stream closed')
                        received.extend(chunk)
                        records = []
                        while len(received) >= 16:
                            records.append(bytes(received[:16])); del received[:16]
                    else:
                        record, _anc, flags, _peer = sock.recvmsg(boundary.max_record)
                        if flags & __import__('socket').MSG_TRUNC: raise ValueError('truncated application record')
                        if not record and boundary.semantics == 'record': raise EOFError('record attachment closed')
                        records = [record]
                    for record in records:
                        seq, timestamp = struct.unpack('!Qd', record)
                        if seq not in sent or sent[seq] != timestamp or seq in replies:
                            raise ValueError('application payload correctness failure')
                        replies.add(seq)
            print({'sent':len(sent), 'echoed':len(replies), 'unanswered':len(sent)-len(replies),
                   'semantics':boundary.semantics, 'reliable':boundary.reliable,
                   'ordered':boundary.ordered, 'runtimeStopped':False})
        finally: selector.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service')
    parser.add_argument('--seconds', type=int, choices=range(1,301), default=10)
    args = parser.parse_args()
    run(args.service, args.seconds)
