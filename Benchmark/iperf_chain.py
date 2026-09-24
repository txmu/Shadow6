#!/usr/bin/env python3
"""Bounded iperf3 application data through real native A/B/C deployments.

iperf's TCP control connection travels directly to the loopback server. Its
single measured data connection travels through the Core. This lets single-
stream and UDP-only cores participate without pretending they multiplex TCP.
The TCP fixture adds a bounded Python copy; a matching fixture baseline is
reported. Parallelism means independent native trios, not worker threads.
"""
from __future__ import annotations
import argparse
from contextlib import nullcontext
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
from pathlib import Path
import platform
import selectors
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integration'))
from stack_test import CORE_BINARIES, DATAGRAM_CORES, run_engine


def receiver_result(document, datagram):
    if document.get('error'):
        raise ValueError(document['error'])
    # Never substitute UDP's legacy sum, which can describe the sender.
    receiver = document['end']['sum_received']
    bps = receiver.get('bits_per_second')
    if type(bps) not in (int, float) or not math.isfinite(bps) or bps <= 0 or receiver.get('sender') is not False:
        raise ValueError('missing or invalid receiver throughput')
    loss = receiver.get('lost_percent', 0 if not datagram else None)
    if type(loss) not in (int, float) or not math.isfinite(loss) or not 0 <= loss <= 100:
        raise ValueError('missing or invalid receiver loss')
    return receiver, bps >= 1_000_000_000 and loss <= 0.1


def snapshot(processes):
    rows = []
    for role, process in zip(('broker', 'agent', 'client'), processes):
        row = {'role': role, 'pid': process.pid}
        try:
            fields = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()
            row.update(cpu_seconds=(int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
                       threads=int(fields[17]), rss_bytes=int(fields[21]) * os.sysconf('SC_PAGE_SIZE'))
            for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                if line.startswith(('voluntary_ctxt_switches:', 'nonvoluntary_ctxt_switches:')):
                    key, value = line.split(':'); row[key] = int(value)
        except (OSError, ValueError, IndexError):
            row['unavailable'] = True
        rows.append(row)
    return rows


class IperfTarget:
    def __init__(self, family, datagram, directory):
        self.family, self.datagram = family, datagram
        self.host = '::1' if family == socket.AF_INET6 else '127.0.0.1'
        self.directory = directory
        self.error = None
        self.process = None
        self.log = None
        self.data_listener = None
        self.data_thread = None

    def start(self):
        # No readiness connection: iperf -1 consumes its first connection.
        with socket.socket(self.family, socket.SOCK_STREAM) as reservation:
            reservation.bind((self.host, 0)); self.server_port = reservation.getsockname()[1]
        self.port = self.server_port
        if not self.datagram:
            self.data_listener = socket.socket(self.family, socket.SOCK_STREAM)
            self.data_listener.bind((self.host, 0)); self.data_listener.listen(1)
            self.data_listener.settimeout(.2)
            self.port = self.data_listener.getsockname()[1]
        self.log = (self.directory / 'server.json').open('wb')
        self.process = subprocess.Popen(['iperf3', '-s', '-1', '-B', self.host, '-p', str(self.server_port),
                                         '--json'], stdout=self.log, stderr=subprocess.STDOUT)
        time.sleep(.25)
        if self.process.poll() is not None:
            self.close(); raise RuntimeError('iperf3 server exited before workload')
        return self.port

    def start_data(self, front):
        if self.datagram: return
        def accept():
            while not front.stop.is_set() and time.monotonic() < front.deadline:
                try: incoming, _ = self.data_listener.accept(); break
                except socket.timeout: continue
                except OSError: return
            else: return
            front.copy(incoming, (self.host, self.server_port))
        self.data_thread = threading.Thread(target=accept, daemon=True)
        self.data_thread.start()

    def close(self):
        if self.data_listener: self.data_listener.close()
        if self.data_thread: self.data_thread.join(1)
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        if self.log: self.log.close()


class Frontend:
    """At most two TCP connections, two threads and 256 KiB per copy direction."""
    def __init__(self, target, endpoint, seconds):
        self.target, self.endpoint = target, endpoint
        self.deadline = time.monotonic() + seconds + 15
        self.stop = threading.Event()
        self.errors = []
        self.threads = []
        self.listener = socket.socket(target.family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((target.host, endpoint[1] if target.datagram else 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(2); self.listener.settimeout(.2)
        self.thread = threading.Thread(target=self.accept, daemon=True)

    def accept(self):
        try:
            for number in range(1 if self.target.datagram else 2):
                while not self.stop.is_set() and time.monotonic() < self.deadline:
                    try: incoming, _ = self.listener.accept(); break
                    except socket.timeout: continue
                else: return
                destination = (self.target.host, self.target.server_port) if number == 0 else self.endpoint
                worker = threading.Thread(target=self.copy, args=(incoming, destination, number == 0), daemon=True)
                self.threads.append(worker); worker.start()
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(str(error))

    def copy(self, incoming, destination, control=False):
        try:
            with incoming, socket.create_connection(destination, timeout=5) as outgoing, selectors.DefaultSelector() as poller:
                if control: self.target.start_data(self)
                peers = {incoming: outgoing, outgoing: incoming}
                pending = {incoming: bytearray(), outgoing: bytearray()}
                reading = set(peers)
                finished = set()
                for connection in peers:
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    connection.setblocking(False)
                while not self.stop.is_set() and time.monotonic() < self.deadline:
                    for connection in peers:
                        if peers[connection] not in reading and not pending[connection] and connection not in finished:
                            connection.shutdown(socket.SHUT_WR)
                            finished.add(connection)
                        events = (selectors.EVENT_READ if connection in reading and len(pending[peers[connection]]) < 262144 else 0)
                        if pending[connection]: events |= selectors.EVENT_WRITE
                        try: poller.unregister(connection)
                        except KeyError: pass
                        if events: poller.register(connection, events)
                    if not reading and not any(pending.values()): return
                    for key, events in poller.select(.1):
                        connection = key.fileobj
                        if events & selectors.EVENT_READ:
                            data = connection.recv(262144 - len(pending[peers[connection]]))
                            if data: pending[peers[connection]].extend(data)
                            else: reading.discard(connection)
                        if events & selectors.EVENT_WRITE:
                            try: sent = connection.send(pending[connection])
                            except BlockingIOError: continue
                            del pending[connection][:sent]
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(str(error))

    def __enter__(self): self.thread.start(); return self
    def __exit__(self, *args):
        self.stop.set(); self.listener.close(); self.thread.join(1)
        for worker in self.threads: worker.join(1)


def measure(endpoint, target, processes, seconds, reverse, rate, baseline=False):
    before = snapshot(processes)
    fixture = (nullcontext(SimpleNamespace(port=target.server_port, errors=[]))
               if baseline and target.datagram else Frontend(target, endpoint, seconds))
    with fixture as front:
        command = ['iperf3', '-c', target.host, '-p', str(front.port), '-t', str(seconds),
                   '-P', '1', '--json', '--get-server-output']
        if reverse: command.append('-R')
        if target.datagram:
            command += ['-u', '-b', str(rate), '-l', '900', '--pacing-timer', '100']
        started = time.monotonic()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=seconds + 12)
        elapsed = time.monotonic() - started
    (target.directory / 'client.json').write_bytes(result.stdout)
    (target.directory / 'client.stderr').write_bytes(result.stderr)
    after = snapshot(processes)
    document = json.loads(result.stdout)
    if result.returncode or document.get('error'):
        raise RuntimeError(document.get('error', result.stderr.decode(errors='replace')))
    end = document['end']
    receiver, target_met = receiver_result(document, target.datagram)
    return {'status': 'ok', 'receiver_bps': receiver['bits_per_second'], 'receiver': receiver,
            'elapsed_seconds': elapsed, 'roles_before': before, 'roles_after': after,
            'fixture_errors': front.errors, 'command': command,
            'retransmits': end.get('sum_sent', {}).get('retransmits'),
            'target_met': target_met}


def case(core, directory, seconds, reverse, rate, baseline=False):
    directory.mkdir(parents=True)
    engine = 'shadow6-' + core
    datagram = engine in DATAGRAM_CORES
    family = socket.AF_INET6 if core == 'hare' else socket.AF_INET
    row = {'core': core, 'direction': 'reverse' if reverse else 'forward',
           'protocol': 'udp' if datagram else 'tcp', 'raw_directory': str(directory),
           'offered_bps': rate if datagram else None, 'baseline': baseline}
    try:
        if baseline:
            target = IperfTarget(family, datagram, directory)
            try:
                target.start()
                row.update(measure((target.host, target.port), target, (), seconds, reverse, rate, True))
            finally: target.close()
        else:
            row.update(run_engine(engine, workload=lambda endpoint, target, processes:
                       measure(endpoint, target, processes, seconds, reverse, rate),
                       target_factory=lambda family, datagram: IperfTarget(family, datagram, directory)))
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired, TimeoutError) as error:
        row.update(status='failed', reason=str(error), target_met=False)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', action='append', choices=[name.removeprefix('shadow6-') for name in CORE_BINARIES])
    parser.add_argument('--seconds', type=int, default=3)
    parser.add_argument('--parallel', type=int, default=1)
    parser.add_argument('--udp-rate', type=int, default=1_100_000_000)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-gbps', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 5 or not 1 <= args.parallel <= 4 or not 1 <= args.udp_rate <= 1_200_000_000:
        parser.error('bounds: seconds 1..5, parallel 1..4, UDP rate 1..1.2G')
    if not shutil.which('iperf3'): parser.error('iperf3 is required')
    args.output.mkdir(parents=True, exist_ok=True)
    cores = args.core or [name.removeprefix('shadow6-') for name in CORE_BINARIES]
    rows = []
    for core in cores:
        for reverse in (False, True):
            label = core + ('-reverse' if reverse else '-forward')
            # UDP baseline is direct; a TCP fixture baseline uses the same copy.
            rows.append(case(core, args.output / (label+'-baseline'), args.seconds, reverse, args.udp_rate, True))
            with ThreadPoolExecutor(max_workers=args.parallel) as pool:
                futures = [pool.submit(case, core, args.output / f'{label}-{i}', args.seconds, reverse, args.udp_rate)
                           for i in range(args.parallel)]
                for future in futures: rows.append(future.result())
            report = {'schema': 'shadow6.iperf-chain.v1', 'commit': os.environ.get('GITHUB_SHA'),
                      'platform': platform.platform(), 'logical_cpus': os.cpu_count(),
                      'parallel': args.parallel, 'concurrency_scope': 'independent-native-trios',
                      'control_path': 'direct loopback TCP; excluded from measured data',
                      'tcp_fixture': 'bounded Python copy; inspect fixture baseline for its ceiling',
                      'gbps_target': 1_000_000_000, 'results': rows}
            (args.output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return int(any(row['status'] != 'ok' or (args.require_gbps and not row['baseline'] and not row['target_met']) for row in rows))

if __name__ == '__main__': raise SystemExit(main())
