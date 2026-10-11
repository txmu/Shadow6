"""One deterministic drop on the owned A-to-B raw S6EPE application hop."""
import subprocess
import re
import threading
import time

from network import system_tool


class FirstCarrierDatagramDrop:
    def __init__(self, pair):
        self.pair = pair; self.tc = system_tool('tc')
        self.stop = threading.Event(); self.thread = None
        self.dropped = 0; self.removed = False; self.errors = []

    def command(self, arguments):
        result = subprocess.run(self.pair.exec(self.pair.a, [self.tc, *arguments]),
            capture_output=True, timeout=2, check=True)
        if len(result.stdout) > 16384: raise ValueError('fault observation exceeds bound')
        return result.stdout

    def start(self):
        if not self.tc: raise PermissionError('tc required for owned first-datagram fault')
        self.command(['qdisc', 'add', 'dev', 's6tl-a', 'clsact'])
        self.command(['filter', 'add', 'dev', 's6tl-a', 'egress', 'protocol', 'ip',
            'pref', '404', 'u32', 'match', 'ip', 'protocol', '17', '0xff',
            'match', 'ip', 'dst', '198.18.6.2/32',
            # Offset zero admits both an unfragmented datagram and its first
            # IPv4 fragment. The MF bit is excluded from this mask. flower's
            # L4 port dissector skips fragmented datagrams, delaying the fault
            # until game traffic instead of the first business record.
            'match', 'u16', '0', '0x1fff', 'at', '6',
            'match', 'ip', 'dport', '18402', '0xffff', 'action', 'drop'])
        def observe():
            deadline = time.monotonic() + 90
            try:
                while not self.stop.is_set() and time.monotonic() < deadline:
                    # u32's JSON output repeats selector keys, which our
                    # strict JSON parser correctly rejects. Read the single
                    # fixed action's bounded statistics line instead.
                    text = self.command(['-s', 'filter', 'show', 'dev', 's6tl-a', 'egress']).decode('ascii')
                    counters = re.findall(r'(?m)^\s*Sent\s+([0-9]{1,20})\s+bytes\s+([0-9]{1,20})\s+pkt\s+\(dropped\s+([0-9]{1,20}),', text)
                    if len(counters) != 1 or any(int(value) >= 2**64 for value in counters[0]):
                        raise ValueError('invalid single-action fault counters')
                    self.dropped = max(self.dropped, int(counters[0][2]))
                    if self.dropped: break
                    self.stop.wait(.1)
                if not self.dropped and not self.stop.is_set(): self.errors.append('DropObservationDeadline')
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.errors.append(type(error).__name__)
            finally:
                try:
                    self.command(['filter', 'del', 'dev', 's6tl-a', 'egress', 'protocol', 'ip', 'pref', '404'])
                    self.removed = True
                except (OSError, subprocess.SubprocessError) as error: self.errors.append(type(error).__name__)
        self.thread = threading.Thread(target=observe, name='owned-first-datagram-drop')
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive(): self.errors.append('DropMonitorCleanupDeadline')

    def evidence(self):
        return {'schema': 'shadow6.first-carrier-datagram-drop.v1',
            'status': 'PASS' if self.dropped == 1 and self.removed and not self.errors else 'FAIL',
            'namespace': self.pair.a, 'interface': 's6tl-a', 'destination': '198.18.6.2:18402',
            'transport': 'udp', 'observedDroppedPackets': str(self.dropped),
            'filterRemoved': self.removed, 'errors': self.errors,
            'scope': 'owned raw S6EPE application hop; no host interface or native Core packet injection'}
