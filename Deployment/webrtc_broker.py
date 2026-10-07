"""Bounded, owner-only S6SG1 signalling broker for Named Services."""
from __future__ import annotations
import os, socket, stat, struct, threading, time
try:
    from limits import S6SG1_PROTOCOL_LIMITS, ENVELOPE_SAFE_DEFAULTS
except ImportError:
    from Crosed.limits import S6SG1_PROTOCOL_LIMITS, ENVELOPE_SAFE_DEFAULTS

MAX_SDP = S6SG1_PROTOCOL_LIMITS['sdp_bytes']
MAX_ID = S6SG1_PROTOCOL_LIMITS['session_id_bytes']
MAX_SESSIONS = 128

class SignallingBroker:
    def __init__(self, path, prefix, *, max_sessions=None, max_clients=None):
        if not os.path.isabs(path) or len(os.fsencode(path)) > 103: raise ValueError('invalid signalling path')
        if not isinstance(prefix, str) or not prefix or len(prefix) > 31: raise ValueError('invalid signalling prefix')
        self.path, self.prefix = path, prefix
        if max_sessions is None: max_sessions = ENVELOPE_SAFE_DEFAULTS['max_sessions']
        if type(max_sessions) is not int or not 1 <= max_sessions <= MAX_SESSIONS:
            raise ValueError('invalid signalling session bound')
        self.max_sessions = max_sessions; self.sessions = {}; self.lock = threading.Lock(); self.stop_event = threading.Event(); self.sock = None
        # Two legs may each hold an offer wait while their poll/answer request
        # is admitted. Reserving four slots avoids a self-inflicted deadlock.
        derived = S6SG1_PROTOCOL_LIMITS['waiters_per_session'] * max_sessions
        if max_clients is not None and (type(max_clients) is not int or max_clients != derived):
            raise ValueError('signalling client capacity must match the resolved session limit')
        self.max_clients = derived
        self.clients = threading.BoundedSemaphore(self.max_clients)

    def start(self):
        parent = os.path.dirname(self.path); os.makedirs(parent, mode=0o700, exist_ok=True); os.chmod(parent, 0o700)
        try: os.unlink(self.path)
        except FileNotFoundError: pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.bind(self.path); os.chmod(self.path, 0o600); self.sock.listen(self.max_sessions); self.sock.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True).start(); return self

    def close(self):
        self.stop_event.set()
        if self.sock:
            try: self.sock.close()
            except OSError: pass
        try: os.unlink(self.path)
        except OSError: pass
        with self.lock: self.sessions.clear()

    def _serve(self):
        while not self.stop_event.is_set():
            try: conn, _ = self.sock.accept()
            except (socket.timeout, OSError): continue
            if not self.clients.acquire(blocking=False): conn.close(); continue
            def admitted(connection):
                try: self._client(connection)
                finally: self.clients.release()
            threading.Thread(target=admitted, args=(conn,), daemon=True).start()

    def _client(self, conn):
        try:
            conn.settimeout(30)
            if hasattr(socket, 'SO_PEERCRED'):
                _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.geteuid(): return
            header = self._exact(conn, 8)
            if header[:5] != b'S6SG1' or header[5:6] not in (b'E', b'N') or header[6:7] not in (b'O', b'P', b'A'): return
            size = header[7]; sid = self._exact(conn, size).decode('ascii')
            if not sid or len(sid) > MAX_ID or not sid.startswith(self.prefix): return
            n = struct.unpack('>I', self._exact(conn, 4))[0]
            if n > MAX_SDP: return
            sdp = self._exact(conn, n).decode('ascii') if n else ''
            with self.lock:
                if sid not in self.sessions and len(self.sessions) >= self.max_sessions: return
                session = self.sessions.setdefault(sid, {'legs': {
                    leg: {'offer': None, 'answer': None, 'updated': time.monotonic()} for leg in ('E', 'N')}})
                leg = header[5:6].decode('ascii')
                state = session['legs'][leg]
                state['updated'] = time.monotonic()
                phase = header[6:7]
                field = 'offer' if phase == b'O' else 'answer' if phase == b'A' else None
                if field and (not sdp or (state[field] is not None and state[field] != sdp)): return
                if phase == b'O': state['offer'] = sdp
                elif phase == b'A': state['answer'] = sdp
                result = state['answer'] if phase == b'O' else state['offer']
            if phase == b'A':
                self._reply(conn, b'A', b''); return
            if result is None:
                result = self._wait(sid, leg, 'answer' if phase == b'O' else 'offer')
            if result is None: self._reply(conn, b'A', b'')
            else: self._reply(conn, b'O', result.encode('ascii'))
        except (OSError, UnicodeError, ValueError, struct.error):
            pass
        finally: conn.close()

    def _wait(self, sid, leg, key):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not self.stop_event.is_set():
            with self.lock:
                session = self.sessions.get(sid)
                if not session: return None
                state = session['legs'][leg]
                if state.get(key): return state[key]
                if time.monotonic() - state['updated'] > 60: self.sessions.pop(sid, None); return None
            time.sleep(.02)
        return None

    @staticmethod
    def _exact(conn, n):
        data=b''
        while len(data) < n:
            part=conn.recv(n-len(data))
            if not part: raise OSError('signalling peer closed')
            data += part
        return data

    @staticmethod
    def _reply(conn, phase, body): conn.sendall(b'S6SR' + phase + struct.pack('>I', len(body)) + body)
