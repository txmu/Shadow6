"""Bounded, owner-only S6SG1 signalling broker for Named Services."""
from __future__ import annotations
import os, socket, stat, struct, threading, time

MAX_SDP = 32768
MAX_ID = 64
MAX_SESSIONS = 128

class SignallingBroker:
    def __init__(self, path, prefix, *, max_sessions=32):
        if not os.path.isabs(path) or len(os.fsencode(path)) > 103: raise ValueError('invalid signalling path')
        if not isinstance(prefix, str) or not prefix or len(prefix) > 31: raise ValueError('invalid signalling prefix')
        self.path, self.prefix = path, prefix
        self.max_sessions = max(1, min(int(max_sessions), MAX_SESSIONS)); self.sessions = {}; self.lock = threading.Lock(); self.stop_event = threading.Event(); self.sock = None

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
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        try:
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
                state = self.sessions.setdefault(sid, {'offer': None, 'answer': None, 'updated': time.monotonic()})
                state['updated'] = time.monotonic()
                phase = header[6:7]
                if phase == b'O': state['offer'] = sdp
                elif phase == b'A': state['answer'] = sdp
                result = state['answer'] if phase == b'O' else state['offer']
            if phase == b'A':
                self._reply(conn, b'A', b''); return
            if result is None:
                result = self._wait(sid, 'answer' if phase == b'O' else 'offer')
            if result is None: self._reply(conn, b'A', b'')
            else: self._reply(conn, b'O', result.encode('ascii'))
        except (OSError, UnicodeError, ValueError, struct.error):
            pass
        finally: conn.close()

    def _wait(self, sid, key):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not self.stop_event.is_set():
            with self.lock:
                state = self.sessions.get(sid)
                if not state: return None
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
