"""Bounded process-local capability handles for reviewed application sessions."""
from __future__ import annotations

import atexit
import secrets
import socket
import threading
import time

try:
    from .connection_plan import LocalMessageSession, open_local_session
except ImportError:
    from connection_plan import LocalMessageSession, open_local_session


MAX_SESSIONS = 64
MAX_READ_BYTES = 65_536
MAX_WRITE_BYTES = 32_768
MAX_TIMEOUT_MS = 5_000


class SessionHandleManager:
    """Own short-lived local sessions without persisting sockets or capabilities."""

    def __init__(self, limit=MAX_SESSIONS):
        if type(limit) is not int or not 1 <= limit <= MAX_SESSIONS:
            raise ValueError('InvalidApplicationSessionLimit')
        self.limit = limit
        self._lock = threading.RLock()
        self._entries = {}

    @staticmethod
    def _remaining_ms(session):
        return max(0, int((session.deadline - time.monotonic()) * 1000))

    @staticmethod
    def _metadata(handle, entry):
        session = entry['session']
        result = {
            'schema': 'shadow6.application-session.v1',
            'handle': handle,
            'boundary': entry['boundary'],
            'recordPreserving': entry['boundary'] == 'message',
            'lifetimeRemainingMs': SessionHandleManager._remaining_ms(session),
            'bytesRemaining': max(0, int(session.remaining)),
            'maxReadBytes': MAX_READ_BYTES,
            'maxWriteBytes': MAX_WRITE_BYTES,
        }
        if entry['boundary'] == 'message':
            result['maxRecord'] = session.max_record
        return result

    @staticmethod
    def _close_entry(entry):
        try:
            entry['session'].close()
        except OSError:
            pass

    def _reap_locked(self):
        now = time.monotonic()
        expired = [handle for handle, entry in self._entries.items()
                   if now >= entry['session'].deadline]
        for handle in expired:
            entry = self._entries.pop(handle)
            self._close_entry(entry)

    def open(self, service, lock_digest, plan_digest, plan):
        if not isinstance(service, str) or not isinstance(lock_digest, str) or not isinstance(plan_digest, str):
            raise ValueError('InvalidApplicationSessionBinding')
        session = open_local_session(plan)
        boundary = 'message' if isinstance(session, LocalMessageSession) else 'stream'
        entry = {'service': service, 'lockDigest': lock_digest, 'planDigest': plan_digest,
                 'boundary': boundary, 'session': session, 'ioLock': threading.RLock()}
        with self._lock:
            self._reap_locked()
            if len(self._entries) >= self.limit:
                self._close_entry(entry)
                raise ValueError('ApplicationSessionCapacityReached')
            while True:
                handle = secrets.token_urlsafe(32)
                if handle not in self._entries:
                    break
            self._entries[handle] = entry
            return self._metadata(handle, entry)

    def _entry(self, handle):
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise ValueError('InvalidApplicationSessionHandle')
        with self._lock:
            self._reap_locked()
            entry = self._entries.get(handle)
            if entry is None:
                raise ValueError('ApplicationSessionExpiredOrUnknown')
            return entry

    @staticmethod
    def _set_timeout(session, timeout_ms):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise ValueError('InvalidApplicationSessionTimeout')
        remaining = session.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('ApplicationSessionExpiredOrUnknown')
        previous = session.socket.gettimeout()
        session.socket.settimeout(min(timeout_ms / 1000, remaining))
        return previous

    @staticmethod
    def _restore_timeout(session, previous):
        try:
            if getattr(session, 'socket', None) is not None:
                session.socket.settimeout(previous)
        except OSError:
            pass

    def _ensure_current(self, handle, entry):
        with self._lock:
            if self._entries.get(handle) is not entry:
                raise ValueError('ApplicationSessionExpiredOrUnknown')

    def read(self, handle, max_bytes, timeout_ms):
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_READ_BYTES:
            raise ValueError('InvalidApplicationSessionReadBound')
        entry = self._entry(handle)
        session = entry['session']
        with entry['ioLock']:
            self._ensure_current(handle, entry)
            if entry['boundary'] == 'message' and max_bytes < session.max_record:
                raise ValueError('MessageReadBoundTooSmall')
            previous = self._set_timeout(session, timeout_ms)
            try:
                data = session.receive_record() if entry['boundary'] == 'message' else session.receive(max_bytes)
            except (socket.timeout, TimeoutError) as error:
                raise TimeoutError('ApplicationSessionTimeout') from error
            except BaseException:
                self.close(handle)
                raise
            finally:
                self._restore_timeout(session, previous)
            eof = bool(getattr(session, 'eof', False)) if entry['boundary'] == 'message' else data == b''
            result = self._metadata(handle, entry)
            result.update(data=data, eof=eof)
            if eof:
                self.close(handle)
                result['closed'] = True
                result['lifetimeRemainingMs'] = 0
            return result

    def write(self, handle, data, timeout_ms):
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_WRITE_BYTES:
            raise ValueError('InvalidApplicationSessionWriteBound')
        entry = self._entry(handle)
        session = entry['session']
        with entry['ioLock']:
            self._ensure_current(handle, entry)
            previous = self._set_timeout(session, timeout_ms)
            try:
                if entry['boundary'] == 'message':
                    session.send_record(bytes(data))
                else:
                    session.send(bytes(data))
            except (socket.timeout, TimeoutError) as error:
                raise TimeoutError('ApplicationSessionTimeout') from error
            except BlockingIOError:
                raise
            except BaseException:
                self.close(handle)
                raise
            finally:
                self._restore_timeout(session, previous)
            result = self._metadata(handle, entry)
            result.update(written=len(data), writeClosed=bool(getattr(session, 'write_closed', False)))
            return result

    def close(self, handle):
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise ValueError('InvalidApplicationSessionHandle')
        with self._lock:
            entry = self._entries.pop(handle, None)
        if entry is None:
            return {'schema': 'shadow6.application-session-close.v1', 'handle': handle, 'closed': False}
        with entry['ioLock']:
            self._close_entry(entry)
        return {'schema': 'shadow6.application-session-close.v1', 'handle': handle, 'closed': True}

    def transfer_fd(self, handle):
        """Transfer one approved attachment to an owner-controlled Unix peer.

        The caller owns the returned descriptor. The web facade's byte/time
        budget no longer applies; native deployment limits still apply. This
        is used only by the fixed local FD adapter, never HTTP/MCP/LLM tools.
        """
        entry = self._entry(handle)
        with entry['ioLock']:
            self._ensure_current(handle,entry)
            with self._lock:
                if self._entries.get(handle) is not entry:
                    raise ValueError('ApplicationSessionExpiredOrUnknown')
                del self._entries[handle]
            return entry['session'].socket.detach()

    def close_service(self, service):
        with self._lock:
            handles = [handle for handle, entry in self._entries.items() if entry['service'] == service]
        closed = 0
        for handle in handles:
            if self.close(handle)['closed']:
                closed += 1
        return closed

    def close_all(self):
        with self._lock:
            handles = list(self._entries)
        for handle in handles:
            self.close(handle)


sessions = SessionHandleManager()
atexit.register(sessions.close_all)
