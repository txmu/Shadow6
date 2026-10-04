"""Small client-side reflector for the S6EPE Named Service signal socket."""
from __future__ import annotations

import os
import socket
import stat
import struct
from pathlib import Path

MAX_SDP = 32768
MAX_ID = 64


def _read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise OSError("S6EPE signalling bridge closed")
        result.extend(part)
    return bytes(result)


class WebrtcClientReflector:
    """Use an existing owner-only Name Service socket from a client endpoint.

    This adapter only reflects bounded SDP handoffs. ICE/DTLS and the S6EPE
    message session remain owned by their native implementations.
    """
    def __init__(self, path, session_id, *, leg="E", timeout=15):
        if not isinstance(path, str) or not os.path.isabs(path) or len(os.fsencode(path)) > 103:
            raise ValueError("invalid S6EPE signalling socket path")
        if not isinstance(session_id, str) or not 1 <= len(session_id.encode("ascii", "strict")) <= MAX_ID:
            raise ValueError("invalid S6EPE signalling session id")
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if any(character not in allowed for character in session_id):
            raise ValueError("invalid S6EPE signalling session id")
        if leg not in {"E", "N"}:
            raise ValueError("invalid S6EPE signalling leg")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise ValueError("invalid S6EPE signalling timeout")
        self.path, self.session_id, self.leg, self.timeout = path, session_id, leg, timeout

    def exchange(self, *, offer, local_sdp=None):
        if type(offer) is not bool or (offer and not isinstance(local_sdp, str)):
            raise ValueError("invalid S6EPE signalling exchange")
        if local_sdp is not None and (not isinstance(local_sdp, str) or
                not local_sdp.isascii() or not local_sdp or len(local_sdp.encode()) > MAX_SDP):
            raise ValueError("invalid bounded SDP")
        phase = "O" if offer else "P" if local_sdp is None else "A"
        session = self.session_id.encode("ascii")
        sdp = b"" if local_sdp is None else local_sdp.encode("ascii")
        request = (b"S6SG1" + self.leg.encode("ascii") + phase.encode("ascii") +
                   bytes([len(session)]) + session + struct.pack(">I", len(sdp)) + sdp)
        path = Path(self.path)
        parent = path.parent.lstat()
        entry = path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or
                parent.st_mode & 0o077 or not stat.S_ISSOCK(entry.st_mode) or
                entry.st_uid != os.geteuid() or entry.st_mode & 0o077):
            raise PermissionError("owner-only S6EPE Name Service socket required")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.path)
            if hasattr(socket, "SO_PEERCRED"):
                _, uid, _ = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != os.geteuid():
                    raise PermissionError("S6EPE Name Service peer identity mismatch")
            connection.sendall(request)
            header = _read_exact(connection, 9)
            if header[:4] != b"S6SR" or header[4:5] not in (b"O", b"A"):
                raise ValueError("invalid S6EPE signalling response")
            size = struct.unpack(">I", header[5:])[0]
            if size > MAX_SDP or (header[4:5] == b"A" and size != 0):
                raise ValueError("invalid S6EPE signalling response size")
            body = _read_exact(connection, size) if size else b""
            if header[4:5] == b"A":
                return None
            if not body:
                raise ValueError("empty remote SDP")
            try:
                return body.decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise ValueError("remote SDP is not ASCII") from error
        finally:
            connection.close()

    def offer(self, sdp):
        """Publish a client offer and return the paired answer."""
        return self.exchange(offer=True, local_sdp=sdp)

    def poll(self):
        """Wait for a server offer."""
        return self.exchange(offer=False)

    def answer(self, sdp):
        """Publish the answer for a received offer."""
        return self.exchange(offer=False, local_sdp=sdp)
