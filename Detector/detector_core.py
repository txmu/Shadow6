"""Shared, dependency-light primitives for the Shadow6 detectors."""

from __future__ import annotations

import collections
import contextlib
import json
import logging
import math
import os
import socket
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable, Sequence


LOGGER = logging.getLogger("Detector")
RF_FORMAT = "shadow6-random-forest-v1"
RF_FEATURES = ["packet_length", "entropy", "is_tcp", "payload_size", "iat"]
MAX_MODEL_BYTES = 64 * 1024 * 1024
MAX_TREES = 2_000
MAX_TREE_NODES = 2_000_000
MAX_CLASSES = 256


def atomic_write_json(path: str | Path, value: object) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_csv(path: str | Path, frame: object) -> None:
    """Persist a pandas-like frame without following an existing output symlink."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            frame.to_csv(handle, index=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def validate_model_file(path: str | Path) -> Path:
    model_path = Path(path).expanduser()
    info = model_path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("model path must be a regular, non-symlink file")
    if info.st_uid != os.geteuid():
        raise PermissionError("model file must be owned by the effective user")
    if info.st_mode & 0o022:
        raise PermissionError("model file must not be group/world writable")
    if info.st_size > MAX_MODEL_BYTES:
        raise ValueError("model file is too large")
    return model_path.resolve(strict=True)


@contextlib.contextmanager
def open_validated_model(path: str | Path):
    """Open an owner-controlled model without a check/open replacement race."""
    model_path = Path(path).expanduser()
    before = model_path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("model path must be a regular, non-symlink file")
    if before.st_uid != os.geteuid():
        raise PermissionError("model file must be owned by the effective user")
    if before.st_mode & 0o022:
        raise PermissionError("model file must not be group/world writable")
    if before.st_size > MAX_MODEL_BYTES:
        raise ValueError("model file is too large")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(model_path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("model file changed while it was being opened")
        if opened.st_uid != os.geteuid() or opened.st_mode & 0o022:
            raise PermissionError("opened model file has unsafe ownership or permissions")
        if opened.st_size > MAX_MODEL_BYTES:
            raise ValueError("model file is too large")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            yield handle
    finally:
        os.close(descriptor)


class TrafficFeatures:
    """Bounds-checked Ethernet/IPv4/IPv6 feature extraction."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        counts = collections.Counter(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def extract_features(packet: bytes) -> tuple[int, float, int, int]:
        packet_length = len(packet)
        payload = b""
        is_tcp = 0
        if packet_length < 14:
            return packet_length, 0.0, 0, 0

        offset = 14
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8):
                break
            if packet_length < offset + 4:
                return packet_length, 0.0, 0, 0
            ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4

        protocol = -1
        transport_offset = 0
        payload_end = packet_length

        if ethertype == 0x0800:  # IPv4
            if packet_length < offset + 20:
                return packet_length, 0.0, 0, 0
            version_ihl = packet[offset]
            if version_ihl >> 4 != 4:
                return packet_length, 0.0, 0, 0
            ip_header_len = (version_ihl & 0x0F) * 4
            if ip_header_len < 20 or packet_length < offset + ip_header_len:
                return packet_length, 0.0, 0, 0
            total_len = struct.unpack_from("!H", packet, offset + 2)[0]
            if total_len < ip_header_len:
                return packet_length, 0.0, 0, 0
            payload_end = min(packet_length, offset + total_len)
            fragment = struct.unpack_from("!H", packet, offset + 6)[0]
            if fragment & 0x1FFF:
                return packet_length, 0.0, 0, 0
            protocol = packet[offset + 9]
            transport_offset = offset + ip_header_len
        elif ethertype == 0x86DD:  # IPv6
            if packet_length < offset + 40 or packet[offset] >> 4 != 6:
                return packet_length, 0.0, 0, 0
            payload_len = struct.unpack_from("!H", packet, offset + 4)[0]
            payload_end = min(packet_length, offset + 40 + payload_len)
            protocol = packet[offset + 6]
            transport_offset = offset + 40
            for _ in range(8):
                if protocol not in (0, 43, 44, 60, 51):
                    break
                if protocol == 44:
                    if transport_offset + 8 > payload_end:
                        return packet_length, 0.0, 0, 0
                    fragment = struct.unpack_from("!H", packet, transport_offset + 2)[0]
                    if fragment & 0xFFF8:
                        return packet_length, 0.0, 0, 0
                    protocol = packet[transport_offset]
                    transport_offset += 8
                    continue
                if transport_offset + 2 > payload_end:
                    return packet_length, 0.0, 0, 0
                next_header = packet[transport_offset]
                unit = 4 if protocol == 51 else 8
                extension_len = (packet[transport_offset + 1] + (2 if protocol == 51 else 1)) * unit
                if extension_len <= 0 or transport_offset + extension_len > payload_end:
                    return packet_length, 0.0, 0, 0
                protocol = next_header
                transport_offset += extension_len
        else:
            return packet_length, 0.0, 0, 0

        if protocol == 6:  # TCP
            is_tcp = 1
            if transport_offset + 20 <= payload_end:
                tcp_header_len = (packet[transport_offset + 12] >> 4) * 4
                if tcp_header_len >= 20 and transport_offset + tcp_header_len <= payload_end:
                    payload = packet[transport_offset + tcp_header_len : payload_end]
        elif protocol == 17 and transport_offset + 8 <= payload_end:  # UDP
            udp_len = struct.unpack_from("!H", packet, transport_offset + 4)[0]
            if udp_len >= 8:
                udp_end = min(payload_end, transport_offset + udp_len)
                payload = packet[transport_offset + 8 : udp_end]

        return packet_length, TrafficFeatures.calculate_entropy(payload[:256]), is_tcp, len(payload)

    @staticmethod
    def flow_key(packet: bytes) -> tuple[bytes, bytes, int, int, int]:
        """Return a stable best-effort five-tuple without trusting packet lengths."""
        if len(packet) < 14:
            return b"", b"", -1, 0, 0
        offset = 14
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8) or len(packet) < offset + 4:
                break
            ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4
        source = destination = b""
        protocol = -1
        transport_offset = len(packet)
        if ethertype == 0x0800 and len(packet) >= offset + 20:
            ihl = (packet[offset] & 0x0F) * 4
            if packet[offset] >> 4 == 4 and ihl >= 20 and len(packet) >= offset + ihl:
                source = packet[offset + 12 : offset + 16]
                destination = packet[offset + 16 : offset + 20]
                protocol = packet[offset + 9]
                transport_offset = offset + ihl
        elif ethertype == 0x86DD and len(packet) >= offset + 40 and packet[offset] >> 4 == 6:
            source = packet[offset + 8 : offset + 24]
            destination = packet[offset + 24 : offset + 40]
            protocol = packet[offset + 6]
            transport_offset = offset + 40
        source_port = destination_port = 0
        if protocol in (6, 17) and len(packet) >= transport_offset + 4:
            source_port, destination_port = struct.unpack_from("!HH", packet, transport_offset)
        forward = (source, destination, source_port, destination_port)
        reverse = (destination, source, destination_port, source_port)
        canonical = min(forward, reverse)
        return canonical[0], canonical[1], protocol, canonical[2], canonical[3]


def export_random_forest(model: object, path: str | Path) -> None:
    """Persist sklearn RandomForest data as inert JSON instead of executable pickle."""
    estimators = []
    for estimator in model.estimators_:
        tree = estimator.tree_
        estimators.append(
            {
                "children_left": tree.children_left.tolist(),
                "children_right": tree.children_right.tolist(),
                "feature": tree.feature.tolist(),
                "threshold": tree.threshold.tolist(),
                "value": tree.value.tolist(),
            }
        )
    atomic_write_json(
        path,
        {
            "format": RF_FORMAT,
            "features": RF_FEATURES,
            "classes": [int(value) for value in model.classes_.tolist()],
            "estimators": estimators,
        },
    )


class SafeRandomForestModel:
    def __init__(self, data: dict):
        if not isinstance(data, dict) or set(data) != {"format", "features", "classes", "estimators"}:
            raise ValueError("model document contains missing or unknown fields")
        if data.get("format") != RF_FORMAT or data.get("features") != RF_FEATURES:
            raise ValueError("unsupported model format or feature schema")
        self.classes = data.get("classes")
        self.estimators = data.get("estimators")
        if (
            not isinstance(self.classes, list)
            or not (1 <= len(self.classes) <= MAX_CLASSES)
            or any(isinstance(value, bool) or not isinstance(value, int) for value in self.classes)
            or len(set(self.classes)) != len(self.classes)
        ):
            raise ValueError("model classes are invalid")
        if not isinstance(self.estimators, list) or not (1 <= len(self.estimators) <= MAX_TREES):
            raise ValueError("model tree count is invalid")
        total_nodes = 0
        for tree in self.estimators:
            if not isinstance(tree, dict) or set(tree) != {
                "children_left", "children_right", "feature", "threshold", "value"
            }:
                raise ValueError("model tree contains missing or unknown fields")
            arrays = [tree.get(key) for key in ("children_left", "children_right", "feature", "threshold", "value")]
            if not all(isinstance(array, list) for array in arrays):
                raise ValueError("model tree arrays are invalid")
            node_count = len(arrays[0])
            if node_count == 0 or any(len(array) != node_count for array in arrays):
                raise ValueError("model tree arrays have inconsistent lengths")
            total_nodes += node_count
            if total_nodes > MAX_TREE_NODES:
                raise ValueError("model has too many nodes")
            left, right, features, thresholds, values = arrays
            if any(isinstance(value, bool) or not isinstance(value, int) for value in left + right + features):
                raise ValueError("model tree indices must be integers")
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in thresholds
            ):
                raise ValueError("model thresholds must be finite numbers")

            incoming = [0] * node_count
            for node, (left_child, right_child) in enumerate(zip(left, right)):
                if left_child == right_child:
                    if left_child != -1:
                        raise ValueError("model leaf markers are invalid")
                else:
                    if not (0 <= features[node] < len(RF_FEATURES)):
                        raise ValueError("model contains an invalid feature index")
                    for child in (left_child, right_child):
                        if not 0 <= child < node_count or child == node:
                            raise ValueError("model contains an invalid tree edge")
                        incoming[child] += 1
                scores = values[node]
                if not (
                    isinstance(scores, list)
                    and len(scores) == 1
                    and isinstance(scores[0], list)
                    and len(scores[0]) == len(self.classes)
                    and all(
                        not isinstance(score, bool)
                        and isinstance(score, (int, float))
                        and math.isfinite(float(score))
                        and float(score) >= 0.0
                        for score in scores[0]
                    )
                ):
                    raise ValueError("model class scores are invalid")
                if left_child == -1 and not any(float(score) > 0.0 for score in scores[0]):
                    raise ValueError("model leaf has no class votes")
            if incoming[0] != 0 or any(count != 1 for count in incoming[1:]):
                raise ValueError("model is not a rooted tree")
            reachable = {0}
            pending = [0]
            while pending:
                node = pending.pop()
                if left[node] != -1:
                    for child in (left[node], right[node]):
                        if child in reachable:
                            raise ValueError("model contains a cycle or duplicate edge")
                        reachable.add(child)
                        pending.append(child)
            if len(reachable) != node_count:
                raise ValueError("model contains unreachable nodes")

    @classmethod
    def load(cls, path: str | Path) -> "SafeRandomForestModel":
        with open_validated_model(path) as handle:
            return cls(json.load(handle))

    def predict(self, rows: Iterable[Sequence[float]]) -> list[int]:
        predictions = []
        for row in rows:
            if len(row) != len(RF_FEATURES) or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in row
            ):
                raise ValueError("prediction row must contain five finite numeric features")
            votes = collections.Counter()
            for tree in self.estimators:
                node = 0
                seen = 0
                while tree["children_left"][node] != tree["children_right"][node]:
                    feature = tree["feature"][node]
                    if not isinstance(feature, int) or not 0 <= feature < len(row):
                        raise ValueError("model contains an invalid feature index")
                    child_key = "children_left" if float(row[feature]) <= float(tree["threshold"][node]) else "children_right"
                    node = tree[child_key][node]
                    seen += 1
                    if not isinstance(node, int) or not 0 <= node < len(tree["feature"]) or seen > len(tree["feature"]):
                        raise ValueError("model contains an invalid tree graph")
                values = tree["value"][node]
                if isinstance(values, list) and len(values) == 1 and isinstance(values[0], list):
                    values = values[0]
                class_index = max(range(len(values)), key=lambda index: float(values[index]))
                votes[self.classes[class_index]] += 1
            predictions.append(votes.most_common(1)[0][0])
        return predictions


class HeuristicProbeModel:
    """Conservative fallback used when no trained model is configured."""

    def predict(self, rows: Iterable[Sequence[float]]) -> list[int]:
        result = []
        for packet_length, entropy, is_tcp, payload_size, *_ in rows:
            suspicious = bool(is_tcp and payload_size > 0 and packet_length <= 512 and entropy < 4.5)
            result.append(int(suspicious))
        return result


class DecoyManager:
    """Bounded tarpit which cannot create an unlimited thread/socket workload."""

    def __init__(self, tarpit_port: int = 8080, host: str = "127.0.0.1", max_clients: int = 64, hold_seconds: int = 60):
        if not 0 <= tarpit_port <= 65535:
            raise ValueError("tarpit port must be between 0 and 65535")
        if max_clients < 1 or hold_seconds < 1:
            raise ValueError("max_clients and hold_seconds must be positive")
        self.tarpit_port = tarpit_port
        self.host = host
        self.hold_seconds = hold_seconds
        self.active = False
        self.server_thread: threading.Thread | None = None
        self._slots = threading.BoundedSemaphore(max_clients)
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._bind_error: Exception | None = None

    def _tarpit_loop(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind((self.host, self.tarpit_port))
                self.tarpit_port = int(server.getsockname()[1])
                server.listen(128)
                server.settimeout(0.5)
            except OSError as exc:
                self._bind_error = exc
                self.active = False
                self._ready.set()
                return
            LOGGER.info("[Decoy] bounded tarpit listening on %s:%d", self.host, self.tarpit_port)
            self._ready.set()
            while not self._stop.is_set():
                try:
                    connection, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not self._slots.acquire(blocking=False):
                    connection.close()
                    continue
                LOGGER.warning("[Decoy] scanner connection from %s", address)
                threading.Thread(target=self._stall_client, args=(connection,), daemon=True).start()

    def _stall_client(self, connection: socket.socket) -> None:
        deadline = time.monotonic() + self.hold_seconds
        try:
            with connection:
                connection.settimeout(2.0)
                while not self._stop.wait(1.0) and time.monotonic() < deadline:
                    connection.sendall(b"HTTP/1.1 200 OK\r\nX-Decoy: Active\r\n")
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            pass
        finally:
            self._slots.release()

    def start(self) -> None:
        if self.active:
            return
        self._bind_error = None
        self._ready.clear()
        self._stop.clear()
        self.active = True
        self.server_thread = threading.Thread(target=self._tarpit_loop, daemon=True)
        self.server_thread.start()
        if not self._ready.wait(timeout=3):
            self.active = False
            raise TimeoutError("tarpit did not become ready")
        if self._bind_error is not None:
            raise OSError(f"failed to bind tarpit: {self._bind_error}") from self._bind_error

    def stop(self) -> None:
        self.active = False
        self._stop.set()
        if self.server_thread:
            self.server_thread.join(timeout=2)


class LogMonitor:
    def __init__(self, log_path: str, decoy: DecoyManager | None = None, stop_event: threading.Event | None = None):
        self.log_path = log_path
        self.decoy = decoy
        self.stop_event = stop_event or threading.Event()

    def tail_log(self) -> None:
        path = Path(self.log_path)
        if not path.is_file():
            LOGGER.error("Log file %s does not exist.", self.log_path)
            return
        LOGGER.info("Monitoring log file %s for probe triggers", self.log_path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(0, os.SEEK_END)
            while not self.stop_event.is_set():
                line = handle.readline()
                if not line:
                    self.stop_event.wait(0.1)
                    continue
                if "DPI PROBING DETECTED" in line and self.decoy:
                    LOGGER.critical("Relay emitted probe alert: %s", line.strip())
                    self.decoy.start()
