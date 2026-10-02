"""Shared, strict feature-report contract for every registered Core family."""
import os
import re
from pathlib import Path


def runtime_environment(root, relative):
    """Constrain loader paths for generated foreign runtimes during audits.

    Idris2's Chez backend and Core-Nim's libdatachannel shim load by soname.
    Inherited LD_LIBRARY_PATH / LD_PRELOAD would let ambient directories
    influence a security check, so only repository-owned directories are restored.
    """
    relative = str(relative).replace("\\", "/")
    root = Path(root)
    if relative.startswith("Core-Idris/"):
        directories = [
            root / "Core-Idris",
            root / "Core-Idris" / "shadow6-idris_app",
            root / "Core-Idris" / "shadow6-idris-crosed_app",
            root / "Core-Idris" / "ffi",
        ]
    elif relative.startswith("Core-Nim/"):
        directories = [root / "Core-Nim"]
    else:
        directories = []
    environment = os.environ.copy()
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"):
        environment.pop(name, None)
    existing = [str(path) for path in directories if path.is_dir() and not path.is_symlink()]
    if existing:
        loader_path = os.pathsep.join(existing)
        environment["LD_LIBRARY_PATH"] = loader_path
        environment["DYLD_LIBRARY_PATH"] = loader_path
    return environment


TRANSPORTS = {"shadow6-go": "kcp", "shadow6-rust": "quic", "shadow6-pony": "udp", "shadow6-gleam": "secure-stream", "shadow6-zig": "enet",
              "shadow6-ada": "cell-relay", "shadow6-d": "secure-stream", "shadow6-nim": "webrtc",
              "shadow6-cpp": "sctp-tls13", "shadow6-hare": "udp",
              "shadow6-carp": "udp", "shadow6-idris": "udp"}
CORE_PATHS = {name: f"Core-{suffix}/{name}" for name, suffix in (
    ("shadow6-go", "Go"), ("shadow6-rust", "Rust"), ("shadow6-pony", "Pony"), ("shadow6-gleam", "Gleam"), ("shadow6-zig", "Zig"),
    ("shadow6-ada", "Ada"), ("shadow6-d", "D"), ("shadow6-nim", "Nim"),
    ("shadow6-cpp", "Cpp"), ("shadow6-hare", "Hare"),
    ("shadow6-carp", "Carp"), ("shadow6-idris", "Idris"))}
CONFIGURABLE_CORES = frozenset(CORE_PATHS) - {"shadow6-idris"}
CAPABILITY_LEVELS = {"observe.version": 1, "observe.health": 1, "policy.request": 2,
    "policy.config": 2, "transport.metadata": 3, "transport.application": 3,
    "identity.assert": 4, "identity.resolve": 4, "core.lifecycle": 5, "core.hook": 5}
BOOLEAN_FIELDS = {"crosed_compiled", "app_transport", "qubes_isolation", "gate_compiled",
                  "gate_enabled_by_default", "utf8"}
COMMON_FIELDS = BOOLEAN_FIELDS | {"core", "version", "crosed_max_level", "crosed_capabilities"}
APP_TRANSPORT_MODES = {
    "shadow6-pony": ["udp", "seqpacket-fd"],
    "shadow6-hare": ["udp", "seqpacket-fd"],
    "shadow6-carp": ["udp", "seqpacket-fd"],
    "shadow6-idris": ["udp", "seqpacket-fd"],
}
SEQPACKET_MAX_RECORD = {
    "shadow6-pony": 1172,
    "shadow6-hare": 978,
    "shadow6-carp": 986,
    "shadow6-idris": 1024,
}
STREAM_CONNECTION_LIMIT = {
    "shadow6-go": 64, "shadow6-rust": 256, "shadow6-gleam": 1,
    "shadow6-zig": 16, "shadow6-ada": 1, "shadow6-d": 1,
    "shadow6-nim": 1, "shadow6-cpp": 64,
}
MESSAGE_BOUNDARY_FIELDS = {
    "kind", "mode", "roles", "max_record", "message_preserving",
    "backpressure", "producer_send_success", "oversize", "transient_error",
    "hard_error", "eof", "close",
}
STREAM_BOUNDARY_FIELDS = {
    "kind", "mode", "roles", "full_duplex", "ordered", "reliable",
    "backpressure", "half_close", "listener_ownership",
    "endpoint_discovery", "listener_ready", "local_connection_limit",
    "shutdown", "eof", "connection_mapping",
}
UDP_PROXY_BOUNDARY_FIELDS = {
    "kind", "mode", "roles", "message_preserving", "ordered", "reliable",
    "delivery", "backpressure", "max_record", "listener_ownership",
    "endpoint_discovery", "listener_ready", "local_peer_limit", "oversize",
}
CREDITED_BOUNDARY_FIELDS = {
    "kind", "mode", "credit_unit", "max_window", "backpressure",
    "backpressure_error", "close", "closed_error", "retry_exhaustion",
}
APPLICATION_BOUNDARY_KINDS = frozenset({"stream", "message", "credited"})


def validate_application_boundary(boundary):
    """Validate the S6NA companion boundary, whose credit is outside Native Core."""
    if (not isinstance(boundary, dict) or set(boundary) != CREDITED_BOUNDARY_FIELDS or
            boundary != {"kind": "credited", "mode": "s6na-companion",
                "credit_unit": "data-frames", "max_window": 64,
                "backpressure": "explicit-credit", "backpressure_error": "S6NA_BACKPRESSURE",
                "close": "invalidate-credit", "closed_error": "S6NA_CLOSED",
                "retry_exhaustion": "S6NA_RETRY_EXHAUSTED"}):
        raise ValueError("invalid credited application boundary")
    return boundary
EXTRA_FIELDS = {"shadow6-ada": {"cell_size"}, "shadow6-d": {"better_c"},
                "shadow6-nim": {"memory_model"},
                "shadow6-cpp": {"standalone", "control_protocol", "data_transport", "max_sessions"}}


def validate_feature_report(report, expected_core=None):
    if not isinstance(report, dict) or not isinstance(report.get("core"), str):
        raise ValueError("feature report must identify its Core")
    core = report["core"]
    if core not in TRANSPORTS or expected_core is not None and core != expected_core:
        raise ValueError("unknown or mismatched Core identity")
    allowed = COMMON_FIELDS | {"transport", "app_transport_modes", "application_boundaries"} | EXTRA_FIELDS.get(core, set())
    if not COMMON_FIELDS <= set(report) or set(report) - allowed:
        raise ValueError("unknown or missing feature-report fields")
    if any(type(report[field]) is not bool for field in BOOLEAN_FIELDS):
        raise ValueError("feature flags must be booleans")
    if not isinstance(report["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]{1,32})?", report["version"]):
        raise ValueError("invalid Core version")
    level, caps = report["crosed_max_level"], report["crosed_capabilities"]
    if type(level) is not int or not 0 <= level <= 5:
        raise ValueError("invalid Crosed level")
    if not isinstance(caps, list) or len(caps) > 10 or any(not isinstance(c, str) for c in caps) or len(set(caps)) != len(caps):
        raise ValueError("invalid capability list")
    if any(c not in CAPABILITY_LEVELS or CAPABILITY_LEVELS[c] > level for c in caps):
        raise ValueError("capability exceeds reported level")
    if report["crosed_compiled"] != (level > 0):
        raise ValueError("contradictory Crosed build flags")
    if "transport.application" in caps and not report["app_transport"]:
        raise ValueError("application capability without application transport")
    if report["gate_enabled_by_default"] and not report["gate_compiled"]:
        raise ValueError("Gate enabled but not compiled")
    modes = report.get("app_transport_modes")
    expected_modes = APP_TRANSPORT_MODES.get(core)
    if expected_modes is None:
        if modes is not None:
            raise ValueError("application transport modes are not declared for this Core")
    elif modes != expected_modes:
        raise ValueError("invalid application transport modes")
    boundaries = report.get("application_boundaries")
    expected_count = 2 if core == "shadow6-gleam" else 1
    if (not isinstance(boundaries, list) or len(boundaries) != expected_count or
            any(not isinstance(boundary, dict) for boundary in boundaries)):
        raise ValueError("invalid application boundary list")
    if core == "shadow6-gleam":
        stream, datagram = boundaries
        if set(stream) != STREAM_BOUNDARY_FIELDS or stream != {
            "kind": "stream", "mode": "localhost-tcp-proxy", "roles": ["client"],
            "full_duplex": True, "ordered": True, "reliable": True,
            "backpressure": "tcp-flow-control", "half_close": True,
            "listener_ownership": "core", "endpoint_discovery": "stdout-ready-jsonl-v1",
            "listener_ready": "bound-and-listening", "local_connection_limit": 1,
            "shutdown": "close-active-flows", "eof": "propagate-half-close",
            "connection_mapping": "one-local-connection-per-native-flow",
        }:
            raise ValueError("invalid Gleam stream application boundary")
        if set(datagram) != UDP_PROXY_BOUNDARY_FIELDS or datagram != {
            "kind": "message", "mode": "localhost-udp-datagram-proxy", "roles": ["client"],
            "message_preserving": True, "ordered": False, "reliable": False,
            "delivery": "best-effort", "backpressure": "udp-datagram-loss",
            "max_record": 65465, "listener_ownership": "core",
            "endpoint_discovery": "stdout-ready-jsonl-v1", "listener_ready": "bound-and-listening",
            "local_peer_limit": 1, "oversize": "discard-datagram",
        }:
            raise ValueError("invalid Gleam Micro-Mux application boundary")
        if "transport" in report and report["transport"] != TRANSPORTS[core]:
            raise ValueError("incorrect Core transport")
        return report
    boundary = boundaries[0]
    if core in SEQPACKET_MAX_RECORD:
        if set(boundary) != MESSAGE_BOUNDARY_FIELDS or boundary != {
            "kind": "message", "mode": "seqpacket-fd", "roles": ["client"],
            "max_record": SEQPACKET_MAX_RECORD[core], "message_preserving": True,
            "backpressure": "native-window", "producer_send_success": "kernel-queue-only",
            "oversize": "discard-record-continue", "transient_error": "retry-eagain-eintr",
            "hard_error": "fail-closed",
            "eof": "empty-record-drain", "close": "drain-accepted-then-stop",
        }:
            raise ValueError("invalid message ingress boundary")
    else:
        if set(boundary) != STREAM_BOUNDARY_FIELDS or boundary != {
            "kind": "stream", "mode": "localhost-tcp-proxy", "roles": ["client"],
            "full_duplex": True, "ordered": True, "reliable": True,
            "backpressure": "tcp-flow-control", "half_close": True,
            "listener_ownership": "core", "endpoint_discovery": "stdout-ready-jsonl-v1",
            "listener_ready": "bound-and-listening",
            "local_connection_limit": STREAM_CONNECTION_LIMIT[core],
            "shutdown": "close-active-flows", "eof": "propagate-half-close",
            "connection_mapping": "one-local-connection-per-native-flow",
        }:
            raise ValueError("invalid stream application boundary")
    if "transport" in report and report["transport"] != TRANSPORTS[core]:
        raise ValueError("incorrect Core transport")
    if "cell_size" in report and (type(report["cell_size"]) is not int or report["cell_size"] != 512):
        raise ValueError("invalid cell size")
    if "better_c" in report and report["better_c"] is not True:
        raise ValueError("Core-D must use betterC")
    if "memory_model" in report and report["memory_model"] not in ("arc", "orc"):
        raise ValueError("Nim requires ARC/ORC")
    for field, expected in {"standalone": True, "control_protocol": "shadow6-cpp-wss-v1",
                            "data_transport": "sctp-tls13", "max_sessions": 16}.items():
        if field in report and (type(report[field]) is not type(expected) or report[field] != expected):
            raise ValueError("invalid C++ feature field: " + field)
    return report


def validate_ready_event(event, expected_core=None, expected_role="client"):
    """Validate a stable JSONL event used to discover a local proxy endpoint."""
    fields = {"event", "schema", "core", "role", "application_boundary"}
    if not isinstance(event, dict) or set(event) != fields:
        raise ValueError("unknown or missing ready-event fields")
    core = event["core"]
    if (core not in STREAM_CONNECTION_LIMIT and core != "shadow6-gleam" or
            expected_core is not None and core != expected_core):
        raise ValueError("unknown or mismatched ready-event Core")
    if event["event"] != "shadow6.ready" or type(event["schema"]) is not int or event["schema"] != 1:
        raise ValueError("invalid ready-event type or schema")
    if event["role"] != expected_role or expected_role != "client":
        raise ValueError("ready event is outside the declared application role")
    boundary = event["application_boundary"]
    if not isinstance(boundary, dict) or set(boundary) != {"kind", "mode", "endpoint"}:
        raise ValueError("invalid ready-event application boundary")
    valid_boundary = (
        boundary["kind"] == "stream" and boundary["mode"] == "localhost-tcp-proxy" and
        core in STREAM_CONNECTION_LIMIT
    ) or (
        boundary["kind"] == "message" and boundary["mode"] == "localhost-udp-datagram-proxy" and
        core == "shadow6-gleam"
    )
    if not valid_boundary:
        raise ValueError("ready event does not identify a declared local proxy")
    endpoint = boundary["endpoint"]
    if (not isinstance(endpoint, dict) or set(endpoint) != {"host", "port"} or
            endpoint["host"] != "127.0.0.1" or type(endpoint["port"]) is not int or
            not 1 <= endpoint["port"] <= 65535):
        raise ValueError("ready endpoint must be a valid loopback endpoint")
    return event
