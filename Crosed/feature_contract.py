"""Shared, strict feature-report contract for every registered Core family."""
import re

TRANSPORTS = {"shadow6-go": "kcp", "shadow6-rust": "quic", "shadow6-pony": "udp", "shadow6-gleam": "micro-mux", "shadow6-zig": "enet",
              "shadow6-ada": "cell-relay", "shadow6-d": "rle-udp", "shadow6-nim": "webrtc"}
CORE_PATHS = {name: f"Core-{suffix}/{name}" for name, suffix in (
    ("shadow6-go", "Go"), ("shadow6-rust", "Rust"), ("shadow6-pony", "Pony"), ("shadow6-gleam", "Gleam"), ("shadow6-zig", "Zig"),
    ("shadow6-ada", "Ada"), ("shadow6-d", "D"), ("shadow6-nim", "Nim"))}
CAPABILITY_LEVELS = {"observe.version": 1, "observe.health": 1, "policy.request": 2,
    "policy.config": 2, "transport.metadata": 3, "transport.application": 3,
    "identity.assert": 4, "identity.resolve": 4, "core.lifecycle": 5, "core.hook": 5}
BOOLEAN_FIELDS = {"crosed_compiled", "app_transport", "qubes_isolation", "gate_compiled",
                  "gate_enabled_by_default", "utf8"}
COMMON_FIELDS = BOOLEAN_FIELDS | {"core", "version", "crosed_max_level", "crosed_capabilities"}
EXTRA_FIELDS = {"shadow6-ada": {"cell_size"}, "shadow6-d": {"better_c"},
                "shadow6-nim": {"memory_model"}}


def validate_feature_report(report, expected_core=None):
    if not isinstance(report, dict) or not isinstance(report.get("core"), str):
        raise ValueError("feature report must identify its Core")
    core = report["core"]
    if core not in TRANSPORTS or expected_core is not None and core != expected_core:
        raise ValueError("unknown or mismatched Core identity")
    allowed = COMMON_FIELDS | {"transport"} | EXTRA_FIELDS.get(core, set())
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
    if "transport" in report and report["transport"] != TRANSPORTS[core]:
        raise ValueError("incorrect Core transport")
    if "cell_size" in report and (type(report["cell_size"]) is not int or report["cell_size"] != 512):
        raise ValueError("invalid cell size")
    if "better_c" in report and report["better_c"] is not True:
        raise ValueError("Core-D must use betterC")
    if "memory_model" in report and report["memory_model"] not in ("arc", "orc"):
        raise ValueError("Nim requires ARC/ORC")
    return report
