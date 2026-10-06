"""Isolated subprocess entry point; invokes the repository's real native runner."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Deployment"))
sys.path.insert(0, str(ROOT / "integration"))
sys.path.insert(0, str(ROOT / "Crosed"))
from profile_registry import select_profile


def run(core: str, profile_id: str, binary: Path, payload_bytes: int, requests: int, rtt_ms: int):
    profile = select_profile(core, profile_id)
    if type(payload_bytes) is not int or not 1 <= payload_bytes <= 65536:
        raise ValueError("payload-bytes must be 1..65536")
    if type(requests) is not int or not 1 <= requests <= 100:
        raise ValueError("requests must be 1..100")
    if not binary.is_file() or binary.is_symlink():
        raise FileNotFoundError("registered Core artifact is not a regular file")
    import stack_test
    engine = "shadow6-" + profile["benchmarkAlias"]
    stack_test.CORE_BINARIES[engine] = binary.resolve()
    if type(rtt_ms) is not int or not 0 <= rtt_ms <= 250:
        raise ValueError("rtt-ms must be 0..250")
    result = stack_test.run_engine(engine, {"payload_bytes": payload_bytes, "requests": requests,
        "concurrency": 1, "rtt_ms": rtt_ms, "loss_percent": 0}, "native")
    if not isinstance(result, dict) or result.get("success_rate") != 1.0 or result.get("bytes_received") != payload_bytes * requests:
        raise ValueError("native application workload did not satisfy bounded correctness contract")
    return {"status": "PASS", "core": core, "profile": profile_id,
            "nativeTransport": profile["nativeTransport"],
            "applicationBoundary": profile["applicationBoundary"],
            "correctness": {"status": "PASS", "workload": "native-three-role-echo-v1",
                "payloadBytes": payload_bytes, "requests": requests,
                "bytesSent": result["bytes_sent"], "bytesReceived": result["bytes_received"],
                "successRate": result["success_rate"]},
            "metrics": {"durationSeconds": result["duration_seconds"],
                "goodputBitsPerSecond": result["throughput_bps"],
                "rttP95Seconds": result["latency_p95_seconds"],
                "rttAverageSeconds": result["latency_avg_seconds"],
                "cpuSeconds": None, "peakRssBytes": None,
                "unavailableMetrics": ["native process CPU/RSS counters", "Core-internal transport counters"]},
            "runtimeObservation": {"status": "unavailable", "reason": "stack_test owns an isolated ephemeral trio, not a Named Service"},
            "adapter": None, "carrier": "native"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--rtt-ms", type=int, default=0)
    args = parser.parse_args()
    try:
        result = run(args.core, args.profile, args.binary, args.payload_bytes, args.requests, args.rtt_ms)
    except PermissionError as error:
        result = {"status": "BLOCKED", "core": args.core, "profile": args.profile,
                  "reason": f"test host denied the requested socket/process capability: {error}"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {"status": "FAIL", "core": args.core, "profile": args.profile,
                  "reason": f"{type(error).__name__}: {error}"}
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
