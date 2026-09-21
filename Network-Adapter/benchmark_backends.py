#!/usr/bin/env python3
"""Compatibility entrypoint for the common 12-core x 3-path benchmark.

Backend comparisons exercise real native trios. Codec conformance stays in
test_network.py/test_node.mjs, never substituted for network throughput.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Benchmark"))
from benchmark import main

if __name__ == "__main__":
    if "--output" not in sys.argv:
        sys.argv.extend(("--output", "-"))
    if "--role" not in sys.argv:
        sys.argv.extend(("--role", "network-chain"))
    raise SystemExit(main())
