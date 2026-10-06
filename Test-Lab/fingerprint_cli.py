#!/usr/bin/env python3
"""Analyze any classic PCAP with the Test Lab's versioned flow schema."""
import argparse
import json
from pathlib import Path
import sys

from fingerprint import analyze


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--core")
    parser.add_argument("--profile")
    parser.add_argument("--link-type", default="unknown")
    parser.add_argument("--scenario", default="unspecified")
    parser.add_argument("--output", type=Path, default=Path("fingerprint.json"))
    args = parser.parse_args(argv)
    try:
        report = analyze(args.pcap, run_id=args.run_id, core=args.core,
                         profile=args.profile, link_type=args.link_type,
                         scenario=args.scenario)
        data = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
        print(json.dumps({"schema": report["schema"], "flows": len(report["flows"]),
                          "output": str(args.output), "classification": report["classification"]["observed"]},
                         sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"fingerprint analysis failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
