#!/usr/bin/env python3
"""Build Shadow6 packet features from a public CTU botnet PCAP.

The CTU-42 file is explicitly the botnet-only capture, so every extracted
packet is labelled 1.  A real Shadow6 capture supplied with the local
experiment is used as the normal (0) source by default.  No packets are
transmitted by this tool; parsing is offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from shadow6_detector_neo import ModelPipeline


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", required=True, type=Path)
    ap.add_argument("--ctu-pcap", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--max-packets", type=int, default=1_000_000)
    args = ap.parse_args()
    ModelPipeline.extract_pcap_to_csv(str(args.normal), str(args.ctu_pcap), str(args.output), args.max_packets)
    manifest = {
        "dataset": "CTU-Malware-Capture-Botnet-42 / Neris",
        "source": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/",
        "normal_source": str(args.normal),
        "botnet_source": str(args.ctu_pcap),
        "botnet_sha256": sha256(args.ctu_pcap),
        "labels": {"0": "local Shadow6 normal capture", "1": "CTU botnet-only capture"},
        "feature_schema": ["packet_length", "entropy", "is_tcp", "payload_size", "iat"],
        "offline_only": True,
    }
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
