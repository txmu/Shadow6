#!/usr/bin/env python3
"""Export the authoritative Native Profile Registry for the Android catalog."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Crosed"))
from native_profiles import CORE_IDS, SCHEMA, profile_digest, profiles


def catalog():
    items = []
    for profile in profiles():
        items.append({
            "id": profile["id"],
            "core": profile["core"],
            "primary": profile["primary"],
            "nativeTransport": profile["nativeTransport"],
            "applicationBoundary": profile["applicationBoundary"],
            "requirements": profile["requirements"],
            "artifact": profile["artifact"],
            "contractDigest": profile_digest(profile),
        })
    if len({item["core"] for item in items if item["primary"]}) != len(CORE_IDS):
        raise ValueError("Native Profile Registry does not contain every primary Core")
    return {"schema": "shadow6.android-native-profile-catalog.v1",
            "sourceSchema": SCHEMA, "profiles": items}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    value = catalog()
    data = (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(data) > 256 * 1024:
        raise SystemExit("Android Native Profile catalog exceeds 256 KiB")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(args.output)
    print(f"Exported {len(CORE_IDS)} Native Cores / {len(value['profiles'])} Profiles")


if __name__ == "__main__":
    main()
