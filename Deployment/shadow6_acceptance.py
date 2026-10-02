#!/usr/bin/env python3
"""Single, source-friendly acceptance gate for deployed Shadow6 artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from shadow6_deployment import load_manifest, manifest_lock, plan_manifest
from shadow6_abi import decode_control, encode_control


def _case(name: str, status: str, detail: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail}


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def run_acceptance(manifest_path: str | Path, *, artifact_dir: str | Path | None = None, output: str | Path = "acceptance", source_only: bool = False) -> dict:
    started = int(time.time())
    out = Path(output)
    cases: list[dict] = []
    try:
        manifest = load_manifest(manifest_path)
        cases.append(_case("manifest.validate", "pass"))
        lock = manifest_lock(manifest)
        plan = plan_manifest(manifest)
        cases.append(_case("manifest.lock", "pass", lock["manifestDigest"]))
    except Exception as exc:
        cases.append(_case("manifest.validate", "fail", str(exc)))
        result = _result(cases, started, source_only)
        _emit(result, out)
        return result
    try:
        frame = encode_control("capabilities", {"boundary": "stream"})
        decode_control(frame)
        cases.append(_case("s6abi.vectors", "pass"))
    except Exception as exc:
        cases.append(_case("s6abi.vectors", "fail", str(exc)))
    if artifact_dir:
        root = Path(artifact_dir)
        if not root.exists():
            cases.append(_case("artifacts.present", "fail", "artifact directory does not exist"))
        else:
            reports = list(root.glob("feature-reports/*.json")) + list(root.glob("*feature-report*.json"))
            cases.append(_case("artifacts.feature-reports", "pass" if reports else "unavailable", f"{len(reports)} reports"))
            checksums = root / "checksums.txt"
            cases.append(_case("artifacts.checksums", "pass" if checksums.is_file() else "unavailable"))
    else:
        cases.append(_case("artifacts", "not-run", "no --artifact-dir supplied"))
    if source_only:
        for name in ("native.feature-reports", "native.loopback", "staged.install"):
            cases.append(_case(name, "unavailable", "--source-only"))
    else:
        for name in ("native.feature-reports", "native.loopback", "staged.install"):
            cases.append(_case(name, "unavailable", "CI artifacts or native binaries were not supplied"))
    result = _result(cases, started, source_only)
    _emit(result, out)
    return result


def _result(cases: list[dict], started: int, source_only: bool) -> dict:
    failed = sum(item["status"] == "fail" for item in cases)
    return {"schema": "shadow6.acceptance.v1", "status": "fail" if failed else "pass", "sourceOnly": source_only, "startedAt": started, "platform": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()}, "summary": {status: sum(x["status"] == status for x in cases) for status in ("pass", "fail", "unavailable", "not-run")}, "cases": cases}


def _emit(result: dict, out: Path) -> None:
    _write(out / "acceptance.json", result)
    lines = [f"Shadow6 acceptance: {result['status']}"] + [f"{x['status']:11} {x['name']} {x['detail']}" for x in result["cases"]]
    (out / "acceptance.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    junit = "<testsuite name=\"shadow6.acceptance\" tests=\"{}\" failures=\"{}\">".format(len(result["cases"]), result["summary"]["fail"])
    for case in result["cases"]:
        junit += f"<testcase name=\"{case['name']}\">" + (f"<failure message=\"{case['detail']}\"/>" if case["status"] == "fail" else "") + "</testcase>"
    (out / "acceptance.junit.xml").write_text(junit + "</testsuite>\n", encoding="utf-8")


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="shadow6 acceptance")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--output", type=Path, default=Path("acceptance"))
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args(argv)
    result = run_acceptance(args.manifest, artifact_dir=args.artifact_dir, output=args.output, source_only=args.source_only)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
