#!/usr/bin/env python3
"""Bundle same-run performance artifacts without merging incompatible metrics."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import zipfile


REPORT_SCHEMAS = {
    "shadow6.iperf3-matrix.v1", "shadow6.iperf-chain.v1",
    "shadow6.benchmark.v2", "shadow6.component-benchmark.v1",
}


def measurements(path, relative):
    """Retain each workload separately; never infer rates from startup times."""
    if path.suffix != ".json":
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError):
        return []  # Incomplete raw diagnostics are still included and hashed.
    if not isinstance(report, dict) or report.get("schema") not in REPORT_SCHEMAS:
        return []
    rows = report.get("results")
    if not isinstance(rows, list):
        raise ValueError(f"invalid benchmark results: {relative}")
    normalized = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"invalid benchmark row: {relative}#{index}")
        network = row.get("network") or row.get("metrics") or row
        rate = network.get("throughput_bps", row.get("receiver_bps"))
        if rate is not None and (type(rate) not in (int, float) or not math.isfinite(rate) or rate < 0):
            raise ValueError(f"invalid throughput: {relative}#{index}")
        dimensions = {key: row[key] for key in (
            "core", "component", "backend", "measurement", "protocol", "direction",
            "family", "streams", "baseline", "concurrency", "payload_bytes",
            "loss_percent", "reorder", "repeat") if key in row}
        for key in ("concurrency", "payload_bytes", "impairment", "duration_scope"):
            if key in network:
                dimensions[key] = network[key]
        normalized.append({"source": relative, "row": index, "schema": report["schema"],
                           "environment": report.get("environment", {}), "workload": dimensions,
                           "status": row.get("status", "unknown"), "throughput_bps": rate,
                           "target_met": row.get("target_met"), "reason": row.get("reason")})
    return normalized


def measurement_summary(rows):
    # One row per report; no cross-platform or cross-workload throughput sum.
    reports = {}
    for row in rows:
        counts = reports.setdefault(row["source"], {"ok": 0, "failed": 0, "other": 0, "rates": 0, "below": 0})
        status = row["status"]
        counts[status if status in ("ok", "failed") else "other"] += 1
        counts["rates"] += row["throughput_bps"] is not None
        counts["below"] += row["target_met"] is False
    lines = ["", "## Final benchmark summary", "",
             "Every measured rate and its workload/platform dimensions are in `measurements.json`.",
             "Rates retain their original scope and are never summed across workloads or architectures.",
             "Other statuses include unsupported and incomplete cases; they are not passes.", "",
             "| Report | OK | Failed | Other | Rate samples | Below target |",
             "|---|---:|---:|---:|---:|---:|"]
    for name, counts in sorted(reports.items()):
        safe = name.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        lines.append(f"| {safe} | {counts['ok']} | {counts['failed']} | {counts['other']} | {counts['rates']} | {counts['below']} |")
    if not reports:
        lines.append("No recognized benchmark reports were available.")
    return lines


def expected_artifacts():
    names = {"shadow6-linux-network-benchmark", "shadow6-linux-arm64-network-benchmark",
             "shadow6-linux-iperf-chain", "shadow6-iperf3-omnios-x86-64"}
    names.update(f"shadow6-idris-network-benchmark-{platform}" for platform in
                 ("ubuntu-latest", "ubuntu-24.04-arm", "macos-latest"))
    for platform, arches in (("linux", ("x86_64", "arm64")),
                             ("macos", ("x86_64", "arm64")),
                             ("windows", ("amd64", "arm64")),
                             ("alpine", ("x86_64", "aarch64")),
                             ("freebsd", ("x86-64", "arm64")),
                             ("openbsd", ("x86-64", "arm64")),
                             ("netbsd", ("x86-64", "arm64"))):
        for arch in arches:
            names.add(f"shadow6-iperf3-{platform}-{arch}")
            if platform not in ("linux", "alpine"):
                names.add(f"shadow6-{platform}-network-benchmark-{arch}")
    for platform in ("ubuntu-24.04", "macos-14", "windows-latest"):
        for version, gil in (("3.14", "1"), ("3.14t", "1"), ("3.14t", "0")):
            names.add(f"python-network-{platform}-{version}-gil-{gil}")
    return names


def collect(source, output, needs, summary):
    source, output = Path(source), Path(output)
    source.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"schema": "shadow6.performance-bundle.v1",
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "commit": os.environ.get("GITHUB_SHA"),
                "jobs": needs, "artifacts": []}
    files, total, samples = [], 0, []
    for artifact in sorted(source.iterdir()):
        if artifact.is_symlink() or not artifact.is_dir():
            raise ValueError("expected artifact directories")
        entry = {"name": artifact.name, "files": []}
        for path in sorted(artifact.rglob("*")):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ValueError("artifact contains a non-regular file")
            size = path.stat().st_size
            total += size
            if size > 64 * 1024**2 or total > 1024**3 or len(files) >= 20000:
                raise ValueError("performance bundle resource limit exceeded")
            relative = path.relative_to(source).as_posix()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024**2), b""):
                    digest.update(block)
            entry["files"].append({"path": relative, "bytes": size, "sha256": digest.hexdigest()})
            files.append((path, "artifacts/" + relative))
            samples.extend(measurements(path, relative))
            if len(samples) > 100000:
                raise ValueError("performance measurement count exceeds 100000")
        manifest["artifacts"].append(entry)
    manifest["missing_artifacts"] = sorted(expected_artifacts() - {
        entry["name"] for entry in manifest["artifacts"] if entry["files"]})
    lines = ["# Cross-platform performance artifacts", "",
             f"Run {manifest['run_id']}, attempt {manifest['run_attempt']}, commit `{manifest['commit']}`.", "",
             "Reports retain their artifact/platform/architecture directories and original units.",
             "Host iperf3 ceilings, native ABC paths and component microbenchmarks are distinct workloads; rates are not combined.",
             "Missing reports are not successful measurements. Failed jobs may have partial reports.", "",
             "| Producer job | Result |", "|---|---|"]
    for name, job in sorted(needs.items()):
        lines.append(f"| {name} | {job['result']} |")
    lines += ["", "| Artifact | Files | Bytes |", "|---|---:|---:|"]
    for entry in manifest["artifacts"]:
        lines.append(f"| {entry['name']} | {len(entry['files'])} | {sum(f['bytes'] for f in entry['files'])} |")
    if not files:
        lines += ["", "**No performance reports were produced or downloaded.**"]
    if manifest["missing_artifacts"]:
        lines += ["", "Expected performance artifacts without data:", ""]
        lines += [f"- `{name}`" for name in manifest["missing_artifacts"]]
    lines += ["", "Android, DragonFly and QEMU component builds do not currently emit performance measurements; OmniOS emits a host iperf3 matrix.",
              "See manifest.json for file hashes and all producer outcomes; this bundle is not a throughput pass certificate."]
    lines += measurement_summary(samples)
    markdown = "\n".join(lines) + "\n"
    # Stage atomically outside the input tree; no archive member is extracted.
    with tempfile.TemporaryDirectory(prefix="shadow6-performance-", dir=output.parent) as temp:
        staged = Path(temp) / "bundle.zip"
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
            archive.writestr("SUMMARY.md", markdown)
            archive.writestr("measurements.json", json.dumps({
                "schema": "shadow6.performance-measurements.v1", "results": samples}, indent=2) + "\n")
            for path, relative in files:
                archive.write(path, relative)
        staged.replace(output)
    if summary:
        with Path(summary).open("a") as stream:
            stream.write(markdown)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collect(args.input, args.output, json.loads(os.environ.get("PERFORMANCE_NEEDS", "{}")),
            os.environ.get("GITHUB_STEP_SUMMARY"))
