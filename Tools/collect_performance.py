#!/usr/bin/env python3
"""Bundle same-run performance artifacts without merging incompatible metrics."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile


def expected_artifacts():
    names = {"shadow6-linux-network-benchmark", "shadow6-linux-arm64-network-benchmark",
             "shadow6-linux-iperf-chain"}
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
    files, total = [], 0
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
    lines += ["", "Android and extra Unix component builds do not currently emit performance measurements.",
              "See manifest.json for file hashes and all producer outcomes; this bundle is not a throughput pass certificate."]
    markdown = "\n".join(lines) + "\n"
    # Stage atomically outside the input tree; no archive member is extracted.
    with tempfile.TemporaryDirectory(prefix="shadow6-performance-", dir=output.parent) as temp:
        staged = Path(temp) / "bundle.zip"
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
            archive.writestr("SUMMARY.md", markdown)
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
