#!/usr/bin/env python3
"""Explicit CI provisioning: download a bounded, SHA-256-verified Go archive."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import urllib.request

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024


def select_archive(metadata, version):
    if not re.fullmatch(r"go1\.[0-9]+\.[0-9]+", version):
        raise ValueError("expected an exact stable Go version")
    filename = version + ".netbsd-amd64.tar.gz"
    matches = [f for release in metadata if release.get("version") == version
               for f in release.get("files", [])
               if f.get("filename") == filename and f.get("os") == "netbsd"
               and f.get("arch") == "amd64" and f.get("kind") == "archive"]
    if len(matches) != 1:
        raise ValueError("expected exactly one NetBSD Go archive")
    item = matches[0]
    if not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
        raise ValueError("invalid archive SHA-256")
    if type(item.get("size")) is not int or not 0 < item["size"] <= MAX_ARCHIVE:
        raise ValueError("invalid archive size")
    return item


def save_archive(source, destination, item):
    """Publish only after length and digest validation; never extract on the host."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=destination) as temporary:
        archive = Path(temporary) / "go.tar.gz"
        digest = hashlib.sha256()
        count = 0
        with archive.open("xb") as output:
            while chunk := source.read(min(1024 * 1024, item["size"] - count + 1)):
                count += len(chunk)
                if count > item["size"]:
                    raise ValueError("Go archive exceeds declared size")
                digest.update(chunk)
                output.write(chunk)
        if count != item["size"] or digest.hexdigest() != item["sha256"]:
            raise ValueError("Go archive size or SHA-256 mismatch")
        archive.replace(destination / "go.tar.gz")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"go1\.[0-9]+\.[0-9]+", args.version):
        parser.error("expected an exact stable Go version")
    with urllib.request.urlopen("https://go.dev/dl/?mode=json&include=all", timeout=30) as response:
        metadata = response.read(MAX_METADATA + 1)
    if len(metadata) > MAX_METADATA:
        raise ValueError("Go download metadata exceeds limit")
    item = select_archive(json.loads(metadata), args.version)
    # Construct the URL from the validated version, never from a metadata URL.
    url = "https://dl.google.com/go/" + args.version + ".netbsd-amd64.tar.gz"
    with urllib.request.urlopen(url, timeout=30) as response:
        save_archive(response, args.destination, item)
    print("Verified " + item["filename"])


if __name__ == "__main__":
    main()
