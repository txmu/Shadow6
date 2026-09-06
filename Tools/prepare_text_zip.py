#!/usr/bin/env python3
"""Remove non-text files and append .txt to text files in a ZIP staging tree."""

from __future__ import annotations

import argparse
import codecs
import os
import stat
from pathlib import Path

ALLOWED_CONTROLS = {8, 9, 10, 12, 13}


def is_utf8_text(path: Path) -> bool:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with path.open("rb") as source:
            while chunk := source.read(65_536):
                if b"\0" in chunk:
                    return False
                decoded = decoder.decode(chunk)
                if any(ord(character) < 32 and ord(character) not in ALLOWED_CONTROLS for character in decoded):
                    return False
            decoder.decode(b"", final=True)
    except (OSError, UnicodeDecodeError):
        return False
    return True


def prepare(root: Path) -> tuple[int, int]:
    root = root.resolve(strict=True)
    kept = removed = 0
    # Move existing suffix chains first: note.txt -> note.txt.txt before
    # note -> note.txt, preserving each original file exactly once.
    for path in sorted(root.rglob("*"), reverse=True):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            continue
        if is_utf8_text(path):
            destination = path.with_name(path.name + ".txt")
            if destination.exists():
                raise ValueError(f"ZIP text-name collision: {destination}")
            os.replace(path, destination)
            kept += 1
        else:
            path.unlink()
            removed += 1
    return kept, removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    kept, removed = prepare(args.root)
    print(f"ZIP text staging: kept {kept}, excluded {removed} non-text files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
