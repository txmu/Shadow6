#!/usr/bin/env python3
"""Keep the generated Chez process in the launcher PID for supervision."""
import argparse
from pathlib import Path


def normalize(path: Path, app: str) -> None:
    if app not in ('shadow6-idris_app', 'shadow6-idris-crosed_app'):
        raise ValueError('unexpected Idris runtime directory')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('invalid generated Idris launcher')
    source = path.read_text(encoding='ascii')
    if not source.startswith('#!/bin/sh\n'):
        raise ValueError('unexpected Idris launcher header')
    original = '"$DIR/shadow6-idris_app/shadow6-idris.so" "$@"'
    replacement = 'exec "$DIR/' + app + '/shadow6-idris.so" "$@"'
    body = source.rstrip()
    if body.endswith(replacement):
        return
    tail = next((candidate for candidate in ('exec ' + original, original)
                 if body.endswith(candidate)), None)
    if tail is None:
        raise ValueError('unexpected Idris launcher tail')
    path.write_text(body[:-len(tail)] + replacement + '\n', encoding='ascii')
    path.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('launcher', type=Path)
    parser.add_argument('app', choices=('shadow6-idris_app', 'shadow6-idris-crosed_app'))
    args = parser.parse_args()
    normalize(args.launcher, args.app)
