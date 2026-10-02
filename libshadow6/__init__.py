"""Thin Python facade over an installed Shadow6 deployment.

libshadow6 intentionally delegates policy, credentials, protocol handling and
feature discovery to the local Shadow6 installation. It is not a second SDK.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

__all__ = ["Shadow6", "Shadow6Error", "feature_report", "run"]


class Shadow6Error(RuntimeError):
    """A local Shadow6 command failed or is unavailable."""


def _cli() -> str:
    value = os.environ.get("SHADOW6_CLI") or shutil.which("shadow6")
    if not value:
        raise Shadow6Error("installed shadow6 CLI not found")
    return value


def run(*args: str, input: str | None = None, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    """Run one fixed local Shadow6 CLI route and return its text result."""
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in args):
        raise ValueError("arguments must be non-empty strings without NUL")
    result = subprocess.run([_cli(), *args], input=input, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise Shadow6Error(result.stderr.strip() or f"shadow6 exited {result.returncode}")
    return result


def feature_report(core: str) -> dict:
    """Read and validate a locally installed Core feature report."""
    if core not in {"go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp"}:
        raise ValueError("unknown Core")
    result = run(core, "--feature-report")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Shadow6Error("Core returned invalid feature JSON") from exc
    if not isinstance(document, dict) or document.get("core") != f"shadow6-{core}":
        raise Shadow6Error("unexpected Core feature report")
    return document


class Shadow6:
    """Small facade bound to one installed Shadow6 CLI."""

    def __init__(self, cli: str | os.PathLike[str] | None = None):
        if cli is not None:
            self.cli = str(Path(cli).expanduser())
            if not Path(self.cli).is_file() or not os.access(self.cli, os.X_OK):
                raise Shadow6Error("configured Shadow6 CLI is not executable")
        else:
            self.cli = _cli()

    def call(self, *args: str, input: str | None = None, timeout: float = 30) -> str:
        old = os.environ.get("SHADOW6_CLI")
        os.environ["SHADOW6_CLI"] = self.cli
        try:
            return run(*args, input=input, timeout=timeout).stdout
        finally:
            if old is None: os.environ.pop("SHADOW6_CLI", None)
            else: os.environ["SHADOW6_CLI"] = old

    def json(self, *args: str, input: str | None = None, timeout: float = 30) -> dict:
        try: value = json.loads(self.call(*args, input=input, timeout=timeout))
        except json.JSONDecodeError as exc: raise Shadow6Error("invalid JSON response") from exc
        if not isinstance(value, dict): raise Shadow6Error("expected JSON object")
        return value

    def features(self) -> dict:
        return self.json("features")
