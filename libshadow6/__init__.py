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

__all__ = ["Shadow6", "Shadow6Error", "run"]


class Shadow6Error(RuntimeError):
    """A local Shadow6 command failed or is unavailable."""


def _cli() -> str:
    value = os.environ.get("SHADOW6_CLI") or shutil.which("shadow6")
    if not value:
        raise Shadow6Error("installed shadow6 CLI not found")
    return value


def run(*args: str, input: str | None = None, timeout: float = 30,
        cli: str | os.PathLike[str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run one fixed local Shadow6 CLI route and return its text result."""
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in args):
        raise ValueError("arguments must be non-empty strings without NUL")
    executable = str(cli) if cli is not None else _cli()
    result = subprocess.run([executable, *args], input=input, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise Shadow6Error(result.stderr.strip() or f"shadow6 exited {result.returncode}")
    return result


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
        return run(*args, input=input, timeout=timeout, cli=self.cli).stdout

    def json(self, *args: str, input: str | None = None, timeout: float = 30) -> dict:
        try: value = json.loads(self.call(*args, input=input, timeout=timeout))
        except json.JSONDecodeError as exc: raise Shadow6Error("invalid JSON response") from exc
        if not isinstance(value, dict): raise Shadow6Error("expected JSON object")
        return value

    def features(self, component: str | None = None) -> dict:
        args = ("features", "--format", "json")
        if component is not None:
            if not isinstance(component, str) or not component:
                raise ValueError("component must be a non-empty string")
            args += ("--component", component)
        result = self.json(*args)
        if component is None:
            return result
        reports = result.get("components")
        if not isinstance(reports, list) or len(reports) != 1 or not isinstance(reports[0], dict):
            raise Shadow6Error("invalid aggregate feature response")
        return reports[0]
