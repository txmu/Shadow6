#!/usr/bin/env python3
"""Guided, local-first Shadow6 build and installation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
for module_dir in (ROOT / "Package-Manager", ROOT / "Public6", Path(__file__).resolve().parent.parent / "share/shadow6/modules"):
    if module_dir.is_dir():
        sys.path.insert(0, str(module_dir))
from shadow6_pkg import keygen  # noqa: E402
from shadow6_public import suite_profile as public6_profile  # noqa: E402

REQUIRED_TOOLS = ("make", "go", "cargo", "rustc", "zip", "tar")
CORE_REPORT_KEYS = {
    "core", "version", "crosed_compiled", "crosed_max_level", "app_transport",
    "qubes_isolation", "utf8", "crosed_capabilities",
}


class EasyBuildError(RuntimeError):
    pass


def ask(question: str, default: bool = False) -> bool:
    suffix = " [y/N]: " if not default else " [Y/n]: "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return default
    if answer in {"y", "yes"}:
        return True
    if answer in {"n", "no"}:
        return False
    raise EasyBuildError("please answer yes or no")


def is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or "com.termux" in os.environ.get("HOME", "")


def preflight(termux: bool) -> None:
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if shutil.which("gcc") is None and shutil.which("clang") is None:
        missing.append("gcc-or-clang")
    if missing:
        raise EasyBuildError("missing required local tools (nothing was downloaded): " + ", ".join(missing))
    if not termux and not (ROOT / ".venv/bin/python").exists():
        raise EasyBuildError(".venv is missing; create it and install the pinned requirements before EasyBuild")


def termux_capabilities() -> dict[str, str]:
    rooted = shutil.which("su") is not None
    return {
        "core-go": "included",
        "core-rust": "included",
        "crosed-l5": "included",
        "application-layer": "included",
        "package-manager": "included",
        "control-center-mcp-lsp-openai": "included",
        "public6": "Public6 both-Core variants, compatibility negotiation, and Control Center MCP/OpenAI tools included",
        "plugins": "management included; execution requires Linux namespace support",
        "detector-live-capture": "available with Root/CAP_NET_RAW" if rooted else "offline analysis only without Root/CAP_NET_RAW",
        "guard-privileged-networking": "available when Root and kernel interfaces permit" if rooted else "requires Root",
        "service-init": "files included; Termux:Boot/service scripts are operator-configured",
    }


def run_fixed(arguments: list[str], environment: dict[str, str], dry_run: bool) -> None:
    print("+ " + " ".join(arguments))
    if not dry_run:
        subprocess.run(arguments, cwd=ROOT, env=environment, check=True)


def _secure_regular(path: Path, limit: int, *, private: bool = True) -> None:
    """Reject replaced, linked, writable, or oversized state files."""
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_uid != os.geteuid():
        raise EasyBuildError(f"state file must be an owner-controlled regular file: {path}")
    if (metadata.st_mode & 0o077 if private else metadata.st_mode & 0o022) or metadata.st_size > limit:
        raise EasyBuildError(f"state file permissions or size are unsafe: {path}")


def verify_core_reports(dry_run: bool) -> None:
    """Check both implementations and their preserved L5/Public6 variants."""
    if dry_run:
        return
    reports: dict[str, dict[str, Any]] = {}
    # EasyBuild validates every locally available native core, not only Go/Rust.
    for core in ("Zig", "Ada", "D", "Nim", "Cpp", "Pony", "Hare", "Carp", "Gleam", "Idris"):
        path = ROOT / f"Core-{core}/shadow6-{core.lower()}"
        if path.is_file():
            result = subprocess.run([str(path), "--feature-report"], cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0:
                raise EasyBuildError(f"feature report failed for {core}: {result.stderr.strip()}")
    for name, path in {
        "go": ROOT / "Core-Go/shadow6-go",
        "rust": ROOT / "Core-Rust/shadow6-rust",
        "go-crosed": ROOT / "Core-Go/shadow6-go-crosed",
        "rust-crosed": ROOT / "Core-Rust/shadow6-rust-crosed",
        "go-public6": ROOT / "Core-Go/shadow6-go-public6",
        "rust-public6": ROOT / "Core-Rust/shadow6-rust-public6",
    }.items():
        if not path.is_file():
            raise EasyBuildError(f"expected Core binary is missing: {path}")
        completed = subprocess.run(
            [str(path), "--feature-report"], cwd=ROOT, capture_output=True,
            text=True, timeout=10, check=False,
        )
        if completed.returncode != 0:
            raise EasyBuildError(f"feature report failed for {name}: {completed.stderr.strip()}")
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise EasyBuildError(f"feature report for {name} is not JSON") from exc
        if set(report) != CORE_REPORT_KEYS:
            raise EasyBuildError(f"feature report for {name} has an incompatible schema")
        reports[name] = report
    defaults = (reports["go"], reports["rust"])
    if any(
        report["crosed_max_level"] != 0
        or report["crosed_compiled"]
        or report["app_transport"]
        or report["qubes_isolation"]
        for report in defaults
    ):
        raise EasyBuildError("default cores are not least-privileged builds")
    comparable = ("version", "crosed_max_level", "app_transport", "qubes_isolation", "utf8", "crosed_capabilities")
    if any(defaults[0][field] != defaults[1][field] for field in comparable):
        raise EasyBuildError("Go and Rust default feature contracts differ")
    variants = (reports["go-crosed"], reports["rust-crosed"])
    if any(
        report["crosed_max_level"] != 5
        or not report["crosed_compiled"]
        or not report["app_transport"]
        or not report["qubes_isolation"]
        or not report["utf8"]
        for report in variants
    ):
        raise EasyBuildError("L5 cores do not expose the complete feature contract")
    if any(variants[0][field] != variants[1][field] for field in comparable):
        raise EasyBuildError("Go and Rust L5 feature contracts differ")
    public6 = (reports["go-public6"], reports["rust-public6"])
    if any(
        report["crosed_max_level"] != 5
        or not report["crosed_compiled"]
        or not report["app_transport"]
        or not report["qubes_isolation"]
        or not report["utf8"]
        for report in public6
    ):
        raise EasyBuildError("Public6 cores do not expose the complete optional feature contract")
    if any(public6[0][field] != public6[1][field] for field in comparable):
        raise EasyBuildError("Go and Rust Public6 feature contracts differ")


def verify_signed_plugins() -> None:
    """Verify every bundled plugin before claiming a complete installation."""
    module_path = ROOT / "Plugin-System" / "shadow6_plugins.py"
    namespace: dict[str, Any] = {"__file__": str(module_path), "__name__": "shadow6_plugins"}
    code = compile(module_path.read_text(encoding="utf-8"), str(module_path), "exec")
    exec(code, namespace)
    registry = namespace["PluginRegistry"]()
    plugin_error = namespace["PluginError"]
    for plugin_id in registry.discover():
        try:
            registry.load(plugin_id)
        except plugin_error as exc:
            raise EasyBuildError(f"bundled plugin signature verification failed: {plugin_id}: {exc}") from exc


def verify_package_trust(private_key: Path, trust: Path) -> None:
    """Ensure the local Ed25519 key and trust store are complete and loadable."""
    _secure_regular(private_key, 16_384)
    _secure_regular(trust, 1_048_576, private=False)
    try:
        key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("private key is not Ed25519")
        trust_document = json.loads(trust.read_text(encoding="utf-8"))
        signers = trust_document.get("signers")
        if trust_document.get("schema_version") != 1 or not isinstance(signers, dict) or not signers:
            raise ValueError("trust store schema is invalid")
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        if public not in signers.values():
            raise ValueError("generated signing key is absent from the trust store")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EasyBuildError(f"package signing material failed verification: {exc}") from exc


def generate_identities(path: Path) -> None:
    if path.exists():
        _secure_regular(path, 65_536)
        return
    result = {"schema_version": 1, "identities": {}}
    for name in ("broker", "agent", "client"):
        key = Ed25519PrivateKey.generate()
        result["identities"][name] = {
            "private_key": key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
            "public_key": key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    _secure_regular(path, 65_536)


def write_profile(path: Path, qubes: bool, compliance: bool, prefix: str) -> None:
    document = {
        "schema_version": 1,
        "features": "all",
        "crosed_level": 5,
        "application_transport": True,
        "plugin_policy": "all bundled signed plugins available; runtime capability checks remain enforced",
        "qubes_style_isolation": qubes,
        "compliance_selected": compliance,
        "compliance_applied": False,
        "prefix": prefix,
        "public6": public6_profile(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    _secure_regular(path, 16_384)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and install every locally available Shadow6 feature")
    parser.add_argument("--prefix")
    parser.add_argument("--destdir", default="")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".config/shadow6")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--enable-qubes-isolation", action="store_true")
    parser.add_argument("--enable-compliance", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-tests", action="store_true", help="explicitly skip tests for development only")
    parser.add_argument("--termux", action="store_true", help="use the Termux userspace profile (auto-detected when possible)")
    args = parser.parse_args()
    termux = args.termux or is_termux()
    prefix = args.prefix or (os.environ.get("PREFIX", "") if termux else str(Path.home() / ".local"))
    if not prefix or not Path(prefix).is_absolute():
        raise EasyBuildError("installation prefix must be an absolute path")
    qubes = args.enable_qubes_isolation
    compliance = args.enable_compliance
    if not args.non_interactive:
        if not args.enable_qubes_isolation:
            qubes = ask("Enable Qubes-inspired application domain policy? (This does not replace Qubes OS isolation)", False)
        if not args.enable_compliance:
            compliance = ask("Select the jurisdiction-specific compliance step for later manual execution?", False)
    preflight(termux)
    environment = dict(os.environ)
    environment["GOCACHE"] = str(ROOT / ".tmp/go-build")
    environment["PYTHON"] = sys.executable if termux else str(ROOT / ".venv/bin/python")
    if termux:
        print("Termux capability profile:")
        for component, status in termux_capabilities().items():
            print(f"  {component}: {status}")
    configure = [str(ROOT / "configure"), "--enable-all", "--crosed-level=0", "--disable-app-transport", "--disable-qubes-isolation"]
    run_fixed(configure, environment, args.dry_run)
    run_fixed(["make", "build"], environment, args.dry_run)
    # Always preserve the canonical full L5 artifact. The interactive Qubes
    # choice controls the generated runtime policy profile, not compilation.
    run_fixed(["make", "crosed-variants", "CROSED_VARIANT_QUBES=1"], environment, args.dry_run)
    run_fixed(["make", "public6-variants"], environment, args.dry_run)
    verify_core_reports(args.dry_run)
    if not args.dry_run:
        verify_signed_plugins()
    if not args.skip_tests:
        run_fixed(["make", "test"], environment, args.dry_run)
        run_fixed(["make", "check"], environment, args.dry_run)
        run_fixed(["make", "audit"], environment, args.dry_run)
    install = ["make", "install", f"PREFIX={prefix}"]
    if args.destdir:
        install.append(f"DESTDIR={args.destdir}")
    run_fixed(install, environment, args.dry_run)
    if not args.dry_run:
        binary_dir = Path(args.destdir + prefix) / "bin"
        binary_dir.mkdir(parents=True, exist_ok=True)
        for core in ("go", "rust"):
            shutil.copy2(ROOT / f"Core-{core.capitalize()}/shadow6-{core}-crosed", binary_dir / f"shadow6-{core}-crosed")
            shutil.copy2(ROOT / f"Core-{core.capitalize()}/shadow6-{core}-public6", binary_dir / f"shadow6-{core}-public6")
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.state_dir.chmod(0o700)
        generate_identities(args.state_dir / "identities.json")
        private_key, trust = args.state_dir / "package-signing.pem", args.state_dir / "package-trust.json"
        if not private_key.exists() and not trust.exists():
            keygen(private_key, trust, "local-owner")
        elif not private_key.exists() or not trust.exists():
            raise EasyBuildError("package signing key/trust store is incomplete; refusing to overwrite it")
        verify_package_trust(private_key, trust)
        write_profile(args.state_dir / "easybuild-profile.json", qubes, compliance, prefix)
        if termux:
            write_profile_path = args.state_dir / "termux-capabilities.json"
            write_profile_path.write_text(json.dumps({"schema_version": 1, "components": termux_capabilities()}, indent=2) + "\n", encoding="utf-8")
            write_profile_path.chmod(0o600)
    print("EasyBuild complete. Full L5 and Public6 cores are installed with explicit suffixes; least-privileged core names remain the defaults.")
    if compliance:
        print("Compliance was selected but not applied. Review and explicitly run 中国内地用户必须执行.sh if appropriate.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EasyBuildError, OSError, subprocess.CalledProcessError) as exc:
        print(f"shadow6-easybuild: {exc}", file=sys.stderr)
        raise SystemExit(2)
