#!/usr/bin/env python3
"""Deterministic offline integrity and binary-hardening checks for Shadow6."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "Crosed"))
from feature_contract import CORE_PATHS, validate_feature_report


class Audit:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def pass_(self, message: str) -> None:
        self.passed += 1
        print(f"[PASS] {message}")

    def fail(self, message: str) -> None:
        self.failed += 1
        print(f"[FAIL] {message}")

    def skip(self, message: str) -> None:
        self.skipped += 1
        print(f"[SKIP] {message}")


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=30, check=False)


def check_elf(audit: Audit, relative: str, *, static_go: bool = False) -> None:
    path = ROOT / relative
    if not path.is_file():
        audit.fail(f"{relative}: binary is missing")
        return
    header = run("readelf", "-W", "-h", str(path))
    programs = run("readelf", "-W", "-l", str(path))
    dynamic = run("readelf", "-W", "-d", str(path))
    if any(result.returncode != 0 for result in (header, programs, dynamic)):
        audit.fail(f"{relative}: readelf could not inspect the binary")
        return
    if re.search(r"Type:\s+DYN", header.stdout):
        audit.pass_(f"{relative}: position-independent executable")
    else:
        audit.fail(f"{relative}: PIE is not enabled")
    stack_line = next((line for line in programs.stdout.splitlines() if "GNU_STACK" in line), "")
    if stack_line and "E" not in stack_line.split()[-1]:
        audit.pass_(f"{relative}: non-executable stack")
    else:
        audit.fail(f"{relative}: executable or unverified stack")
    if "GNU_RELRO" in programs.stdout and ("BIND_NOW" in dynamic.stdout or static_go):
        audit.pass_(f"{relative}: relocation hardening present")
    else:
        audit.fail(f"{relative}: full RELRO could not be verified")
    if static_go:
        linked = run("ldd", str(path))
        output = f"{linked.stdout}\n{linked.stderr}".lower()
        if "statically linked" in output or "not a dynamic executable" in output:
            audit.pass_(f"{relative}: no shared-library dependency")
        else:
            audit.fail(f"{relative}: unexpected dynamic dependency: {output.strip()}")
        strings = run("strings", str(path))
        if str(ROOT) not in strings.stdout:
            audit.pass_(f"{relative}: local build path removed")
        else:
            audit.fail(f"{relative}: local build path is embedded")


def check_gleam_invariants(audit: Audit) -> None:
    build = (ROOT / "Core-Gleam" / "compile.sh").read_text(encoding="utf-8")
    forbidden = (ROOT / "Core-Gleam" / "shadow6-gleam").read_bytes()
    if "--disable-jit" in build and "-static-pie" in build:
        audit.pass_("Core-Gleam: static ERTS build explicitly disables JIT")
    else:
        audit.fail("Core-Gleam: no-JIT static ERTS flags are incomplete")
    if all(marker not in forbidden for marker in (b"BeamAsm", b"beam_jit", b"burrito")):
        audit.pass_("Core-Gleam: final ELF contains no JIT or extractor marker")
    else:
        audit.fail("Core-Gleam: final ELF contains a JIT or extractor marker")


def source_files() -> list[Path]:
    roots = [ROOT / name for name in ("Core-Go", "Core-Rust", "Core-Gleam", "Gate", "CLI", "Migration", "I18n", "Online-Repository", "C11Relay", "Guard", "Service-Init", "Auto-Orchestrator", "Detector", "Plugin-System", "plugins", "Package-Manager", "EasyBuild", "Android", "Crosed", "Application-Layer", "Security-Assistants", "Infrastructure-Assistants", "Slot-System", "Control-Center", "Public6", "integration")]
    roots.append(ROOT / "Core-Zig")
    suffixes = {".go", ".rs", ".erl", ".gleam", ".zig", ".c", ".h", ".py", ".sh", ".kt", ".kts"}
    result: list[Path] = [ROOT / "setup_test.sh", ROOT / "configure"]
    for base in roots:
        for directory, names, files in os.walk(base):
            names[:] = [name for name in names if name not in {"target", "__pycache__", ".venv", ".zig-cache", "zig-out"}]
            for filename in files:
                path = Path(directory) / filename
                if path.suffix in suffixes:
                    result.append(path)
    return result


def check_sources(audit: Audit) -> None:
    files = source_files()
    required = [
        ROOT / "Core-Go" / "main.go",
        ROOT / "Core-Rust" / "src" / "main.rs",
        ROOT / "Core-Gleam" / "src" / "shadow6_gleam.gleam",
        ROOT / "Core-Gleam" / "c_src" / "main.c",
        ROOT / "C11Relay" / "c11relay.c",
        ROOT / "Guard" / "main.go",
        ROOT / "Gate" / "main.go",
        ROOT / "CLI" / "shadow6.py",
        ROOT / "Migration" / "shadow6_migrate.py",
        ROOT / "Online-Repository" / "shadow6_repo.py",
        ROOT / "Auto-Orchestrator" / "shadow6_auto.py",
        ROOT / "Service-Init" / "shadow6_init.py",
        ROOT / "Detector" / "detector_core.py",
        ROOT / "Plugin-System" / "shadow6_plugins.py",
        ROOT / "Crosed" / "crosedctl.py",
        ROOT / "Application-Layer" / "shadow_protocols.py",
        ROOT / "Security-Assistants" / "shadow6_security.py",
        ROOT / "Infrastructure-Assistants" / "shadow6_infra.py",
        ROOT / "Slot-System" / "shadow6_slots.py",
        ROOT / "Control-Center" / "shadow6_control.py",
        ROOT / "Package-Manager" / "shadow6_pkg.py",
        ROOT / "EasyBuild" / "shadow6_easybuild.py",
        ROOT / "Android" / "app" / "src" / "main" / "java" / "org" / "shadow6" / "android" / "MainActivity.kt",
        ROOT / "Public6" / "shadow6_public.py",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        audit.fail(f"required sources missing: {', '.join(missing)}")
    else:
        audit.pass_("all component entry points are present")

    checks = {
        "TLS verification bypass": re.compile(r"InsecureSkipVerify\s*:\s*true"),
        "shell-based subprocess execution": re.compile(r"(?:shell\s*=\s*True|Command\s*\(\s*[\"'](?:sh|bash)[\"']\s*,\s*[\"']-c)"),
        "process-wide forced termination": re.compile(r"pkill\s+-9"),
    }
    combined = []
    for path in files:
        try:
            combined.append((path, path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            audit.fail(f"cannot read {path.relative_to(ROOT)}: {exc}")
    for label, pattern in checks.items():
        matches = [str(path.relative_to(ROOT)) for path, text in combined if pattern.search(text)]
        if matches:
            audit.fail(f"{label} found in: {', '.join(matches)}")
        else:
            audit.pass_(f"no {label}")

    scripts = [ROOT / name for name in ("configure", "setup_test.sh")]
    scripts += [ROOT / component / "compile.sh" for component in ("Core-Go", "Core-Rust", "C11Relay", "Guard")]
    unsafe = [str(path.relative_to(ROOT)) for path in scripts if not path.is_file() or not os.access(path, os.X_OK)]
    if unsafe:
        audit.fail(f"required scripts are missing or not executable: {', '.join(unsafe)}")
    else:
        audit.pass_("required build and verification scripts are executable")


def check_plugins(audit: Audit) -> None:
    result = run(sys.executable, "Plugin-System/shadow6_plugins.py", "list")
    expected = {"maze-runner", "number-guess", "rock-paper-scissors"}
    found = {line.split("\t", 1)[0] for line in result.stdout.splitlines() if "\t" in line}
    if result.returncode == 0 and found == expected and "INVALID" not in result.stdout:
        audit.pass_("all bundled plugins have valid signatures and code digests")
    else:
        audit.fail(f"bundled plugin verification failed: {(result.stderr or result.stdout).strip()}")


def check_core_feature_contract(audit: Audit) -> None:
    # Validate each family independently; parity is a Go/Rust requirement,
    # not a requirement to pretend that every transport has identical features.
    for core, relative in CORE_PATHS.items():
        for suffix in ("", "-crosed", "-public6"):
            path = ROOT / (relative + suffix)
            if not path.exists() and not path.is_symlink():
                if not suffix and core not in {"shadow6-go", "shadow6-rust"}:
                    audit.skip(f"{relative}: optional Core not built")
                continue
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
                    raise ValueError("unsafe Core binary")
                completed = run(str(path), "--feature-report")
                if completed.returncode or len(completed.stdout) > 16384:
                    raise ValueError("feature report command failed or exceeded bound")
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result: raise ValueError("duplicate field")
                        result[key] = value
                    return result
                report = json.loads(completed.stdout, object_pairs_hook=unique)
                validate_feature_report(report, core)
                if not suffix and (report["crosed_max_level"] or report["app_transport"] or report["qubes_isolation"]):
                    raise ValueError("default Core must be least privileged")
                audit.pass_(f"{relative}{suffix}: valid feature contract")
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                audit.fail(f"{relative}{suffix}: {exc}")
    reports = []
    for relative in ("Core-Go/shadow6-go", "Core-Rust/shadow6-rust"):
        result = run(str(ROOT / relative), "--feature-report")
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            audit.fail(f"{relative}: invalid feature report")
            return
        required = {
            "core", "version", "crosed_compiled", "crosed_max_level", "app_transport",
            "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8", "crosed_capabilities",
        }
        if result.returncode != 0 or set(report) != required:
            audit.fail(f"{relative}: incomplete feature contract")
            return
        reports.append(report)
    comparable = ("version", "crosed_max_level", "app_transport", "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8", "crosed_capabilities")
    if all(reports[0][field] == reports[1][field] for field in comparable):
        audit.pass_("Core-Go and Core-Rust expose the same Crosed/application/isolation contract")
    else:
        audit.fail("Core-Go and Core-Rust feature contracts differ")

    variants = (ROOT / "Core-Go/shadow6-go-crosed", ROOT / "Core-Rust/shadow6-rust-crosed")
    if all(path.is_file() for path in variants):
        variant_reports = []
        for path in variants:
            result = run(str(path), "--feature-report")
            try:
                variant_reports.append(json.loads(result.stdout))
            except json.JSONDecodeError:
                audit.fail(f"{path.relative_to(ROOT)}: invalid Crosed variant report")
                return
        if all(
            report.get("crosed_max_level") == 5
            and report.get("app_transport") is True
            and report.get("qubes_isolation") is True
            for report in variant_reports
        ) and all(variant_reports[0][field] == variant_reports[1][field] for field in comparable):
            audit.pass_("L5 Crosed Core variants expose matching full feature contracts")
        else:
            audit.fail("L5 Crosed Core variant contracts are incomplete or inconsistent")

    public6_variants = (ROOT / "Core-Go/shadow6-go-public6", ROOT / "Core-Rust/shadow6-rust-public6")
    if all(path.is_file() for path in public6_variants):
        public6_reports = []
        for path in public6_variants:
            result = run(str(path), "--feature-report")
            try:
                public6_reports.append(json.loads(result.stdout))
            except json.JSONDecodeError:
                audit.fail(f"{path.relative_to(ROOT)}: invalid Public6 variant report")
                return
        if all(
            report.get("crosed_max_level") == 5
            and report.get("app_transport") is True
            and report.get("qubes_isolation") is True
            and report.get("utf8") is True
            for report in public6_reports
        ) and all(public6_reports[0][field] == public6_reports[1][field] for field in comparable):
            audit.pass_("Public6 Core variants expose matching full feature contracts")
        else:
            audit.fail("Public6 Core variant contracts are incomplete or inconsistent")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run non-networked Shadow6 source and binary checks")
    parser.add_argument("--source-only", action="store_true", help="skip checks that require built binaries")
    args = parser.parse_args()
    audit = Audit()
    check_sources(audit)
    check_plugins(audit)
    if not args.source_only:
        check_core_feature_contract(audit)
    if args.source_only:
        audit.skip("binary hardening checks disabled by --source-only")
    else:
        check_elf(audit, "Core-Go/shadow6-go", static_go=True)
        check_elf(audit, "Core-Rust/shadow6-rust")
        if (ROOT / "Core-Gleam/shadow6-gleam").is_file():
            check_elf(audit, "Core-Gleam/shadow6-gleam", static_go=True)
            check_gleam_invariants(audit)
        if (ROOT / "Core-Zig/shadow6-zig").is_file():
            check_elf(audit, "Core-Zig/shadow6-zig")
        check_elf(audit, "C11Relay/bridge_relay")
        check_elf(audit, "Guard/shadow6-guard", static_go=True)
        check_elf(audit, "Gate/shadow6-gate", static_go=True)
        if (ROOT / "Core-Go/shadow6-go-crosed").is_file():
            check_elf(audit, "Core-Go/shadow6-go-crosed", static_go=True)
        if (ROOT / "Core-Rust/shadow6-rust-crosed").is_file():
            check_elf(audit, "Core-Rust/shadow6-rust-crosed")
        if (ROOT / "Core-Gleam/shadow6-gleam-crosed").is_file():
            check_elf(audit, "Core-Gleam/shadow6-gleam-crosed", static_go=True)
        if (ROOT / "Core-Go/shadow6-go-public6").is_file():
            check_elf(audit, "Core-Go/shadow6-go-public6", static_go=True)
        if (ROOT / "Core-Rust/shadow6-rust-public6").is_file():
            check_elf(audit, "Core-Rust/shadow6-rust-public6")
    print(f"Summary: {audit.passed} passed, {audit.failed} failed, {audit.skipped} skipped")
    return 1 if audit.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
