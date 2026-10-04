"""Regression guards for the Linux CI job that serves "make test".

The Linux job downloads the Idris runtime built by another job and then runs
"make test", which executes the signed ``audit`` runbook.  That runbook pins a
fixed, minimal PATH, so any interpreter it must resolve has to be reachable
from that exact PATH.  These checks keep the Chez Scheme ABI binding explicit
instead of silently depending on the runner's ambient PATH ordering.
"""
import ast
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "multiplatform.yml"
INFRA = ROOT / "Infrastructure-Assistants" / "shadow6_infra.py"


def safe_execution_path() -> str:
    """Evaluate the assistant's sealed PATH without importing its dependencies."""
    module = ast.parse(INFRA.read_text(encoding="utf-8"))
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "SAFE_EXECUTION_PATH"
            for target in node.targets
        ):
            return eval(compile(ast.Expression(node.value), "<SAFE_EXECUTION_PATH>", "eval"),
                        {"os": os, "Path": Path})
    raise AssertionError("shadow6_infra.py no longer defines SAFE_EXECUTION_PATH")


SAFE_EXECUTION_PATH = safe_execution_path()


def linux_job():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["linux"]


def steps():
    return linux_job()["steps"]


def step_script(name_fragment):
    for step in steps():
        if name_fragment.lower() in (step.get("name") or "").lower():
            return step.get("run") or ""
    raise AssertionError(f"no linux step matching {name_fragment!r}")


def apt_install_packages(script: str) -> set[str]:
    """Package arguments of every ``apt-get install`` in a step, comments stripped."""
    commands: list[str] = []
    pending = ""
    for line in script.splitlines():
        stripped = line.strip()
        if not pending and stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        pending += " " + (stripped[:-1] if continued else stripped)
        if not continued:
            commands.append(pending)
            pending = ""
    if pending:
        commands.append(pending)
    packages: set[str] = set()
    for command in commands:
        match = re.search(r"\bapt-get\s+install\b(.*)", command)
        if match:
            packages.update(token for token in match.group(1).split()
                            if token and not token.startswith("-"))
    return packages


def audit_path_literal(script: str) -> str:
    match = re.search(r"^[ \t]*audit_path=(\S+)[ \t]*$", script, re.M)
    if match is None:
        raise AssertionError("restore step must declare the audit path it reproduces")
    return match.group(1)


class LinuxIdrisRuntimeTests(unittest.TestCase):
    def test_windows_iperf_setup_installs_its_cache_cleanup_command(self):
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        setup = next(step for step in workflow['jobs']['iperf3-matrix']['steps']
                     if step.get('name') == 'Install MSYS2 iperf3 on Windows')
        # The pinned action's cache save invokes paccache, provided by
        # pacman-contrib. Minimal MSYS archives do not guarantee it is present.
        self.assertIn('pacman-contrib', setup['with']['install'].split())
        self.assertIn('iperf3', setup['with']['install'].split())

    def test_public6_is_rebuilt_before_tests_and_audit(self):
        # Public6 executables are tracked release products. Checkout alone can
        # leave their feature contract older than the sources under test.
        scripts = [step.get("run", "") for step in steps()]
        rebuild = scripts.index("make public6-variants")
        self.assertLess(rebuild, scripts.index("make test"))
        self.assertLess(rebuild, scripts.index("make audit"))
        recipe = (ROOT / "Makefile").read_text().split("public6-variants:\n", 1)[1].split("\npublic6-contract:", 1)[0]
        self.assertIn("CROSED_LEVEL=5 APP_TRANSPORT=1 QUBES_ISOLATION=1", recipe)
        for family in ("Go", "Rust"):
            self.assertIn(f"Core-{family}/shadow6-{family.lower()}-public6", recipe)
        self.assertIn("CROSED_LEVEL=0 APP_TRANSPORT=0 QUBES_ISOLATION=0", recipe.split("-public6", 2)[-1])

    def test_runtime_restore_preserves_all_tracked_idris_sources(self):
        restore = step_script("Restore executable modes")
        # Execute the actual restoration block, before host interpreter setup.
        block = restore.split("chmod 0755 Core-Gleam/", 1)[0]
        tracked = subprocess.check_output(
            ["git", "ls-files", "Core-Idris"], cwd=ROOT, text=True).splitlines()
        with tempfile.TemporaryDirectory(prefix="shadow6-ci-restore-") as directory:
            stage = Path(directory)
            for name in tracked:
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            subprocess.run(["git", "init", "-q"], cwd=stage, check=True)
            subprocess.run(["git", "add", "Core-Idris"], cwd=stage, check=True)
            artifacts = stage / "runner/idris-artifact"
            artifacts.mkdir(parents=True)
            product = stage / "shadow6-idris"
            product.write_bytes(b"compiled runtime fixture\n")
            with tarfile.open(artifacts / "core-idris-runtime.tar.gz", "w:gz") as archive:
                archive.add(product, arcname="shadow6-idris")
            subprocess.run(["bash", "-eu"], input=block, text=True, cwd=stage,
                           env=dict(os.environ, RUNNER_TEMP=str(stage / "runner")),
                           check=True, capture_output=True)
            for name in tracked:
                self.assertEqual((stage / name).read_bytes(), (ROOT / name).read_bytes(), name)
            self.assertEqual((stage / "Core-Idris/shadow6-idris").read_bytes(), product.read_bytes())

    def test_distro_chezscheme_never_shadows_the_matched_interpreter(self):
        # apt's chezscheme lands in /usr/bin, which precedes /usr/local/bin in
        # SAFE_EXECUTION_PATH.  Installing it makes the audit resolve an
        # interpreter whose fasl ABI does not match the downloaded image.
        install = step_script("Install Linux native build dependencies")
        self.assertTrue(apt_install_packages(install), install)
        self.assertNotIn("chezscheme", apt_install_packages(install), install)

    def test_shim_is_built_from_homebrew_and_pins_the_audit_path(self):
        restore = step_script("Restore executable modes")
        self.assertIn("brew --prefix chezscheme", restore)
        self.assertIn("/usr/local/bin/chezscheme", restore)
        self.assertRegex(restore, r"command -v chezscheme.*=\s*/usr/local/bin/chezscheme")

    def test_feature_reports_run_under_the_audit_path(self):
        restore = step_script("Restore executable modes")
        # The smoke test must reproduce the runbook's sealed PATH exactly;
        # otherwise it can pass here and still fail inside "make test".
        self.assertEqual(audit_path_literal(restore), SAFE_EXECUTION_PATH, restore)
        for binary in ("shadow6-idris", "shadow6-idris-crosed"):
            self.assertRegex(
                restore,
                r'PATH="\$audit_path"\s+\./' + re.escape(binary) + r"\s+--feature-report",
                restore,
            )

    def test_audit_path_constant_is_absolute_and_ordered(self):
        entries = SAFE_EXECUTION_PATH.split(os.pathsep)
        self.assertTrue(all(entry.startswith("/") for entry in entries), entries)
        # /usr/bin still precedes /usr/local/bin, which is exactly why the
        # Homebrew shim has to live in a directory the runbook reaches first.
        self.assertLess(entries.index("/usr/bin"), entries.index("/usr/local/bin"))


if __name__ == "__main__":
    unittest.main()
