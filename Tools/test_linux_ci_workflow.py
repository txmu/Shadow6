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
