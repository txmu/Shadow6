"""Regressions for the installed-layout Shadow6 tree resolution.

Installed entry points live in ``<prefix>/bin`` (or in
``<prefix>/share/shadow6/modules``) while the tree they inspect is installed at
``<prefix>/share/shadow6/tree``.  Deriving that tree from the script location
must work for any prefix and for a staged ``DESTDIR`` installation, otherwise
the deployment doctor and the component catalogs report a missing tree.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import install_layout


ROOT = Path(__file__).resolve().parents[1]


class InstallLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shadow6-layout-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.addCleanup(lambda: os.environ.pop(install_layout.TREE_ENV, None))

    def make_tree(self, path):
        path.mkdir(parents=True, exist_ok=True)
        (path / install_layout.TREE_MARKER).write_text("all:\n", encoding="utf-8")
        return path

    def test_installed_tree_path_is_derived_from_the_prefix(self):
        for prefix in ("/usr/local", "/opt/shadow6", str(self.base / "staged/usr/local")):
            self.assertEqual(install_layout.installed_tree(prefix),
                             Path(prefix) / "share" / "shadow6" / "tree")

    def test_bin_entrypoint_resolves_the_sibling_tree(self):
        prefix = self.base / "usr/local"
        tree = self.make_tree(prefix / "share" / "shadow6" / "tree")
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        script = prefix / "bin" / "shadow6-security"
        script.write_text("", encoding="utf-8")
        self.assertEqual(install_layout.tree_root(script), tree.resolve())

    def test_shared_module_entrypoint_resolves_the_installed_tree(self):
        prefix = self.base / "opt/shadow6"
        tree = self.make_tree(prefix / "share" / "shadow6" / "tree")
        modules = prefix / "share" / "shadow6" / "modules"
        modules.mkdir(parents=True, exist_ok=True)
        script = modules / "shadow6_infra.py"
        script.write_text("", encoding="utf-8")
        self.assertEqual(install_layout.tree_root(script), tree.resolve())

    def test_source_checkout_wins_over_an_enclosing_prefix(self):
        # A checkout below an installation prefix must still operate on itself.
        prefix = self.base / "usr/local"
        self.make_tree(prefix / "share" / "shadow6" / "tree")
        checkout = self.make_tree(prefix / "src/Shadow6")
        script = checkout / "Security-Assistants" / "shadow6_security.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("", encoding="utf-8")
        self.assertEqual(install_layout.tree_root(script), checkout.resolve())

    def test_environment_override_takes_precedence(self):
        override = self.make_tree(self.base / "override")
        os.environ[install_layout.TREE_ENV] = str(override)
        self.assertEqual(install_layout.tree_root("/usr/local/bin/shadow6-security"), override.resolve())

    def test_unresolvable_layout_reports_the_configured_path(self):
        missing = self.base / "nothing" / "share" / "shadow6" / "tree"
        self.assertEqual(install_layout.resolve_tree(missing), missing.resolve())

    def test_every_console_entrypoint_uses_the_shared_resolver(self):
        # A hard-coded /usr/local fallback silently ignores PREFIX and DESTDIR.
        entrypoints = [
            "CLI/shadow6.py", "CLI/shadow6_vcore.py",
            "Security-Assistants/shadow6_security.py",
            "Infrastructure-Assistants/shadow6_infra.py",
            "Slot-System/shadow6_slots.py", "Extension-System/shadow6_extensions.py",
            "Control-Center/shadow6_control.py", "EasyBuild/shadow6_easybuild.py",
            "Public6/shadow6_public.py",
        ]
        for relative in entrypoints:
            with self.subTest(entrypoint=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("tree_root", text, relative)
                self.assertNotIn('"/usr/local/share/shadow6/tree"', text, relative)

    def test_installed_entrypoints_import_in_an_isolated_prefix(self):
        # Reproduce "make install" for just the shared modules and confirm an
        # installed entry point resolves the installed tree without the sources.
        prefix = self.base / "usr/local"
        tree = self.make_tree(prefix / "share" / "shadow6" / "tree")
        modules = prefix / "share" / "shadow6" / "modules"
        modules.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "Crosed" / "install_layout.py", modules / "install_layout.py")
        bin_dir = prefix / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        script = bin_dir / "probe.py"
        script.write_text(
            "import sys\nfrom pathlib import Path\n"
            "_HERE = Path(__file__).resolve().parent\n"
            "for _candidate in (_HERE, _HERE.parent / 'share' / 'shadow6' / 'modules'):\n"
            "    if (_candidate / 'install_layout.py').is_file():\n"
            "        sys.path.insert(0, str(_candidate))\n"
            "        break\n"
            "from install_layout import tree_root\n"
            "print(tree_root(__file__))\n",
            encoding="utf-8",
        )
        completed = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, check=True)
        self.assertEqual(completed.stdout.strip(), str(tree.resolve()))


if __name__ == "__main__":
    unittest.main()
