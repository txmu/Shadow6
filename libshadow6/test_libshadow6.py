from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import libshadow6


class LibShadow6Tests(unittest.TestCase):
    def test_run_uses_argument_vector_and_reports_failure(self):
        completed = subprocess.CompletedProcess(["shadow6", "features"], 0, "{}\n", "")
        with patch.object(libshadow6, "_cli", return_value="/opt/shadow6") as find_cli, \
             patch.object(libshadow6.subprocess, "run", return_value=completed) as run:
            self.assertEqual(libshadow6.run("features", timeout=4), completed)
        find_cli.assert_called_once_with()
        self.assertEqual(run.call_args.args[0], ["/opt/shadow6", "features"])
        self.assertEqual(run.call_args.kwargs["timeout"], 4)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

        failed = subprocess.CompletedProcess(["shadow6"], 3, "", "denied\n")
        with patch.object(libshadow6, "_cli", return_value="shadow6"), \
             patch.object(libshadow6.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(libshadow6.Shadow6Error, "denied"):
                libshadow6.run("status")

    def test_arguments_reject_empty_nul_and_non_strings(self):
        for value in ("", "bad\x00arg", 7):
            with self.subTest(value=value), self.assertRaises(ValueError):
                libshadow6.run(value)  # type: ignore[arg-type]

    def test_facade_json_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "shadow6"
            cli.write_text("#!/bin/sh\nprintf '%s' '{\"level\":0}'\n", encoding="utf-8")
            cli.chmod(0o700)
            client = libshadow6.Shadow6(cli)
            self.assertEqual(client.json("features"), {"level": 0})

            cli.write_text("#!/bin/sh\nprintf '[]'\n", encoding="utf-8")
            with self.assertRaisesRegex(libshadow6.Shadow6Error, "expected JSON object"):
                client.json("features")

    def test_features_uses_aggregate_cli_contract_and_component_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "shadow6"
            cli.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "name = sys.argv[sys.argv.index('--component') + 1] if '--component' in sys.argv else 'go'\n"
                "print(json.dumps({'schema':'shadow6.features.v1','components':[{'core':'shadow6-' + name}]}))\n",
                encoding="utf-8")
            cli.chmod(0o700)
            client = libshadow6.Shadow6(cli)
            self.assertEqual(client.features(), {"schema": "shadow6.features.v1", "components": [{"core": "shadow6-go"}]})
            self.assertEqual(client.features("pony"), {"core": "shadow6-pony"})

    def test_calls_do_not_mutate_global_cli_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            for cli in (first, second):
                cli.write_text("#!/bin/sh\nprintf '%s' \"$0\"\n", encoding="utf-8")
                cli.chmod(0o700)
            a, b = libshadow6.Shadow6(first), libshadow6.Shadow6(second)
            self.assertEqual(a.call("status"), str(first))
            self.assertEqual(b.call("status"), str(second))

    def test_invalid_cli_path_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(libshadow6.Shadow6Error):
                libshadow6.Shadow6(Path(directory) / "missing")


if __name__ == "__main__":
    unittest.main()
