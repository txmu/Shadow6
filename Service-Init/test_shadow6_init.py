import plistlib
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

from shadow6_init import INIT_SYSTEMS, generate_init_script, rc_variable


class InitTests(unittest.TestCase):
    def test_rc_arguments_survive_both_parsing_layers(self):
        path = '/etc/a b\'"${HOME};$(false)\\config.json'
        for system in ("openrc", "rc.d"):
            script = generate_init_script(system, "shadow6-test.node", "/opt/a b/core", path)
            assignment = next(line for line in script.splitlines() if line.startswith("command_args="))
            value = shlex.split(assignment.split("=", 1)[1])[0]
            self.assertEqual(shlex.split(value)[-2:], ["--config", path])
            subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True, timeout=5)

    def test_systemd_expansion_is_context_specific(self):
        script = generate_init_script("systemd", "s6", "/opt/${BIN}%i", "/etc/${CONF}%n")
        self.assertIn('ExecStart="/opt/$${BIN}%%i" --config "/etc/$${CONF}%%n"', script)
        self.assertIn('ReadOnlyPaths="/etc/${CONF}%%n"', script)

    def test_rc_service_identifier_and_pid_tracking(self):
        script = generate_init_script("rc.d", "shadow6-a.b", "/bin/core", "/etc/core.json")
        self.assertEqual(rc_variable("shadow6-a.b"), "s6_shadow6_a_b")
        self.assertIn(": ${s6_shadow6_a_b_enable:=NO}", script)
        self.assertIn("command=/usr/sbin/daemon", script)
        self.assertIn("-p /var/run/shadow6-a.b.pid", script)

    def test_control_characters_rejected_for_all_formats(self):
        for system in INIT_SYSTEMS:
            for character in ("\x01", "\t", "\r", "\n", "\x7f", "\ud800"):
                with self.subTest(system=system, character=repr(character)), self.assertRaises(ValueError):
                    generate_init_script(system, "s6", "/bin/core", "/etc/" + character)

    def test_launchd_roundtrip_and_cli(self):
        path = '/etc/a&b<>" config'
        script = generate_init_script("launchd", "s6", "/bin/core", path)
        self.assertEqual(plistlib.loads(script.encode())["ProgramArguments"], ["/bin/core", "--config", path])
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("shadow6_init.py")),
                                 "--system", "runit", "--name", "s6", "--binary", "/bin/core", "--config", path],
                                capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(shlex.split(result.stdout.splitlines()[-1]), ["exec", "/bin/core", "--config", path])


if __name__ == "__main__":
    unittest.main()
