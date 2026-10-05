import plistlib
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

from shadow6_init import INIT_SYSTEMS, generate_init_script, rc_variable


class InitTests(unittest.TestCase):
    def test_all_target_definitions_keep_runner_and_config(self):
        for system in sorted(INIT_SYSTEMS):
            with self.subTest(system=system):
                script = generate_init_script(system, 'shadow6-ci', '/opt/shadow6-runner',
                                              '/var/lib/shadow6/plan.json', fd_ceiling=1024)
                self.assertIn('/opt/shadow6-runner', script)
                self.assertIn('/var/lib/shadow6/plan.json', script)

    def test_paths_are_validated_for_target_platform(self):
        import json
        binary, config = r'C:\Shadow6\runner.exe', r'C:\Shadow6\plan.json'
        definition = json.loads(generate_init_script('windows-service', 's6', binary, config))
        self.assertEqual(definition['binary'], binary)
        self.assertEqual(definition['config'], config)
        for system in INIT_SYSTEMS:
            for path in ('relative/runner', r'C:relative\runner'):
                with self.subTest(system=system, path=path), self.assertRaises(ValueError):
                    generate_init_script(system, 's6', path, '/etc/config')
        with self.assertRaises(ValueError):
            generate_init_script('systemd', 's6', binary, config)

    def test_supervisor_capabilities_report_observed_availability(self):
        from Deployment.supervisor_contract import capabilities
        strong = capabilities("strong")
        self.assertEqual(strong["backend"], "linux-pidfd")
        self.assertIn(strong["availability"], {"available", "unavailable"})
        self.assertEqual(strong["pidReuseProtection"], strong["availability"])
        native = capabilities("systemd")
        self.assertIn(native["availability"], {"partial", "unavailable"})
        self.assertEqual(native["activation"], "explicit-operator-action")
        self.assertEqual(native["definitionGeneration"], "available")
        self.assertEqual(native["systemOperationInterface"], "available")
        self.assertEqual(native["systemOperationProvider"], "optional-external")
        self.assertEqual(native["nativeLifecycleParity"], "unverified")

    def test_external_system_operation_is_fixed_and_lock_bound(self):
        from Deployment.system_operations import operation_request, validate_request, validate_receipt
        request = operation_request(backend="launchd", operation="activate",
            service="home/nas", plan_path="/private/runtime.json",
            lock_digest="sha256:" + "a" * 64, now=1000, ttl=60)
        self.assertEqual(validate_request(request, now=1020), request)
        self.assertNotIn("argv", request)
        self.assertEqual(request["serviceLabel"], "shadow6-" + __import__("hashlib").sha256(
            b"home/nas").hexdigest()[:24])
        receipt = {"schema":"shadow6.system-operation-receipt.v1",
            "requestId":request["requestId"], "operation":"activate",
            "lockDigest":request["lockDigest"], "result":"completed",
            "observedAt":1020, "readiness":"unknown"}
        self.assertEqual(validate_receipt(receipt, request, now=1020), receipt)
        with self.assertRaisesRegex(ValueError, "separately verified"):
            validate_receipt({**receipt, "readiness":"ready"}, request, now=1020)
        with self.assertRaisesRegex(ValueError, "unsupported system operation"):
            operation_request(backend="launchd", operation="run-arbitrary-command",
                service="home/nas", plan_path="/private/runtime.json",
                lock_digest=request["lockDigest"], now=1000)

    def test_rc_arguments_survive_both_parsing_layers(self):
        path = '/etc/a b\'"${HOME};$(false)\\config.json'
        for system in ("openrc", "rc.d"):
            script = generate_init_script(system, "shadow6-test.node", "/opt/a b/core", path)
            assignment = next(line for line in script.splitlines() if line.startswith("command_args="))
            value = shlex.split(assignment.split("=", 1)[1])[0]
            self.assertEqual(shlex.split(value)[-2:], ["--config", path])

    @unittest.skipUnless(Path('/bin/sh').is_file(), 'POSIX shell syntax check requires /bin/sh')
    def test_rc_shell_syntax(self):
        for system in ('openrc', 'rc.d'):
            script = generate_init_script(system, 'shadow6-test.node', '/opt/a b/core',
                                          '/etc/a b config.json')
            subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True, timeout=5)

    def test_systemd_expansion_is_context_specific(self):
        script = generate_init_script("systemd", "s6", "/opt/${BIN}%i", "/etc/${CONF}%n")
        self.assertIn('ExecStart="/opt/$${BIN}%%i" --config "/etc/$${CONF}%%n"', script)
        self.assertIn('ReadOnlyPaths="/etc/${CONF}%%n"', script)

    def test_named_service_keeps_locked_host_fd_ceiling(self):
        for system, expected in (("systemd", "LimitNOFILE=1024"),
                                 ("procd", 'nofile="1024 1024"')):
            script = generate_init_script(system, "s6", "/opt/shadow6-service-runner",
                                          "/run/shadow6/plan.json", fd_ceiling=1024)
            self.assertIn(expected, script)
        for value in (0, -1, True, 1.5, 2**53):
            with self.assertRaises(ValueError):
                generate_init_script("systemd", "s6", "/bin/core", "/etc/core.json",
                                     fd_ceiling=value)

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
