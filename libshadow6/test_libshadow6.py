from __future__ import annotations

import json
import os
import socket
import time
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import libshadow6


class LibShadow6Tests(unittest.TestCase):
    def test_s6na_credited_attachment_preserves_records_and_rearms_credit(self):
        from Deployment.service_storage import atomic_write
        with tempfile.TemporaryDirectory(prefix="shadow6-s6na-app-") as raw:
            root = Path(raw)
            reservations = []
            for _ in range(2):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0)); reservations.append(sock)
            left_port, right_port = [sock.getsockname()[1] for sock in reservations]
            for sock in reservations: sock.close()
            key = os.urandom(32)
            sessions = []
            for side, local, remote in ((0,left_port,right_port),(1,right_port,left_port)):
                key_path = root / f"key-{side}"
                config_path = root / f"config-{side}.json"
                atomic_write(key_path, key)
                document = {"schema":"shadow6.s6na-attachment.v1", "core":"go",
                    "key_file":str(key_path), "bind":["127.0.0.1",local],
                    "peer":["127.0.0.1",remote], "side":side, "stream":0,
                    "limits":{"max_message":4096,"max_inflight":4096,
                               "payload_bytes":128,"window_frames":64}}
                atomic_write(config_path, json.dumps(document).encode())
                facade = object.__new__(libshadow6.Shadow6)
                facade._closed = False; facade._attachments = set()
                sessions.append(facade.open_credited(config_path))
            left, right = sessions
            self.addCleanup(left.close); self.addCleanup(right.close)

            for i in range(64):
                self.assertEqual(left.send_record(bytes([i]) * 64), 63-i)
            with self.assertRaisesRegex(libshadow6.Shadow6Error, "S6NA_BACKPRESSURE"):
                left.send_record(b"overflow")
            self.assertEqual(right.receive_record(timeout=1), bytes([0]) * 64)
            self.assertEqual(len(right._received), 63)
            left.endpoint.poll(0)
            self.assertGreater(left.application_credit(), 0)
            right.send_record(b"whole-record-reply")
            self.assertEqual(left.receive_record(timeout=1), b"whole-record-reply")
            owner = left._owner
            owner.close()
            with self.assertRaisesRegex(libshadow6.Shadow6Error, "S6NA_CLOSED"):
                left.application_credit()

    def test_open_selects_matching_boundary_and_context_stops_capsule(self):
        class Runtime(libshadow6.Shadow6):
            def __init__(self):
                self.cli = "unused"
                self._sessions = set()
                self._closed = False
                self.calls = []

            def _control(self, method, params):
                self.calls.append((method, params))
                if method == "capsule.candidates":
                    return {"schema": "shadow6.capability-capsule-candidates.v1", "candidates": [
                        {"core": "pony", "boundary": {"kind": "stream", "mode": "localhost-tcp-proxy",
                         "roles": ["client"], "ordered": True, "reliable": True}}]}
                if method == "capsule.start":
                    return {"state": "running", "token": "secret-token", "mode": "localhost-tcp-proxy",
                            "endpoint": {"host": "127.0.0.1", "port": 43210}}
                return {"state": "stopped"}

        runtime = Runtime()
        with runtime as s6:
            with s6.open({"kind": "stream", "reliable": True, "ordered": True},
                         config="/tmp/core.json") as session:
                self.assertEqual(session.core, "pony")
                self.assertEqual(session.endpoint, {"host": "127.0.0.1", "port": 43210})
                self.assertEqual(session.protocol, "tcp")
                self.assertEqual(session.status(), {"state": "stopped"})
                session.pause()
                session.resume()
            self.assertEqual(runtime.calls[-1][0], "capsule.stop")
        self.assertEqual([call[0] for call in runtime.calls],
                         ["capsule.candidates", "capsule.start", "capsule.status", "capsule.pause",
                          "capsule.resume", "capsule.stop"])

    def test_open_requires_config_and_seqpacket_port(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "shadow6"
            cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cli.chmod(0o700)
            client = libshadow6.Shadow6(cli)
            with self.assertRaisesRegex(ValueError, "config is required"):
                client.open({"kind": "stream"})

    def test_open_requires_port_for_seqpacket_boundary(self):
        class Runtime(libshadow6.Shadow6):
            def __init__(self):
                self.cli = "unused"
                self._sessions = set()
                self._closed = False

            def _control(self, method, params):
                return {"schema": "shadow6.capability-capsule-candidates.v1", "candidates": [
                    {"core": "hare", "boundary": {"kind": "message", "mode": "seqpacket-fd",
                     "roles": ["client"], "message_preserving": True}}]}

        runtime = Runtime()
        with self.assertRaisesRegex(ValueError, "requires a loopback listener port"):
            runtime.open({"kind": "message", "message_preserving": True},
                         config="/tmp/core.json", candidates=["hare"])

    def test_open_can_select_best_effort_micro_mux_udp_endpoint(self):
        class Runtime(libshadow6.Shadow6):
            def __init__(self):
                self.cli = "unused"
                self._sessions = set()
                self._closed = False
                self.start_params = None

            def _control(self, method, params):
                if method == "capsule.candidates":
                    return {"schema": "shadow6.capability-capsule-candidates.v1", "candidates": [
                        {"core": "gleam", "boundary": {"kind": "message",
                         "mode": "localhost-udp-datagram-proxy", "roles": ["client"],
                         "ordered": False, "reliable": False, "delivery": "best-effort"}}]}
                if method == "capsule.start":
                    self.start_params = params
                    return {"state": "running", "token": "mux-token",
                            "mode": params["boundary_mode"],
                            "endpoint": {"host": "127.0.0.1", "port": 50123}}
                return {}

        runtime = Runtime()
        session = runtime.open({"kind": "message", "reliable": False, "ordered": False,
                                "delivery": "best-effort"}, config="/tmp/gleam.json")
        self.assertEqual(session.core, "gleam")
        self.assertEqual(session.protocol, "udp")
        self.assertEqual(session.endpoint["port"], 50123)
        self.assertEqual(runtime.start_params["boundary_mode"], "localhost-udp-datagram-proxy")
        session.close()

    def test_facade_close_stops_all_owned_sessions(self):
        class Runtime(libshadow6.Shadow6):
            def __init__(self):
                self.cli = "unused"
                self._sessions = set()
                self._closed = False
                self.stopped = []

            def _control(self, method, params):
                if method == "capsule.stop":
                    self.stopped.append(params["token"])
                return {}

        runtime = Runtime()
        one = libshadow6.Session(runtime, "one", "go", {"host": "127.0.0.1", "port": 1}, "stream", "tcp")
        two = libshadow6.Session(runtime, "two", "rust", {"host": "127.0.0.1", "port": 2}, "stream", "tcp")
        runtime._sessions.update((one, two))
        runtime.close()
        runtime.close()
        self.assertCountEqual(runtime.stopped, ["one", "two"])

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
