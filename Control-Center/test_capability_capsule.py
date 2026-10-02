from __future__ import annotations

import json
import os
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import capability_capsule as capsule


ROOT = Path(__file__).resolve().parents[1]


class FakeProcess:
    def __init__(self):
        self.pid = 987654
        self.done = False
        self.closed = threading.Event()

    def poll(self):
        return 0 if self.done else None

    def wait(self, timeout=None):
        self.done = True
        self.closed.set()
        return 0


@unittest.skipUnless(os.name == "posix" and hasattr(socket, "SOCK_SEQPACKET"), "POSIX SOCK_SEQPACKET process lifecycle is required")
class CapabilityCapsuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shadow6-capsule-")
        self.base = Path(self.temp.name)
        self.config = self.base / "client.json"
        self.config.write_text("{}", encoding="utf-8")
        self.config.chmod(0o600)
        self.core = self.base / "fake-core"
        self.marker = self.base / "received.bin"
        self._write_core("seqpacket-fd")
        self.registry = self.base / "capsules.json"
        self._write_registry()
        self.registry_patch = patch.object(capsule, "REGISTRY_FILE", self.registry)
        self.registry_patch.start()
        self.env_patch = patch.dict(os.environ, {
            "SHADOW6_APP_FLOW_PROXY": str(ROOT / "Tools/app_flow_proxy.py"),
            "PYTHON": sys.executable,
            "SHADOW6_TEST_MARKER": str(self.marker),
            "SHADOW6_RUNTIME_MARKER": str(self.base / "runtime-started"),
        })
        self.env_patch.start()
        self.tokens = []

    def tearDown(self):
        for token in self.tokens:
            try:
                capsule.stop(token)
            except (ValueError, OSError):
                pass
        with capsule._LOCK:
            leftovers = list(capsule._CAPSULES.values())
            capsule._CAPSULES.clear()
        for item in leftovers:
            item.close()
        self.env_patch.stop()
        self.registry_patch.stop()
        self.temp.cleanup()

    def _write_core(self, mode: str, max_record: int = 1172):
        core_name = f"shadow6-{mode}"
        if mode == "seqpacket-fd":
            runtime = (
                "if os.environ.get('SHADOW6_RUNTIME_MARKER'):\n"
                " Path(os.environ['SHADOW6_RUNTIME_MARKER']).touch()\n"
                "fd = int(os.environ['SHADOW6_APP_FLOW_FD'])\n"
                "flow = socket.socket(fileno=fd)\n"
                "data = flow.recv(1172)\n"
                "Path(os.environ['SHADOW6_TEST_MARKER']).write_bytes(data)\n"
                "time.sleep(120)\n"
            )
            boundary = {"kind": "message", "mode": mode, "roles": ["client"], "max_record": max_record}
        elif mode == "localhost-tcp-proxy":
            runtime = (
                "listener = socket.socket()\n"
                "listener.bind(('127.0.0.1', 0))\n"
                "listener.listen(4)\n"
                "print(json.dumps({'event':'shadow6.ready','schema':1,'core':core,'role':'client',"
                "'application_boundary':{'kind':'stream','mode':'localhost-tcp-proxy',"
                "'endpoint':{'host':'127.0.0.1','port':listener.getsockname()[1]}}}), flush=True)\n"
                "while True:\n"
                " conn, _ = listener.accept()\n"
                " conn.close()\n"
            )
            boundary = {"kind": "stream", "mode": "localhost-tcp-proxy", "roles": ["client"],
                        "listener_ownership": "core", "endpoint_discovery": "stdout-ready-jsonl-v1"}
        else:
            runtime = "time.sleep(120)\n"
            boundary = {"kind": "message", "mode": "unrecognized", "roles": ["client"]}
        script = (
            "#!/usr/bin/env python3\nimport json, os, socket, sys, time\nfrom pathlib import Path\n"
            f"core = {core_name!r}\n"
            f"if '--feature-report' in sys.argv:\n print(json.dumps({{'core':core,'application_boundaries':[{boundary!r}]}}))\n"
            "else:\n" + "".join(" " + line for line in runtime.splitlines(keepends=True))
        )
        self.core.write_text(script, encoding="utf-8")
        self.core.chmod(0o700)

    def _write_registry(self, max_record: int = 1172):
        self.registry.write_text(json.dumps({"synthetic-core": {
            "binary": str(self.core), "max_record": max_record,
        }}), encoding="utf-8")
        self.registry.chmod(0o600)

    @staticmethod
    def _free_port():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def _connect_retry(self, endpoint):
        deadline = time.monotonic() + 3
        last = None
        while time.monotonic() < deadline:
            try:
                return socket.create_connection(endpoint, timeout=0.3)
            except OSError as error:
                last = error
                time.sleep(0.02)
        raise AssertionError(f"capsule listener did not start: {last}")

    def test_seqpacket_capsule_forwards_local_tcp_and_pause_resume_controls_processes(self):
        result = capsule.start("synthetic-core", str(self.config), "tcp", "127.0.0.1", self._free_port(), ttl=60)
        token = result["token"]
        self.tokens.append(token)
        with self._connect_retry(("127.0.0.1", result["port"])) as peer:
            peer.sendall(b"capsule-payload")
        deadline = time.monotonic() + 3
        while not self.marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.marker.read_bytes(), b"capsule-payload")
        paused = capsule.pause(token)
        self.assertEqual(paused["state"], "paused")
        if Path("/proc").is_dir():
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                states = []
                for pid in paused["pids"]:
                    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
                    states.append(next(line.split()[1] for line in status.splitlines() if line.startswith("State:")))
                if all(state in {"T", "t"} for state in states):
                    break
                time.sleep(0.01)
            self.assertTrue(all(state in {"T", "t"} for state in states), states)
        self.assertEqual(capsule.list_capsules()["capsules"][0]["state"], "paused")
        resumed = capsule.resume(token)
        self.assertEqual(resumed["state"], "running")
        if Path("/proc").is_dir():
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                states = []
                for pid in resumed["pids"]:
                    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
                    states.append(next(line.split()[1] for line in status.splitlines() if line.startswith("State:")))
                if all(state not in {"T", "t"} for state in states):
                    break
                time.sleep(0.01)
            self.assertTrue(all(state not in {"T", "t"} for state in states), states)
        stopped = capsule.stop(token)
        self.assertEqual(stopped["state"], "stopped")
        self.tokens.remove(token)

    def test_stream_boundary_uses_core_ready_endpoint_without_fd_proxy(self):
        self._write_core("localhost-tcp-proxy")
        self._write_registry()
        with patch.dict(os.environ, {"SHADOW6_APP_FLOW_PROXY": ""}), patch.object(capsule.shutil, "which", return_value=None):
            result = capsule.start("synthetic-core", str(self.config), ttl=60)
        token = result["token"]
        self.tokens.append(token)
        self.assertEqual(result["mode"], "localhost-tcp-proxy")
        self.assertNotIn("proxy_pid", result)
        self.assertEqual(result["endpoint"]["host"], "127.0.0.1")
        with socket.create_connection((result["endpoint"]["host"], result["endpoint"]["port"]), timeout=3):
            pass
        capsule.stop(token)
        self.tokens.remove(token)

    def test_missing_proxy_and_unsupported_boundary_fail_before_core_runtime_launch(self):
        runtime_marker = self.base / "runtime-started"
        runtime_marker.unlink(missing_ok=True)
        with patch.dict(os.environ, {"SHADOW6_APP_FLOW_PROXY": ""}):
            with self.assertRaisesRegex(ValueError, "SHADOW6_APP_FLOW_PROXY"):
                capsule.start("synthetic-core", str(self.config), "tcp", "127.0.0.1", self._free_port())
        self.assertFalse(runtime_marker.exists())

        self._write_core("unsupported")
        self._write_registry()
        with self.assertRaisesRegex(ValueError, "application boundary"):
            capsule.start("synthetic-core", str(self.config), "tcp", "127.0.0.1", self._free_port())
        self.assertFalse(runtime_marker.exists())

    def test_core_boundary_limits_and_registry_permissions_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "Core application boundary"):
            capsule.start("synthetic-core", str(self.config), "tcp", "127.0.0.1", self._free_port(), max_record=1172 + 1)
        self.registry.chmod(0o644)
        with self.assertRaises(PermissionError):
            capsule.capsule_registry()

    def test_reaper_enforces_expired_ttl_without_a_status_request(self):
        process = FakeProcess()
        expired = capsule.Capsule("expired-test", "synthetic-core", (process,), time.monotonic() - 5, 1)
        with capsule._LOCK:
            capsule._CAPSULES[expired.token] = expired
        with patch.object(capsule.os, "killpg"):
            capsule._ensure_reaper()
            self.assertTrue(process.closed.wait(2))
        with capsule._LOCK:
            self.assertNotIn(expired.token, capsule._CAPSULES)


if __name__ == "__main__":
    unittest.main()
