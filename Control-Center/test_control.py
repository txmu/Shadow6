#!/usr/bin/env python3

import json
import asyncio
import io
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from shadow6_control import API_VERSION, dispatch, render_build_config, response, schema
import shadow6_control as control


CONTROL = Path(__file__).with_name("shadow6_control.py")


class ControlCenterTests(unittest.TestCase):
    def test_abc_control_session_is_monotonic_and_replay_protected(self):
        session = control.ABCControlSession(ttl=10)
        self.assertEqual(session.advance("B", 1)["phase"], "B")
        self.assertEqual(session.advance("C", 2)["phase"], "C")
        with self.assertRaises(ValueError):
            session.advance("A", 3)
        with self.assertRaises(ValueError):
            session.advance("C", 2)
    def test_privacy_and_guide_match_across_stdio_protocols(self):
        def run(adapter, payload):
            return subprocess.run([sys.executable, str(CONTROL), adapter], input=payload,
                capture_output=True, timeout=15, check=True).stdout

        for method, params in (("system.guide", {"lang": "zh"}), ("privacy.report", {})):
            expected = dispatch(method, params)
            tool = control._tool_name(method)
            request = {"id": 1, "method": method, "params": params}
            result = json.loads(run("rpc", (json.dumps(request) + "\n").encode()))
            self.assertEqual(result["result"], expected)
            messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": params}}]
            output = run("mcp", "".join(json.dumps(item) + "\n" for item in messages).encode())
            self.assertEqual(json.loads(output.splitlines()[1])["result"]["structuredContent"], expected)
            call = {"type": "function_call", "call_id": "privacy-test", "name": tool, "arguments": json.dumps(params)}
            result = json.loads(run("openai-rpc", (json.dumps(call) + "\n").encode()))
            self.assertEqual(json.loads(result["output"])["result"], expected)
            messages[1] = {"jsonrpc": "2.0", "id": 2, "method": "workspace/executeCommand",
                           "params": {"command": tool, "arguments": [params]}}
            payload = b""
            for item in messages:
                body = json.dumps(item).encode()
                payload += f"Content-Length: {len(body)}\r\n\r\n".encode() + body
            output = run("lsp", payload)
            replies = []
            while output:
                header, output = output.split(b"\r\n\r\n", 1)
                size = int(header.split(b":", 1)[1])
                replies.append(json.loads(output[:size])); output = output[size:]
            self.assertEqual(replies[1]["result"], expected)

    def test_privacy_report_discards_identifying_diagnostics(self):
        with mock.patch.object(control, "doctor", return_value={"checks": [
                {"passed": True, "detail": "secret/path/identity", "name": "private-host"},
                {"passed": False, "detail": "TOKEN"}]}):
            self.assertEqual(dispatch("privacy.report"), {"profile": "aggregate-only", "checks": 2,
                "passed": 1, "failed": 1, "network_anonymity": False})

    def test_safe_errors_and_jsonl_default_permissions(self):
        with mock.patch.object(control, "dispatch", side_effect=ValueError("SECRET /home/private")):
            result = response({"method": "system.schema"})
        self.assertNotIn("SECRET", json.dumps(result)); self.assertNotIn("/home/private", json.dumps(result))
        request = {"method": "config.render", "params": {}}
        self.assertEqual(response(request)["error"]["code"], "PermissionError")
        self.assertTrue(response(request, allow_mutations=True)["ok"])

    def test_shared_privacy_and_guide_tool_contracts(self):
        for protocol in ("mcp", "openai"):
            names = {item["name"] for item in control._tool_definitions(protocol)}
            self.assertTrue({"shadow6_privacy_report", "shadow6_system_guide"} <= names)
        self.assertFalse(schema()["transport"]["jsonl"]["mutations_default"])
        for lang in ("en", "zh"):
            expected = dispatch("system.guide", {"lang": lang})
            self.assertEqual(control._invoke_tool("shadow6_system_guide", {"lang": lang}, False), expected)
        with self.assertRaises(ValueError):
            dispatch("privacy.report", {"include_secrets": True})

    def test_read_only_transports_cannot_choose_host_executables_or_roots(self):
        for method, params in (
            ("gate.features", {"binary": "/usr/bin/true"}),
            ("config.validate", {"kind": "core-go", "path": "/tmp/config", "binary": "/usr/bin/true"}),
            ("crosed.features", {"cores": ["/usr/bin/true"]}),
            ("assistant.doctor", {"root": "/tmp"}),
        ):
            with self.subTest(method=method), mock.patch.object(control, "dispatch") as invoke:
                result = response({"method": method, "params": params}, allow_mutations=False)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], "PermissionError")
                invoke.assert_not_called()

    def test_extension_transport_accepts_only_explicit_crosed_core_and_fixed_plugin_trust(self):
        root = Path(__file__).resolve().parents[1]
        base = {"core": str(root / "Core-Go/shadow6-go"), "request": "/tmp/request",
                "crosed_trust": "/tmp/crosed-trust", "bindings": "/tmp/bindings"}
        with self.assertRaises(PermissionError):
            control._transport_execution_policy("extensions.invoke", base)
        changed = {**base, "core": str(root / "Core-Go/shadow6-go-crosed"),
                   "plugin_trust": "/tmp/caller-controlled-trust"}
        with self.assertRaises(PermissionError):
            control._transport_execution_policy("extensions.invoke", changed)

    def test_schema_constraints_are_enforced_before_dispatch(self):
        for method, params in (
            ("crosed.features", {"cores": ["x"] * 17}),
            ("packages.install", {"package": "x", "trust_store": "x", "store": "x", "activate": 1}),
            ("runbook.plan", {"action": "audit", "private_key": "x", "output": "x", "ttl": 301}),
            ("runbook.plan", {"action": "audit", "private_key": "x", "output": "x", "ttl": True}),
            ("gate.portmap.validate", {}),
            ("migration.plan", {"apply": True}),
        ):
            with self.subTest(method=method), self.assertRaises(ValueError):
                dispatch(method, params)

    def test_jsonl_stops_reading_at_oversized_frame(self):
        stream = mock.Mock()
        stream.buffer.readline.return_value = b"x" * (control.MAX_REQUEST + 1)
        output = io.StringIO()
        with mock.patch.object(sys, "stdin", stream), mock.patch.object(sys, "stdout", output):
            control.jsonl()
        stream.buffer.readline.assert_called_once_with(control.MAX_REQUEST + 1)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "RequestTooLarge")

    def test_protocols_reject_duplicate_and_nonportable_json(self):
        for raw in (b'{"method":"system.schema","method":"system.status"}\n',
                    b'{"method":"system.schema","id":NaN}\n',
                    b'{"method":"system.schema","id":"\\ud800"}\n'):
            with self.subTest(raw=raw):
                completed = subprocess.run([sys.executable, str(CONTROL), "rpc"], input=raw,
                                           capture_output=True, timeout=10, check=True)
                self.assertFalse(json.loads(completed.stdout)["ok"])

    def test_lsp_rejects_duplicate_length_and_truncated_headers(self):
        for data in (b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                     b"Content-Length: 2\r\n"):
            stream = mock.Mock(buffer=io.BytesIO(data))
            with mock.patch.object(sys, "stdin", stream), self.assertRaises(ValueError):
                control._read_lsp_message()

    def test_core_validation_preserves_secret_symlink_for_core_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret"
            target.write_text("{}")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with mock.patch.object(control, "bounded_run", return_value=subprocess.CompletedProcess([], 1, "", "symlink rejected")) as run:
                with self.assertRaisesRegex(ValueError, "symlink rejected"):
                    dispatch("config.validate", {"kind": "core-go", "path": str(link)})
            self.assertIn(str(link), run.call_args.args[0])

    def test_schema_covers_components_features_init_and_ui_transport(self):
        document = schema()
        self.assertEqual(document["api_version"], API_VERSION)
        self.assertIn("control-center", document["components"])
        self.assertIn("core-cpp", document["components"])
        self.assertEqual(document["features"]["crosed_level"]["maximum"], 5)
        for system in ("rc.d", "procd", "launchd", "guix"):
            self.assertIn(system, document["init_systems"])
        self.assertTrue(document["transport"]["http"]["loopback_only"])
        self.assertIn("slots.invoke", document["methods"])
        self.assertIn("extensions.invoke", document["methods"])
        for method in ("packages.list", "packages.verify", "packages.install", "packages.activate"):
            self.assertIn(method, document["methods"])
        for method in ("public6.profile", "public6.offer", "public6.negotiate"):
            self.assertIn(method, document["methods"])
        self.assertIn("public6-offer", document["config_kinds"])
        self.assertIn("core-cpp", document["config_kinds"])

    def test_build_configuration_is_complete_and_strict(self):
        config = render_build_config({
            "crosed_level": 5, "app_transport": True, "qubes_isolation": True,
            "build_control": True,
        }).decode()
        self.assertIn("BUILD_PLUGINS=1\n", config)
        self.assertIn("BUILD_CPP=1\n", config)
        self.assertIn("BUILD_CONTROL=1\n", config)
        self.assertIn("CROSED_LEVEL=5\n", config)
        self.assertIn("APP_TRANSPORT=1\n", config)
        with self.assertRaisesRegex(ValueError, "unknown parameters"):
            render_build_config({"arbitrary_command": True})

    def test_init_render_writes_atomic_file_with_expected_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "shadow6"
            result = dispatch("init.render", {
                "system": "openwrt", "name": "shadow6", "binary": "/usr/bin/shadow6-go",
                "config": "/etc/shadow6/core.json", "output": str(target),
            })
            self.assertEqual(result["mode"], "0755")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertIn("USE_PROCD=1", target.read_text(encoding="utf-8"))

    def test_rpc_errors_are_bounded_and_web_mutations_default_deny(self):
        ok = response({"id": "你好", "method": "system.schema", "params": {}})
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["id"], "你好")
        denied = response({"id": 2, "method": "config.render", "params": {}}, allow_mutations=False)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "PermissionError")
        invalid = response({"method": "system.schema", "extra": True})
        self.assertFalse(invalid["ok"])

    def test_plugin_inventory_is_available_through_unified_api(self):
        root = Path(__file__).resolve().parents[1]
        result = dispatch("plugins.list", {"root": str(root)})
        self.assertIn("maze-runner", result["plugins"])

    def test_config_output_is_utf8(self):
        result = dispatch("init.render", {
            "system": "launchd", "name": "shadow6", "binary": "/opt/影子/shadow6",
            "config": "/etc/影子.json",
        })
        encoded = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self.assertIn("影子".encode("utf-8"), encoded)

    def test_slots_are_available_through_unified_api(self):
        result = dispatch("slots.catalog", {})
        self.assertIn("slot.protocol.factory", result["slots"])

    def test_key_generation_never_returns_private_key_material(self):
        with tempfile.TemporaryDirectory() as directory:
            private_path = Path(directory) / "identity.key"
            result = dispatch("orchestrator.key.generate", {"private_key_output": str(private_path)})
            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
            self.assertEqual(len(private_path.read_text(encoding="utf-8").strip()), 64)
            self.assertNotIn("private_key", result)
            self.assertEqual(len(result["public_key"]), 64)

    def test_mcp_lists_tools_and_denies_mutations_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            denied_output = Path(directory) / "not-created"
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "shadow6_orchestrator_key_generate", "arguments": {"private_key_output": str(denied_output)}}},
            ]
            completed = subprocess.run(
                [sys.executable, str(CONTROL), "mcp"],
                input="".join(json.dumps(item) + "\n" for item in requests),
                capture_output=True, text=True, timeout=10, check=True,
            )
            replies = [json.loads(line) for line in completed.stdout.splitlines()]
            self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-06-18")
            names = {tool["name"] for tool in replies[1]["result"]["tools"]}
            self.assertIn("shadow6_orchestrator_topology_apply", names)
            self.assertIn("shadow6_packages_install", names)
            self.assertIn("shadow6_public6_negotiate", names)
            self.assertTrue(replies[2]["result"]["isError"])
            self.assertFalse(denied_output.exists())

    def test_openai_tools_use_responses_function_shape(self):
        completed = subprocess.run(
            [sys.executable, str(CONTROL), "openai-tools"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        tools = json.loads(completed.stdout)
        by_name = {tool["name"]: tool for tool in tools}
        key_tool = by_name["shadow6_orchestrator_key_generate"]
        self.assertEqual(key_tool["type"], "function")
        self.assertFalse(key_tool["parameters"]["additionalProperties"])
        self.assertIn("private_key_output", key_tool["parameters"]["required"])
        self.assertIn("shadow6_public6_profile", by_name)

        call = {"type": "function_call", "call_id": "call_1", "name": "shadow6_orchestrator_commands", "arguments": "{}"}
        completed = subprocess.run(
            [sys.executable, str(CONTROL), "openai-rpc"],
            input=json.dumps(call) + "\n", capture_output=True, text=True,
            timeout=10, check=True,
        )
        output = json.loads(completed.stdout)
        self.assertEqual(output["type"], "function_call_output")
        self.assertTrue(json.loads(output["output"])["ok"])

    def test_public6_profile_is_available_through_unified_api(self):
        result = dispatch("public6.profile", {})
        self.assertEqual(result["suite"], "public6")
        self.assertEqual(result["compatibility_gate"], ["core.family", "core.version"])

    def test_lsp_executes_read_only_workspace_command(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "workspace/executeCommand", "params": {"command": "shadow6_orchestrator_commands", "arguments": [{}]}},
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": None},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
        request = bytearray()
        for message in messages:
            body = json.dumps(message, separators=(",", ":")).encode()
            request.extend(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        completed = subprocess.run(
            [sys.executable, str(CONTROL), "lsp"], input=bytes(request),
            capture_output=True, timeout=10, check=True,
        )
        output = completed.stdout
        replies = []
        while output:
            header, output = output.split(b"\r\n\r\n", 1)
            length = int(header.split(b":", 1)[1].strip())
            body, output = output[:length], output[length:]
            replies.append(json.loads(body))
        self.assertIn("executeCommandProvider", replies[0]["result"]["capabilities"])
        self.assertIn("apply", replies[1]["result"]["commands"])
        self.assertIsNone(replies[2]["result"])


class ControlHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from aiohttp import ClientSession, web
        self.runner = control.http_runner(control.http_app("a" * 32))
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.client = ClientSession()

    async def asyncTearDown(self):
        await self.client.close()
        await self.runner.cleanup()

    async def test_http_auth_strict_json_and_readonly_boundary(self):
        async with self.client.get(self.url + "/v1/schema", headers={"Authorization": "Bearer 非ASCII"}) as reply:
            self.assertEqual(reply.status, 401)
            self.assertEqual(reply.headers["Cache-Control"], "no-store")
        headers = {"Authorization": "Bearer " + "a" * 32, "Content-Type": "application/json"}
        async with self.client.get(self.url + "/v1/schema", headers=headers) as reply:
            self.assertEqual(reply.status, 200)
        for payload in ('{"method":"system.schema","method":"system.status"}',
                        '{"method":"gate.features","params":{"binary":"/usr/bin/true"}}',
                        '{"method":"orchestrator.key.generate","params":{"private_key_output":"/tmp/unused"}}'):
            async with self.client.post(self.url + "/v1/rpc", data=payload, headers=headers) as reply:
                self.assertEqual(reply.status, 400)
        async with self.client.post(self.url + "/v1/rpc", data=b"x" * (control.MAX_REQUEST + 1), headers=headers) as reply:
            self.assertEqual(reply.status, 413)

    async def test_http_rejects_browser_and_header_ambiguity(self):
        auth = {"Authorization": "Bearer " + "a" * 32}
        for extra in ({"Host": f"attacker.invalid:{self.port}"},
                      {"Host": "127.0.0.1:1"}, {"Origin": "null"},
                      {"Origin": "https://attacker.invalid"},
                      {"Origin": self.url + "/"}, {"Sec-Fetch-Site": "cross-site"},
                      {"Sec-Fetch-Site": "same-site"}):
            with self.subTest(headers=extra):
                async with self.client.get(self.url + "/v1/schema", headers=auth | extra) as reply:
                    self.assertEqual(reply.status, 403)
                    self.assertEqual(reply.headers["Cache-Control"], "no-store")
                    self.assertEqual(reply.headers["X-Frame-Options"], "DENY")
        for extra in ({"Origin": self.url, "Sec-Fetch-Site": "same-origin"},
                      {"Host": f"localhost:{self.port}"}):
            async with self.client.get(self.url + "/v1/schema", headers=auth | extra) as reply:
                self.assertEqual(reply.status, 200)
        duplicates = [("Authorization", "Bearer " + "a" * 32), ("Authorization", "Bearer " + "a" * 32)]
        async with self.client.get(self.url + "/v1/schema", headers=duplicates) as reply:
            self.assertEqual(reply.status, 401)
            self.assertIn("Bearer", reply.headers["WWW-Authenticate"])
        for name, value in (("Origin", self.url), ("Sec-Fetch-Site", "same-origin")):
            async with self.client.get(self.url + "/v1/schema", headers=list(auth.items()) + [(name, value)] * 2) as reply:
                self.assertEqual(reply.status, 403)

    async def test_http_requires_uncompressed_explicit_json(self):
        auth = {"Authorization": "Bearer " + "a" * 32}
        for extra in ({}, {"Content-Type": "text/plain"},
                      {"Content-Type": "application/x-www-form-urlencoded"},
                      {"Content-Type": "application/json", "Content-Encoding": "gzip"}):
            async with self.client.post(self.url + "/v1/rpc", data='{"method":"system.schema"}', headers=auth | extra) as reply:
                self.assertEqual(reply.status, 415)
        async with self.client.post(self.url + "/v1/rpc", json={"method": "system.schema"}, headers=auth) as reply:
            self.assertEqual(reply.status, 200)
            self.assertTrue((await reply.json())["ok"])

    async def test_http_shared_privacy_and_guide_methods(self):
        for method, params in (("system.guide", {"lang": "zh"}), ("privacy.report", {})):
            expected = await asyncio.to_thread(dispatch, method, params)
            async with self.client.post(self.url + "/v1/rpc", json={"method": method, "params": params},
                    headers={"Authorization": "Bearer " + "a" * 32}) as reply:
                self.assertEqual(reply.status, 200)
                self.assertEqual((await reply.json())["result"], expected)

    async def test_http_caps_open_connections(self):
        connections = []
        try:
            for _ in range(65):
                connections.append(await asyncio.open_connection("127.0.0.1", self.port))
            self.assertLessEqual(len(self.runner.server.connections), 64)
            self.assertEqual(await asyncio.wait_for(connections[-1][0].read(1), 2), b"")
        finally:
            for _, writer in connections:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for _, writer in connections), return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
