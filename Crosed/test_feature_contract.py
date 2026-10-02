import unittest
import pathlib
import socket
from feature_contract import (APP_TRANSPORT_MODES, SEQPACKET_MAX_RECORD,
    STREAM_CONNECTION_LIMIT, TRANSPORTS, validate_application_boundary,
    validate_feature_report, validate_ready_event)

class FeatureContractTests(unittest.TestCase):
    def report(self, core):
        return dict(core=core, version="1.1.0", crosed_compiled=False,
            crosed_max_level=0, app_transport=False, qubes_isolation=False,
            gate_compiled=False, gate_enabled_by_default=False, utf8=True,
            crosed_capabilities=[], transport=TRANSPORTS[core])

    def with_modes(self, core):
        report = self.report(core)
        if core in APP_TRANSPORT_MODES:
            report["app_transport_modes"] = list(APP_TRANSPORT_MODES[core])
            report["application_boundaries"] = [{
                "kind": "message", "mode": "seqpacket-fd", "roles": ["client"],
                "max_record": SEQPACKET_MAX_RECORD[core], "message_preserving": True,
                "backpressure": "native-window", "producer_send_success": "kernel-queue-only",
                "oversize": "discard-record-continue", "transient_error": "retry-eagain-eintr",
                "hard_error": "fail-closed",
                "eof": "empty-record-drain", "close": "drain-accepted-then-stop",
            }]
        else:
            report["application_boundaries"] = [{
                "kind": "stream", "mode": "localhost-tcp-proxy", "roles": ["client"],
                "full_duplex": True, "ordered": True, "reliable": True,
                "backpressure": "tcp-flow-control", "half_close": True,
                "listener_ownership": "core", "endpoint_discovery": "stdout-ready-jsonl-v1",
                "listener_ready": "bound-and-listening",
                "local_connection_limit": STREAM_CONNECTION_LIMIT[core],
                "shutdown": "close-active-flows", "eof": "propagate-half-close",
                "connection_mapping": "one-local-connection-per-native-flow",
            }]
            if core == "shadow6-gleam":
                report["application_boundaries"].append({
                    "kind": "message", "mode": "localhost-udp-datagram-proxy", "roles": ["client"],
                    "message_preserving": True, "ordered": False, "reliable": False,
                    "delivery": "best-effort", "backpressure": "udp-datagram-loss",
                    "max_record": 65465, "listener_ownership": "core",
                    "endpoint_discovery": "stdout-ready-jsonl-v1", "listener_ready": "bound-and-listening",
                    "local_peer_limit": 1, "oversize": "discard-datagram",
                })
        return report

    def test_every_core_and_its_specific_fields(self):
        for core in TRANSPORTS:
            report = self.with_modes(core)
            report.update({"shadow6-ada": {"cell_size": 512}, "shadow6-d": {"better_c": True},
                           "shadow6-nim": {"memory_model": "arc"}}.get(core, {}))
            self.assertEqual(validate_feature_report(report, core), report)

    def test_unknown_missing_mistyped_and_contradictory_fields(self):
        for patch in ({"unknown": True}, {"crosed_max_level": True},
                      {"crosed_capabilities": ["core.hook"]}, {"transport": "quic"},
                      {"gate_enabled_by_default": True}, {"crosed_compiled": True},
                      {"crosed_capabilities": [[], []]}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                validate_feature_report(dict(self.with_modes("shadow6-nim"), **patch))
        report = self.with_modes("shadow6-ada")
        del report["gate_compiled"]
        with self.assertRaises(ValueError): validate_feature_report(report)

    def test_family_fields_cannot_leak_to_other_cores(self):
        with self.assertRaises(ValueError):
            validate_feature_report(dict(self.report("shadow6-go"), better_c=True))
        with self.assertRaises(ValueError):
            validate_feature_report(self.report("shadow6-d"), "shadow6-nim")

    def test_udp_core_application_modes_share_the_validator(self):
        for core, modes in APP_TRANSPORT_MODES.items():
            with self.subTest(core=core):
                report = self.with_modes(core)
                self.assertEqual(report["app_transport_modes"], modes)
                self.assertIs(validate_feature_report(report, core), report)

    def test_gleam_contract_publishes_both_stream_and_micro_mux_boundaries(self):
        report = self.with_modes("shadow6-gleam")
        self.assertEqual([item["mode"] for item in report["application_boundaries"]],
                         ["localhost-tcp-proxy", "localhost-udp-datagram-proxy"])
        self.assertIs(validate_feature_report(report, "shadow6-gleam"), report)
        report["application_boundaries"][1]["reliable"] = True
        with self.assertRaisesRegex(ValueError, "Micro-Mux"):
            validate_feature_report(report, "shadow6-gleam")

    def test_boundary_schema_is_required_and_strict(self):
        report = self.with_modes("shadow6-hare")
        del report["application_boundaries"]
        with self.assertRaises(ValueError):
            validate_feature_report(report)
        for patch in ({"max_record": 1}, {"roles": ["broker"]},
                      {"producer_send_success": "core-admitted"},
                      {"oversize": "close-core"}, {"transient_error": "fatal"},
                      {"hard_error": "ignore"}, {"extra": True}):
            report = self.with_modes("shadow6-idris")
            report["application_boundaries"][0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                validate_feature_report(report)
        for core, limit in STREAM_CONNECTION_LIMIT.items():
            report = self.with_modes(core)
            boundary = report["application_boundaries"][0]
            self.assertEqual(boundary["kind"], "stream")
            self.assertEqual(boundary["local_connection_limit"], limit)
            self.assertIs(validate_feature_report(report, core), report)

    def test_stream_ready_event_is_structured_and_loopback_bounded(self):
        event = {"event":"shadow6.ready", "schema":1, "core":"shadow6-rust",
            "role":"client", "application_boundary":{"kind":"stream",
            "mode":"localhost-tcp-proxy", "endpoint":{"host":"127.0.0.1", "port":43210}}}
        self.assertIs(validate_ready_event(event, "shadow6-rust"), event)
        for mutate in (
            lambda value: value.update(extra=True),
            lambda value: value.update(schema=True),
            lambda value: value["application_boundary"]["endpoint"].update(host="0.0.0.0"),
            lambda value: value["application_boundary"]["endpoint"].update(port=0),
            lambda value: value.update(role="agent"),
        ):
            import copy
            invalid = copy.deepcopy(event)
            mutate(invalid)
            with self.assertRaises(ValueError):
                validate_ready_event(invalid)

    def test_gleam_micro_mux_ready_event_is_structured(self):
        event = {"event":"shadow6.ready", "schema":1, "core":"shadow6-gleam",
            "role":"client", "application_boundary":{"kind":"message",
            "mode":"localhost-udp-datagram-proxy", "endpoint":{"host":"127.0.0.1", "port":43210}}}
        self.assertIs(validate_ready_event(event, "shadow6-gleam"), event)

    def test_seqpacket_records_backpressure_and_runtime_contracts(self):
        if not hasattr(socket, "SOCK_SEQPACKET"):
            self.skipTest("platform has no SOCK_SEQPACKET")
        reader, writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        writer.setblocking(False)
        writer.send(b"first")
        writer.send(b"second-record")
        self.assertEqual(reader.recv(64), b"first")
        self.assertEqual(reader.recv(64), b"second-record")
        sent = 0
        while True:
            try:
                writer.send(b"x" * 512)
                sent += 1
            except BlockingIOError:
                break
        self.assertGreater(sent, 0)
        self.assertEqual(writer.getblocking(), False)
        self.assertEqual(reader.recv(1024), b"x" * 512)

        root = pathlib.Path(__file__).resolve().parents[1]
        runtimes = {
            "shadow6-pony": ("Core-Pony/runtime.pony", (
                "while (count < 16) and _session.can_send()", "_flow_eof", "_session.pending_count() == 0", "data.size() > 1172", "elseif result == -3 then")),
            "shadow6-hare": ("Core-Hare/src/runtime.ha", (
                "poll::event::POLLIN else 0", "pending_count < WINDOW", "rt::MSG_DONTWAIT | rt::MSG_TRUNC", "n > 978 || sent >= 1000000", "pending_count == 0")),
            "shadow6-carp": ("Core-Carp/src/runtime.h", (
                "chain_inflight < CARP_WINDOW", "can_send && !application_flow_eof", "recvmsg(application_flow_fd", "MSG_TRUNC", "n > BODY - COMMAND - 10", "chain_inflight == 0")),
            "shadow6-idris": ("Core-Idris/ffi/sodium_ffi.c", (
                "pending_count<IDRIS_CHAIN_WINDOW", "FD_CLR(ingress,&set)", "MSG_TRUNC", "n==0", "flow_eof&&pending_count==0", "truncated||n>IDRIS_NATIVE_MAX")),
        }
        for core, (relative, required) in runtimes.items():
            source = (root / relative).read_text(encoding="utf-8")
            with self.subTest(core=core):
                for marker in required:
                    self.assertIn(marker, source)

    def test_all_stream_cores_emit_structured_ready_metadata(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        sources = {
            "shadow6-go": ("Core-Go/data.go", "shadow6.ready"),
            "shadow6-rust": ("Core-Rust/src/main.rs", "shadow6.ready"),
            "shadow6-gleam": ("Core-Gleam/src/shadow6_role.erl", "shadow6.ready"),
            "shadow6-zig": ("Core-Zig/src/runtime.zig", "shadow6.ready"),
            "shadow6-ada": ("Core-Ada/src/runtime.adb", "shadow6.ready"),
            "shadow6-d": ("Core-D/src/runtime.d", "shadow6.ready"),
            "shadow6-nim": ("Core-Nim/src/runtime.nim", "shadow6.ready"),
            "shadow6-cpp": ("Core-Cpp/src/runtime.hpp", "shadow6.ready"),
        }
        for core, (relative, marker) in sources.items():
            with self.subTest(core=core):
                self.assertIn(marker, (root / relative).read_text(encoding="utf-8"))

    def test_feature_report_consumers_use_shared_validator(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        consumers = {
            "VCore inventory/discovery": "CLI/shadow6_vcore.py",
            "shadow6 --version": "CLI/shadow6.py",
            "security audit": "shadow6_audit.py",
            "Security Assistants": "Security-Assistants/shadow6_security.py",
            "crosedctl": "Crosed/crosedctl.py",
        }
        for name, relative in consumers.items():
            with self.subTest(consumer=name):
                source = (root / relative).read_text(encoding="utf-8")
                self.assertIn("validate_feature_report", source)

    def test_credited_boundary_is_distinct_from_native_message_and_stream(self):
        boundary = {"kind":"credited", "mode":"s6na-companion",
            "credit_unit":"data-frames", "max_window":64,
            "backpressure":"explicit-credit", "backpressure_error":"S6NA_BACKPRESSURE",
            "close":"invalidate-credit", "closed_error":"S6NA_CLOSED",
            "retry_exhaustion":"S6NA_RETRY_EXHAUSTED"}
        self.assertIs(validate_application_boundary(boundary), boundary)
        import copy
        invalid = copy.deepcopy(boundary)
        invalid["retry_exhaustion"] = "remote-ack"
        with self.assertRaises(ValueError):
            validate_application_boundary(invalid)

    def test_application_modes_are_strict_and_core_scoped(self):
        for core in APP_TRANSPORT_MODES:
            for modes in (["udp"], ["udp", "seqpacket-fd", "tcp"],
                          ["seqpacket-fd", "udp"], "udp"):
                report = self.with_modes(core)
                report["app_transport_modes"] = modes
                with self.subTest(core=core, modes=modes), self.assertRaises(ValueError):
                    validate_feature_report(report, core)
        report = self.report("shadow6-go")
        report["app_transport_modes"] = ["udp", "seqpacket-fd"]
        with self.assertRaises(ValueError):
            validate_feature_report(report)
