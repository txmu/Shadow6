#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shadow6_extensions import ExtensionError, _application, invoke


class ExtensionTests(unittest.TestCase):
    def request_file(self, document):
        handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        json.dump(document, handle, separators=(",", ":"))
        handle.close()
        os.chmod(handle.name, 0o600)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    @staticmethod
    def request(slot="slot.chat.filter"):
        return {
            "version": 1, "mod_id": "combined-extension", "nonce": "00" * 16,
            "issued_at": 1, "requested_level": 3,
            "capabilities": ["transport.application"],
            "source_domain": "work", "target_domain": "vault",
            "payload": {"application": {
                "protocol": "shadow.extension", "version": 1, "slot": slot,
                "source_domain": "work", "target_domain": "vault", "payload": {"text": "ok"},
            }}, "signature": "00" * 64,
        }

    def test_domains_are_bound_to_signed_crosed_envelope(self):
        request = self.request()
        request["payload"]["application"]["target_domain"] = "work"
        with self.assertRaisesRegex(ExtensionError, "does not match"):
            _application(request)

    @patch("shadow6_extensions.invoke_slot")
    @patch("shadow6_extensions.negotiate")
    @patch("shadow6_extensions.load_bindings")
    def test_three_systems_are_one_fail_closed_transaction(self, bindings, negotiate, slot_call):
        bindings.return_value = [{"slot": "slot.chat.filter", "enabled": True}]
        negotiate.return_value = {
            "status": "granted", "core": "shadow6-go", "granted_level": 3,
            "granted_capabilities": ["transport.application"],
        }
        slot_call.return_value = {"protocol": "shadow6.slot.v1", "payload": {"text": "filtered"}}
        result = invoke(Path("/core"), self.request_file(self.request()), Path("/trust"), Path("/bindings"), object())
        self.assertEqual(result["result"]["payload"]["text"], "filtered")
        slot_call.assert_called_once()

        negotiate.return_value["granted_capabilities"] = []
        with self.assertRaisesRegex(ExtensionError, "does not cover"):
            invoke(Path("/core"), self.request_file(self.request()), Path("/trust"), Path("/bindings"), object())

    @patch("shadow6_extensions.load_bindings", return_value=[])
    def test_a_signed_plugin_provider_is_mandatory(self, _bindings):
        with self.assertRaisesRegex(ExtensionError, "no enabled signed"):
            invoke(Path("/core"), self.request_file(self.request()), Path("/trust"), Path("/bindings"), object())


if __name__ == "__main__":
    unittest.main()
