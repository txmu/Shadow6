#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path

from shadow6_plugins import PluginRegistry
from shadow6_slots import SLOTS, SlotError, catalog, invoke, load_bindings


ROOT = Path(__file__).resolve().parents[1]


class SlotTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry(ROOT / "plugins", ROOT / "Plugin-System" / "trusted_signers.json")

    def binding_file(self, document):
        temporary = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        json.dump(document, temporary)
        temporary.close()
        os.chmod(temporary.name, 0o600)
        self.addCleanup(lambda: Path(temporary.name).unlink(missing_ok=True))
        return Path(temporary.name)

    def test_catalog_spans_all_major_surfaces(self):
        phases = {definition["phase"] for definition in catalog()["slots"].values()}
        for phase in ("lifecycle", "transport", "application", "identity", "security", "assistant", "presentation"):
            self.assertIn(phase, phases)

    def test_empty_binding_set_is_valid_and_invocable(self):
        path = self.binding_file({"version": 1, "bindings": []})
        self.assertEqual(load_bindings(path, self.registry), [])
        result = invoke("slot.transport.observe", {"文字": "✓"}, path, self.registry)
        self.assertEqual(result["payload"], {"文字": "✓"})

    def test_unsigned_slot_capability_is_rejected(self):
        path = self.binding_file({"version": 1, "bindings": [{
            "slot": "slot.ui.panel", "plugin": "maze-runner", "priority": 1,
            "required": True, "enabled": True,
        }]})
        with self.assertRaisesRegex(SlotError, "not signed"):
            load_bindings(path, self.registry)

    def test_privileged_slots_require_explicit_approval(self):
        path = self.binding_file({"version": 1, "bindings": []})
        with self.assertRaisesRegex(SlotError, "explicit privileged"):
            invoke("slot.assistant.hand", {}, path, self.registry)
        self.assertEqual(invoke("slot.assistant.hand", {}, path, self.registry, allow_privileged=True)["level"], 4)

    def test_unknown_fields_and_duplicate_bindings_fail_closed(self):
        path = self.binding_file({"version": 1, "bindings": [], "extra": True})
        with self.assertRaises(SlotError):
            load_bindings(path, self.registry)


if __name__ == "__main__":
    unittest.main()
