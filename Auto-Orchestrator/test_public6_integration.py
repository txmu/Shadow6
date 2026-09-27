#!/usr/bin/env python3
"""Test Public6 join-code integration in Auto-Orchestrator."""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "CLI"))
from shadow6_connect import CORE_NAMES as CONNECT_CORES

sys.path.insert(0, str(ROOT / "Public6"))
from join_code import CORE_NAMES as PUBLIC6_CORES

sys.path.insert(0, str(ROOT / "Auto-Orchestrator"))
from shadow6_auto import CORE_ENGINES

class TestPublic6Integration(unittest.TestCase):
    def test_connect_tool_covers_all_public6_cores(self):
        self.assertEqual(set(CONNECT_CORES), PUBLIC6_CORES)
    
    def test_orchestrator_covers_all_twelve_cores(self):
        core_families = {e.removeprefix("shadow6-") for e in CORE_ENGINES}
        self.assertEqual(len(core_families), 12)
        self.assertEqual(core_families, PUBLIC6_CORES)

if __name__ == "__main__":
    unittest.main()
