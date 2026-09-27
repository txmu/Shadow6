#!/usr/bin/env python3
"""Test shadow6_connect.py one-click Public6 connection tool."""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "CLI"))
from shadow6_connect import CORE_NAMES

class TestShadow6Connect(unittest.TestCase):
    def test_core_names_matches_public6(self):
        sys.path.insert(0, str(ROOT / "Public6"))
        from join_code import CORE_NAMES as PUBLIC6_CORES
        self.assertEqual(set(CORE_NAMES), PUBLIC6_CORES)
    
    def test_all_twelve_cores_present(self):
        self.assertEqual(len(CORE_NAMES), 12)
        expected = {"go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp"}
        self.assertEqual(set(CORE_NAMES), expected)

if __name__ == "__main__":
    unittest.main()
