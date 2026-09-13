import json, tempfile, unittest
from pathlib import Path
from benchmark import _load_config

class ConfigTests(unittest.TestCase):
    def test_rejects_unknown_and_unbounded(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"; p.write_text(json.dumps({"repeats": 1001}))
            with self.assertRaises(ValueError): _load_config(str(p))
    def test_defaults_are_bounded(self):
        c = _load_config(None); self.assertEqual(c["repeats"], 1); self.assertIn("go", c["cores"])

if __name__ == "__main__": unittest.main()
