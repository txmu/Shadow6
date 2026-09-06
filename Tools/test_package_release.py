import tempfile
import unittest
from pathlib import Path

from prepare_text_zip import prepare


class TextZipTests(unittest.TestCase):
    def test_existing_txt_suffix_chain_preserves_every_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            originals = {"note": "first", "note.txt": "second", "note.txt.txt": "third"}
            for name, content in originals.items():
                (root / name).write_text(content, encoding="utf-8")
            self.assertEqual(prepare(root), (3, 0))
            for name, content in originals.items():
                self.assertEqual((root / (name + ".txt")).read_text(encoding="utf-8"), content)

    def test_only_utf8_text_is_renamed_and_binary_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("你好\n", encoding="utf-8")
            (root / "empty").write_bytes(b"")
            (root / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00binary")
            kept, removed = prepare(root)
            self.assertEqual((kept, removed), (2, 1))
            self.assertTrue((root / "README.md.txt").is_file())
            self.assertTrue((root / "empty.txt").is_file())
            self.assertFalse((root / "icon.png.txt").exists())
            self.assertFalse((root / "icon.png").exists())


if __name__ == "__main__":
    unittest.main()
