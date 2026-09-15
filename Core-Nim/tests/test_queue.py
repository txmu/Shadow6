"""Exercise the real C callback queue without requiring libdatachannel."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class QueueTests(unittest.TestCase):
    def test_reliable_backpressure_and_lifecycle(self):
        with tempfile.TemporaryDirectory(prefix="shadow6-nim-queue-") as tmp:
            binary = Path(tmp) / "queue-test"
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                            "-Werror", "-pthread", str(Path(__file__).with_suffix(".c")),
                            "-o", str(binary)], check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
