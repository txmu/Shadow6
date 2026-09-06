import errno
import os
import pty
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "中国内地用户必须执行.sh"


def run_in_terminal(answer: str):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(str(SCRIPT), [str(SCRIPT), "--show"])
    output = bytearray()
    answered = False
    while True:
        try:
            chunk = os.read(descriptor, 4096)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.extend(chunk)
        if not answered and "手动输入 Y 或 Agree".encode() in output:
            os.write(descriptor, answer.encode() + b"\n")
            answered = True
    os.close(descriptor)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), output.decode("utf-8", errors="replace")


class ComplianceScriptTests(unittest.TestCase):
    def test_pipe_cannot_fake_manual_agreement(self):
        result = subprocess.run(
            [str(SCRIPT), "--show"],
            input="Y\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("必须在交互式终端", result.stderr)
        self.assertIn("中华人民共和国网络安全法", result.stdout)

    def test_exact_y_and_agree_are_accepted_in_terminal(self):
        for answer in ("Y", "Agree"):
            with self.subTest(answer=answer):
                status, output = run_in_terminal(answer)
                self.assertEqual(status, 0)
                self.assertIn("本人承诺仅在境内合法合规使用本工具", output)
                self.assertIn("确认已接受", output)
                self.assertEqual(output.count("iptables -A OUTPUT"), 5)

    def test_other_answer_cancels(self):
        status, output = run_in_terminal("yes")
        self.assertEqual(status, 3)
        self.assertIn("操作已取消", output)
        self.assertNotIn("iptables -A OUTPUT", output)


if __name__ == "__main__":
    unittest.main()
