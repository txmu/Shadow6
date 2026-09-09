from pathlib import Path
import argparse
import json
import subprocess
import tempfile

ROOT = Path(__file__).parents[1]
SRC = (ROOT / "src/main.ha").read_text()

def test_fixed_packet_contract():
    assert "len(p) == PACKET" in SRC
    assert "12-byte monotonic nonce" in (ROOT / "README.md").read_text()

def test_platform_scope_and_fail_closed():
    assert "Linux/FreeBSD" in (ROOT / "README.md").read_text()
    assert "fstat" in SRC

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    test_fixed_packet_contract()
    test_platform_scope_and_fail_closed()
    assert "NOFOLLOW" in SRC and "fstat" in SRC
    print("Core-Hare contract tests passed")
    if args.binary:
        binary = str(args.binary.resolve(strict=True))
        result = subprocess.run([binary, "--feature-report"], check=True,
                                capture_output=True, text=True, timeout=10)
        report = json.loads(result.stdout)
        assert report["core"] == "shadow6-hare"
        assert report["crosed_max_level"] == 0
        assert report["crosed_capabilities"] == []
        assert not report["crosed_compiled"]
        assert not report["app_transport"] and not report["qubes_isolation"]
        with tempfile.TemporaryDirectory(prefix="shadow6-hare-test-") as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"role":"broker"}')
            path.chmod(0o600)
            def check(expected):
                result = subprocess.run([binary, "--check-config", str(path)],
                                        capture_output=True, text=True, timeout=10)
                assert (result.returncode == 0) == expected, result
            check(True)
            path.chmod(0o644)
            check(False)
            path.chmod(0o600)
            path.write_text('{"unknown":true}')
            check(False)
            target = Path(directory) / "target.json"
            path.write_text('{"role":"broker"}')
            path.rename(target)
            path.symlink_to(target)
            check(False)
        print("Core-Hare native feature, config, mode and symlink tests passed")
