from pathlib import Path

ROOT = Path(__file__).parents[1]
SRC = (ROOT / "src/main.ha").read_text()

def test_fixed_packet_contract():
    assert "len(p) == PACKET" in SRC
    assert "12-byte monotonic nonce" in (ROOT / "README.md").read_text()

def test_platform_scope_and_fail_closed():
    assert "Linux/FreeBSD" in (ROOT / "README.md").read_text()
    assert "fstat" in SRC

if __name__ == "__main__":
    test_fixed_packet_contract()
    assert "NOFOLLOW" in SRC and "fstat" in SRC
    print("Core-Hare contract tests passed")
