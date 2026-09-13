"""Native protocol boundary tests; no sockets, downloads or secret files."""
import ctypes as C
import ctypes.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
U8 = C.c_ubyte
P = C.POINTER(U8)
N = C.c_size_t


def buf(value):
    return (U8 * value)() if isinstance(value, int) else (U8 * len(value)).from_buffer_copy(value)


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="shadow6-pony-crypto-")
        cls.addClassCleanup(cls.temp.cleanup)
        library = Path(cls.temp.name) / "session.so"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared",
                        "-fPIC", "-O2", "-fstack-protector-strong", str(ROOT / "crypto/session.c"),
                        "-lsodium", "-o", str(library)], check=True, timeout=60)
        cls.lib = C.CDLL(str(library))
        cls.lib.s6p_public.argtypes = [P, N, P, N]
        cls.lib.s6p_start.argtypes = [P, N, P, N, P, N, P, N, C.c_uint64]
        cls.lib.s6p_respond.argtypes = [P, N, P, N, P, N, P, N, P, N, C.c_uint64]
        cls.lib.s6p_finish.argtypes = [P, N, P, N, P, N, C.c_uint64]
        cls.lib.s6p_seal.argtypes = [P, N, N, P, N, C.c_uint64, C.c_uint]
        cls.lib.s6p_open.argtypes = [P, N, P, N]
        cls.sodium = C.CDLL(ctypes.util.find_library("sodium"))
        cls.sodium.crypto_sign_seed_keypair.argtypes = [P, P, P]
        cls.sodium.crypto_sign_detached.argtypes = [P, C.c_void_p, P, C.c_ulonglong, P]

    def setUp(self):
        self.client = buf(bytes(range(32)))
        self.agent = buf(bytes(range(32, 64)))
        self.cp, self.ap = buf(32), buf(32)
        self.assertEqual(self.lib.s6p_public(self.client, 32, self.cp, 32), 0)
        self.assertEqual(self.lib.s6p_public(self.agent, 32, self.ap, 32), 0)
        self.state, self.hello, self.response = buf(236), buf(140), buf(172)
        self.ck, self.ak = buf(96), buf(96)
        self.assertEqual(self.lib.s6p_start(self.client, 32, self.ap, 32,
                                         self.state, 236, self.hello, 140, 1000), 0)

    def respond(self, now=1000):
        return self.lib.s6p_respond(self.agent, 32, self.cp, 32, self.hello, 140,
                                    self.response, 172, self.ak, 96, now)

    def finish(self, now=1000):
        return self.lib.s6p_finish(self.state, 236, self.response, 172, self.ck, 96, now)

    def establish(self):
        self.assertEqual(self.respond(), 0)
        self.assertEqual(self.finish(), 0)
        self.assertEqual(bytes(self.ck[:32]), bytes(self.ak[32:64]))
        self.assertEqual(bytes(self.ck[32:64]), bytes(self.ak[:32]))
        self.assertEqual(bytes(self.ck[64:]), bytes(self.ak[64:]))
        self.assertNotEqual(bytes(self.ck[:32]), bytes(self.ck[32:64]))
        self.assertEqual(bytes(self.state), bytes(236))

    def seal(self, payload=b"authenticated data", sequence=1, kind=2):
        packet = buf(1200)
        packet[12:12 + len(payload)] = payload
        self.assertEqual(self.lib.s6p_seal(packet, 1200, 12 + len(payload),
                                         self.ck, 96, sequence, kind), 0)
        return buf(bytes(packet[:28 + len(payload)]))

    def test_round_trip_and_key_confirmation(self):
        self.establish()
        for payload in (b"", b"\x00", bytes(range(256)), b"a" * 1172):
            packet = self.seal(payload)
            self.assertEqual(self.lib.s6p_open(packet, len(packet), self.ak, 96), 0)
            self.assertEqual(bytes(packet[12:-16]), payload)

    def test_hello_tampering_every_byte(self):
        original = bytes(self.hello)
        for i in range(140):
            self.hello = buf(original)
            self.hello[i] ^= 1
            self.assertNotEqual(self.respond(), 0, i)
            self.assertEqual(bytes(self.ak), bytes(96))

    def test_response_tampering_every_byte(self):
        self.assertEqual(self.respond(), 0)
        original, state = bytes(self.response), bytes(self.state)
        for i in range(172):
            self.state, self.response = buf(state), buf(original)
            self.response[i] ^= 1
            self.assertNotEqual(self.finish(), 0, i)
            self.assertEqual(bytes(self.ck), bytes(96))
            self.assertEqual(bytes(self.state), bytes(236))

    def test_wrong_pinned_identity(self):
        self.cp[0] ^= 1
        self.assertNotEqual(self.respond(), 0)

    def test_stale_and_future_handshakes(self):
        self.assertNotEqual(self.respond(1031), 0)
        self.assertNotEqual(self.respond(999), 0)
        self.assertEqual(self.respond(1030), 0)
        self.assertNotEqual(self.finish(1031), 0)

    def test_consumed_handshake_cannot_replay(self):
        self.establish()
        self.assertNotEqual(self.finish(), 0)

    def test_low_order_point_with_valid_signature(self):
        self.hello[44:76] = bytes(32)
        message = buf(bytes(self.hello[:76]) + bytes(self.cp) + bytes(self.ap))
        sk, pk, sig = buf(64), buf(32), buf(64)
        self.sodium.crypto_sign_seed_keypair(pk, sk, self.client)
        self.sodium.crypto_sign_detached(sig, None, message, len(message), sk)
        self.hello[76:] = bytes(sig)
        self.assertNotEqual(self.respond(), 0)

    def test_aead_tampering_and_reflection(self):
        self.establish()
        original = bytes(self.seal())
        for i in range(len(original)):
            packet = buf(original)
            packet[i] ^= 1
            self.assertNotEqual(self.lib.s6p_open(packet, len(packet), self.ak, 96), 0, i)
        packet = buf(original)
        self.assertNotEqual(self.lib.s6p_open(packet, len(packet), self.ck, 96), 0)

    def test_size_counter_and_kind_bounds(self):
        self.establish()
        packet = buf(1201)
        for cap, size, seq, kind in ((1201, 12, 1, 2), (1200, 1185, 1, 2),
                                     (1200, 11, 1, 2), (1200, 12, 0, 2),
                                     (1200, 12, 1000001, 2)):
            self.assertNotEqual(self.lib.s6p_seal(packet, cap, size, self.ck, 96, seq, kind), 0)
        for size in (0, 27, 1201):
            self.assertNotEqual(self.lib.s6p_open(packet, size, self.ak, 96), 0)

    def test_sessions_use_fresh_keys(self):
        self.establish()
        previous = bytes(self.ck)
        self.setUp()
        self.establish()
        self.assertNotEqual(previous, bytes(self.ck))


if __name__ == "__main__":
    unittest.main()
