import os
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from shadow_protocols import (  # noqa: E402
    ProtocolError, ProtocolFactory, ReplayWindow, ShadowChat, ShadowIdentity,
    decode_frame, encode_frame, normalized_text,
)


class ApplicationProtocolTests(unittest.TestCase):
    def test_shadow_identity_signature_domain_and_expiry(self):
        issuer = ShadowIdentity.generate("alice")
        assertion = issuer.assertion("device-1", "chat-vm", {"role": "member"})
        claims = ShadowIdentity.verify(assertion, issuer.public_hex(), {"chat-vm"})
        self.assertEqual(claims["role"], "member")
        with self.assertRaises(ProtocolError):
            ShadowIdentity.verify(assertion, issuer.public_hex(), {"vault-vm"})
        assertion["claims"]["role"] = "admin"
        with self.assertRaises(ProtocolError):
            ShadowIdentity.verify(assertion, issuer.public_hex(), {"chat-vm"})

    def test_shadow_chat_utf8_tamper_and_replay(self):
        key = os.urandom(32)
        alice = ShadowIdentity.generate("alice")
        sender = ShadowChat(key, alice)
        receiver = ShadowChat(key, ShadowIdentity.generate("bob"), ReplayWindow())
        message = sender.encrypt("bob", "你好，Shadow6! e\u0301")
        self.assertEqual(receiver.decrypt(message, alice.public_hex()), "你好，Shadow6! é")
        with self.assertRaises(ProtocolError):
            receiver.decrypt(message, alice.public_hex())
        tampered = sender.encrypt("bob", "original")
        tampered["ciphertext"] = tampered["ciphertext"][:-2] + "AA"
        with self.assertRaises(ProtocolError):
            receiver.decrypt(tampered, alice.public_hex())

    def test_protocol_factory_and_bounded_framing(self):
        factory = ProtocolFactory()
        factory.register("shadow.test", 1, lambda document: document["value"])
        frame = encode_frame({"protocol": "shadow.test", "version": 1, "value": "中文"})
        self.assertEqual(factory.decode(frame), "中文")
        self.assertEqual(decode_frame(frame)["value"], "中文")
        with self.assertRaises(ProtocolError):
            factory.register("shadow.test", 1, lambda document: document)
        with self.assertRaises(ProtocolError):
            decode_frame(b"\x00\x00\x00\x05{}")
        with self.assertRaises(ProtocolError):
            normalized_text("\x00")


if __name__ == "__main__":
    unittest.main()
