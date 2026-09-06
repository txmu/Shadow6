#!/usr/bin/env python3
"""UTF-8 application protocols carried over a Shadow6 local proxy."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAX_FRAME = 1_048_576
MAX_TEXT = 65_536
IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DOMAIN_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


class ProtocolError(ValueError):
    pass


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise ProtocolError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(ProtocolError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise ProtocolError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise ProtocolError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise ProtocolError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise ProtocolError("invalid Unicode scalar") from exc
            if size > MAX_FRAME or "\x00" in item:
                raise ProtocolError("unsafe or oversized JSON string")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise ProtocolError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise ProtocolError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise ProtocolError("JSON document exceeds size limit")
    return encoded


def normalized_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("text must be a string")
    normalized = unicodedata.normalize("NFC", value)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeError as exc:
        raise ProtocolError("text contains an invalid Unicode scalar") from exc
    if not encoded or len(encoded) > MAX_TEXT or "\x00" in normalized:
        raise ProtocolError("UTF-8 text is empty, oversized, or contains NUL")
    return normalized


def encode_frame(document: dict[str, Any]) -> bytes:
    if not isinstance(document, dict):
        raise ProtocolError("application frame must be an object")
    payload = canonical(document)
    if len(payload) > MAX_FRAME:
        raise ProtocolError("application frame exceeds 1 MiB")
    return struct.pack(">I", len(payload)) + payload


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) < 4:
        raise ProtocolError("truncated application frame")
    length = struct.unpack(">I", frame[:4])[0]
    if length > MAX_FRAME or len(frame) != length + 4:
        raise ProtocolError("invalid application frame length")
    try:
        document = strict_json(frame[4:], MAX_FRAME)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid UTF-8 JSON application frame") from exc
    if not isinstance(document, dict):
        raise ProtocolError("application frame must be an object")
    return document


class ProtocolFactory:
    def __init__(self) -> None:
        self._decoders: dict[tuple[str, int], Callable[[dict[str, Any]], Any]] = {}

    def register(self, protocol: str, version: int, decoder: Callable[[dict[str, Any]], Any]) -> None:
        if not isinstance(protocol, str) or not re.fullmatch(r"shadow\.[a-z][a-z0-9.-]{1,63}", protocol) or type(version) is not int or not 1 <= version <= 255 or not callable(decoder):
            raise ProtocolError("invalid protocol identifier or version")
        key = (protocol, version)
        if key in self._decoders:
            raise ProtocolError("protocol version is already registered")
        self._decoders[key] = decoder

    def decode(self, frame: bytes) -> Any:
        document = decode_frame(frame)
        protocol, version = document.get("protocol"), document.get("version")
        if not isinstance(protocol, str) or type(version) is not int:
            raise ProtocolError("invalid protocol identifier or version type")
        decoder = self._decoders.get((protocol, version))
        if decoder is None:
            raise ProtocolError("unsupported protocol or version")
        return decoder(document)


@dataclass(frozen=True)
class ShadowIdentity:
    identity: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, identity: str) -> "ShadowIdentity":
        if not isinstance(identity, str) or not IDENTITY_RE.fullmatch(identity):
            raise ProtocolError("invalid ShadowIdentity name")
        return cls(identity, Ed25519PrivateKey.generate())

    def public_hex(self) -> str:
        return self.private_key.public_key().public_bytes_raw().hex()

    def assertion(self, subject: str, domain: str, claims: dict[str, Any], ttl: int = 300) -> dict[str, Any]:
        if not isinstance(subject, str) or not isinstance(domain, str) or not IDENTITY_RE.fullmatch(subject) or not DOMAIN_RE.fullmatch(domain):
            raise ProtocolError("invalid assertion subject or compartment domain")
        if not isinstance(claims, dict) or len(canonical(claims)) > 16_384 or type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ProtocolError("invalid assertion claims or TTL")
        issued_at = int(time.time())
        document = {
            "protocol": "shadow.identity",
            "version": 1,
            "issuer": self.identity,
            "subject": subject,
            "domain": domain,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl,
            "nonce": os.urandom(16).hex(),
            "claims": claims,
        }
        document["signature"] = self.private_key.sign(canonical(document)).hex()
        return document

    @staticmethod
    def verify(document: dict[str, Any], issuer_public_hex: str, allowed_domains: set[str], now: int | None = None, *, replay_window: "ReplayWindow | None" = None) -> dict[str, Any]:
        required = {"protocol", "version", "issuer", "subject", "domain", "issued_at", "expires_at", "nonce", "claims", "signature"}
        if not isinstance(document, dict) or set(document) != required or document["protocol"] != "shadow.identity" or type(document["version"]) is not int or document["version"] != 1:
            raise ProtocolError("invalid ShadowIdentity schema")
        canonical(document)
        for name in ("issuer", "subject"):
            if not isinstance(document[name], str) or not IDENTITY_RE.fullmatch(document[name]):
                raise ProtocolError("invalid identity name")
        if not isinstance(document["domain"], str) or not DOMAIN_RE.fullmatch(document["domain"]):
            raise ProtocolError("invalid identity domain")
        if type(document["issued_at"]) is not int or type(document["expires_at"]) is not int or not 1 <= document["expires_at"] - document["issued_at"] <= 3600:
            raise ProtocolError("invalid identity validity window")
        if not isinstance(document["claims"], dict) or len(canonical(document["claims"])) > 16_384 or not isinstance(document["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", document["nonce"]):
            raise ProtocolError("invalid identity claims or nonce")
        current = int(time.time()) if now is None else now
        if document["domain"] not in allowed_domains or not document["issued_at"] <= current <= document["expires_at"]:
            raise ProtocolError("identity domain denied or assertion expired")
        unsigned = dict(document)
        try:
            if not isinstance(unsigned["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", unsigned["signature"]):
                raise ValueError("invalid signature encoding")
            if not isinstance(issuer_public_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", issuer_public_hex):
                raise ValueError("invalid key encoding")
            signature = bytes.fromhex(unsigned.pop("signature"))
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_public_hex)).verify(signature, canonical(unsigned))
        except (ValueError, InvalidSignature) as exc:
            raise ProtocolError("invalid ShadowIdentity signature") from exc
        if replay_window is not None:
            replay_window.accept_until(issuer_public_hex + ":" + document["nonce"], document["expires_at"], current)
        return document["claims"]


class ReplayWindow:
    def __init__(self, limit: int = 4096) -> None:
        if type(limit) is not int or not 1 <= limit <= 65_536:
            raise ProtocolError("invalid replay window capacity")
        self.limit = limit
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def accept(self, message_id: str, timestamp: int, now: int) -> None:
        if type(timestamp) is not int or abs(now - timestamp) > 300:
            raise ProtocolError("replayed, stale, or saturated ShadowChat message")
        self.accept_until(message_id, timestamp + 300, now)

    def accept_until(self, message_id: str, expires_at: int, now: int) -> None:
        if not isinstance(message_id, str) or len(message_id) > 256 or type(expires_at) is not int or type(now) is not int or not now <= expires_at <= now + 3600:
            raise ProtocolError("invalid replay key or expiration")
        with self._lock:
            self._seen = {key: value for key, value in self._seen.items() if value >= now}
            if message_id in self._seen or len(self._seen) >= self.limit:
                raise ProtocolError("replayed or saturated message")
            self._seen[message_id] = expires_at


class ShadowChat:
    def __init__(self, session_key: bytes, sender: ShadowIdentity, replay_window: ReplayWindow | None = None) -> None:
        if len(session_key) != 32:
            raise ProtocolError("ShadowChat session key must be 32 bytes")
        self.cipher = ChaCha20Poly1305(session_key)
        self.sender = sender
        self.replay = replay_window or ReplayWindow()

    def encrypt(self, recipient: str, text: str) -> dict[str, Any]:
        if not isinstance(recipient, str) or not IDENTITY_RE.fullmatch(recipient):
            raise ProtocolError("invalid ShadowChat recipient")
        text = normalized_text(text)
        nonce = os.urandom(12)
        metadata = {
            "protocol": "shadow.chat",
            "version": 1,
            "sender": self.sender.identity,
            "recipient": recipient,
            "message_id": os.urandom(16).hex(),
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(nonce).decode(),
        }
        ciphertext = self.cipher.encrypt(nonce, text.encode("utf-8"), canonical(metadata))
        document = {**metadata, "ciphertext": base64.b64encode(ciphertext).decode()}
        document["signature"] = self.sender.private_key.sign(canonical(document)).hex()
        return document

    def decrypt(self, document: dict[str, Any], sender_public_hex: str, now: int | None = None) -> str:
        required = {"protocol", "version", "sender", "recipient", "message_id", "timestamp", "nonce", "ciphertext", "signature"}
        if not isinstance(document, dict) or set(document) != required or document["protocol"] != "shadow.chat" or type(document["version"]) is not int or document["version"] != 1:
            raise ProtocolError("invalid ShadowChat schema")
        canonical(document)
        if document["recipient"] != self.sender.identity:
            raise ProtocolError("ShadowChat recipient does not match local identity")
        if not isinstance(document["sender"], str) or not IDENTITY_RE.fullmatch(document["sender"]) or type(document["timestamp"]) is not int:
            raise ProtocolError("invalid ShadowChat sender or timestamp")
        if not isinstance(document["message_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", document["message_id"]):
            raise ProtocolError("invalid ShadowChat message id")
        unsigned = dict(document)
        try:
            if not isinstance(unsigned["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", unsigned["signature"]):
                raise ValueError("invalid signature encoding")
            if not isinstance(sender_public_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", sender_public_hex):
                raise ValueError("invalid sender key")
            if not isinstance(document["nonce"], str) or len(document["nonce"]) != 16 or not isinstance(document["ciphertext"], str) or len(document["ciphertext"]) > 4 * ((MAX_TEXT + 18) // 3):
                raise ValueError("invalid ciphertext or nonce size")
            signature = bytes.fromhex(unsigned.pop("signature"))
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender_public_hex)).verify(signature, canonical(unsigned))
            nonce = base64.b64decode(document["nonce"], validate=True)
            ciphertext = base64.b64decode(document["ciphertext"], validate=True)
        except (ValueError, InvalidSignature) as exc:
            raise ProtocolError("invalid ShadowChat encoding or signature") from exc
        current = int(time.time()) if now is None else now
        metadata = {key: document[key] for key in ("protocol", "version", "sender", "recipient", "message_id", "timestamp", "nonce")}
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, canonical(metadata)).decode("utf-8")
        except (ValueError, UnicodeDecodeError, InvalidTag) as exc:
            raise ProtocolError("ShadowChat authentication or UTF-8 decoding failed") from exc
        normalized = normalized_text(plaintext)
        if normalized != plaintext:
            raise ProtocolError("ShadowChat plaintext must be NFC")
        # Unauthenticated input must never reserve a replay ID.
        self.replay.accept(sender_public_hex + ":" + document["message_id"], document["timestamp"], current)
        return normalized


def default_factory(identity_key: str | None = None, allowed_domains: set[str] | None = None, *, chat: ShadowChat | None = None, sender_key: str | None = None) -> ProtocolFactory:
    factory = ProtocolFactory()
    if identity_key is not None:
        domains = allowed_domains or set()
        replay = ReplayWindow()
        factory.register("shadow.identity", 1, lambda doc: ShadowIdentity.verify(doc, identity_key, domains, replay_window=replay))
    if (chat is None) != (sender_key is None):
        raise ProtocolError("chat factory requires both receiver and trusted sender key")
    if chat is not None:
        factory.register("shadow.chat", 1, lambda doc: chat.decrypt(doc, sender_key))
    return factory
