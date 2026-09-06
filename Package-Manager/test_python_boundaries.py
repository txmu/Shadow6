"""Offline regressions for the seven Python security boundaries (no Core builds)."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for directory in ("Plugin-System", "Package-Manager", "Online-Repository", "Migration",
                  "Slot-System", "Application-Layer", "Crosed"):
    sys.path.insert(0, str(ROOT / directory))

import shadow6_pkg as pkg
import shadow6_plugins as plugins
import shadow6_repo as repo
import shadow6_migrate as migrate
import shadow_protocols as protocols
import shadow6_slots as slots
import crosedctl as crosed
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shadow6-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_package_json_rejects_nonportable_and_ambiguous_values(self):
        for data in (b'{"n":NaN}', b'{"n":Infinity}', b'{"n":9007199254740992}',
                     b'{"n":"\\ud800"}', '{"n":1}'.encode("utf-16"),
                     b'{"n":1,"n":2}', b'{"n":' + b'[' * 40 + b'0' + b']' * 40 + b'}'):
            with self.subTest(data=data[:40]), self.assertRaises(pkg.PackageError):
                pkg.strict_json(data)

    def test_portable_archive_paths(self):
        for name in (".", "a//b", "a/./b", "C:/payload", "a:b", "CON", "a/../b", "a\\b"):
            with self.subTest(name=name), self.assertRaises(pkg.PackageError):
                pkg._safe_relative(name)

    def test_package_install_rechecks_bytes_after_verification(self):
        data = b"signed"
        manifest = {"kind": "app", "id": "test-app", "version": "1.0.0", "files": [
            {"path": "data", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "executable": False}]}
        source = mock.Mock()
        source.read.return_value = b"tampered"
        with mock.patch.object(pkg, "verify_package", return_value=(manifest, source)):
            with self.assertRaises(pkg.PackageError):
                pkg.install_package(self.root / "source", self.root / "trust", self.root / "store", False)
        self.assertFalse((self.root / "store/app/test-app/versions/1.0.0").exists())

    def test_package_directory_rejects_symlink_ancestor(self):
        outside = self.root / "outside"; outside.mkdir(); (outside / "data").write_bytes(b"secret")
        source = self.root / "source"; source.mkdir(); (source / "nested").symlink_to(outside)
        package = pkg.PackageSource(source)
        self.addCleanup(package.close)
        with self.assertRaises((pkg.PackageError, OSError)):
            package.read("nested/data")

    def test_secret_key_requires_exact_mode(self):
        key, trust = self.root / "key", self.root / "trust"
        pkg.keygen(key, trust, "owner")
        key.chmod(0o700)
        for read, error in ((pkg._secure_private_key, pkg.PackageError),
                            (crosed.read_owner_only, crosed.CrosedError)):
            with self.subTest(reader=read.__name__), self.assertRaises(error):
                read(key)

    def migration_bundle(self, files):
        source = self.root / "bundle"; source.mkdir()
        entries = []
        for name, data in files:
            path = source / "files" / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            entries.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o600})
        doc = {"format": "shadow6-migration-v1", "version": "1.0", "scopes": ["config"], "files": entries}
        (source / "manifest.json").write_text(json.dumps(doc))
        destination = self.root / "destination"; destination.mkdir()
        return source, destination, doc

    def test_migration_does_not_follow_destination_links(self):
        source, destination, _ = self.migration_bundle([("nested/config.json", b"new")])
        outside = self.root / "outside"; outside.mkdir()
        (destination / "nested").symlink_to(outside)
        with self.assertRaises((migrate.MigrationError, OSError)):
            migrate.import_bundle(source, destination, False)
        self.assertFalse((outside / "config.json").exists())

    def test_migration_validates_all_files_before_first_write(self):
        source, destination, doc = self.migration_bundle([("a.json", b"new"), ("b.json", b"good")])
        (source / "files/b.json").write_bytes(b"bad")
        with self.assertRaises(migrate.MigrationError):
            migrate.import_bundle(source, destination, False)
        self.assertFalse((destination / "a.json").exists())

    def test_migration_duplicate_archive_names(self):
        source, destination, doc = self.migration_bundle([("a.json", b"new")])
        archive = self.root / "duplicate.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("bundle/manifest.json", json.dumps(doc))
            output.writestr("bundle/files/a.json", b"old")
            with __import__("warnings").catch_warnings():
                __import__("warnings").simplefilter("ignore", UserWarning)
                output.writestr("bundle/files/a.json", b"new")
        with self.assertRaises(migrate.MigrationError):
            migrate.import_bundle(archive, destination)

    def test_application_frames_reject_ambiguous_json(self):
        for raw in (b'{"version":1,"version":2}', b'{"value":NaN}', b'{"value":"\\ud800"}',
                    b'{"value":9007199254740992}', '{"value":1}'.encode("utf-16")):
            with self.subTest(raw=raw), self.assertRaises(protocols.ProtocolError):
                protocols.decode_frame(struct.pack(">I", len(raw)) + raw)

    def test_application_factory_rejects_boolean_version(self):
        factory = protocols.ProtocolFactory(); factory.register("shadow.test", 1, lambda doc: doc)
        with self.assertRaises(protocols.ProtocolError):
            factory.decode(protocols.encode_frame({"protocol": "shadow.test", "version": True}))

    def test_default_factory_cannot_accept_unauthenticated_chat(self):
        with self.assertRaises(protocols.ProtocolError):
            protocols.default_factory().decode(protocols.encode_frame({"protocol": "shadow.chat", "version": 1}))

    def test_chat_rejects_wrong_recipient(self):
        key = os.urandom(32); alice = protocols.ShadowIdentity.generate("alice")
        sender = protocols.ShadowChat(key, alice)
        receiver = protocols.ShadowChat(key, protocols.ShadowIdentity.generate("bob"))
        with self.assertRaises(protocols.ProtocolError):
            receiver.decrypt(sender.encrypt("charlie", "private"), alice.public_hex())

    def test_chat_invalid_aead_does_not_consume_replay_id(self):
        key = os.urandom(32); alice = protocols.ShadowIdentity.generate("alice")
        receiver = protocols.ShadowChat(key, protocols.ShadowIdentity.generate("bob"))
        good = protocols.ShadowChat(key, alice).encrypt("bob", "valid")
        bad = protocols.ShadowChat(os.urandom(32), alice).encrypt("bob", "invalid")
        bad["message_id"] = good["message_id"]
        bad.pop("signature")
        bad["signature"] = alice.private_key.sign(protocols.canonical(bad)).hex()
        with self.assertRaises(protocols.ProtocolError):
            receiver.decrypt(bad, alice.public_hex())
        self.assertEqual(receiver.decrypt(good, alice.public_hex()), "valid")

    def test_identity_rejects_excessive_signed_lifetime(self):
        alice = protocols.ShadowIdentity.generate("alice")
        document = alice.assertion("bob", "chat-vm", {})
        document["expires_at"] += 100000; document.pop("signature")
        document["signature"] = alice.private_key.sign(protocols.canonical(document)).hex()
        with self.assertRaises(protocols.ProtocolError):
            protocols.ShadowIdentity.verify(document, alice.public_hex(), {"chat-vm"})

    def test_slot_bindings_reject_duplicate_json(self):
        path = self.root / "bindings.json"
        path.write_bytes(b'{"version":1,"bindings":[],"bindings":[]}'); path.chmod(0o600)
        with self.assertRaises(slots.SlotError):
            slots.load_bindings(path, mock.Mock())

    def test_crosed_rejects_boolean_level_and_nonobject_payload(self):
        key = Ed25519PrivateKey.generate()
        for level, payload in ((True, {}), (1, []), (1, {"bad": float("nan")})):
            with self.subTest(level=level, payload=payload), self.assertRaises(crosed.CrosedError):
                crosed.build_request("mod", level, ["observe.version"], payload, key)


if __name__ == "__main__":
    unittest.main()
