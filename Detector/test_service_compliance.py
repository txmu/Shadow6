"""Real-Core compliance integration; requires the ordinary Go build artifact."""
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Deployment.core_catalog import CoreCatalog
from Deployment.protocol_context import minimal_context
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write
from service_compliance import verify_named_service

ROOT = Path(__file__).resolve().parents[1]


class ServiceComplianceIntegrationTests(unittest.TestCase):
    def test_real_go_broker_compares_intent_lock_claim_and_owned_listener(self):
        binary = ROOT / "Core-Go/shadow6-go"
        if not binary.is_file():
            self.skipTest("ordinary Go build artifact unavailable")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

        with tempfile.TemporaryDirectory(prefix="shadow6-detector-compliance-") as directory:
            root = Path(directory)
            config = root / "broker.json"
            registry_path = root / "services.json"
            key = Ed25519PrivateKey.generate()
            private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            with socket.socket(type=socket.SOCK_DGRAM) as reserve:
                reserve.bind(("127.0.0.1", 0))
                address = f"127.0.0.1:{reserve.getsockname()[1]}"
            native = {"role": "broker", "broker": {"listen_addr": address,
                      "private_key": (private + public).hex(), "agents": [], "clients": [],
                      "webhook_url": "", "stealth_mode": False}}
            atomic_write(config, json.dumps(native, separators=(",", ":")).encode())
            catalog = CoreCatalog(ROOT)
            catalog._items["go"]["executable"] = str(binary)
            registry = ServiceRegistry(registry_path, catalog)
            context = minimal_context("go")
            context["role"] = "broker"
            registry.create("verify/broker", core="go", config={"config_path": str(config)}, context=context)
            try:
                registry.apply("verify/broker")
                actual = registry.run("verify/broker")
                self.assertEqual(actual["state"], "running")
                doctor = registry.doctor("verify/broker")
                self.assertTrue(doctor["healthy"], doctor["findings"])
                self.assertTrue(doctor["lockValid"])
                self.assertEqual(doctor["profileBinding"]["profile"], "go-kcp")
                result = verify_named_service("verify/broker", registry=registry)
                self.assertTrue(result["compliant"], result["findings"])
                self.assertEqual(result["evidence"]["intent"], "S6P1")
                self.assertEqual(result["evidence"]["capability"], "feature-report")
                self.assertEqual(result["evidence"]["realization"], "DeploymentLock")
                self.assertEqual(result["evidence"]["observed"], "OS-process-and-socket")
                self.assertTrue(result["evidence"]["ownedEndpoints"], result)
                port = int(address.rsplit(":", 1)[1])
                self.assertTrue(any(item.get("port") == port for item in result["evidence"]["ownedEndpoints"]))
                plan_path, _ = registry.launch_plan("verify/broker")
                runner = ROOT / "Service-Init/shadow6_service_runner.py"
                checked = subprocess.run(
                    [sys.executable, str(runner), "--config", str(plan_path), "--check-config"],
                    capture_output=True, timeout=5)
                self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors="replace"))
            finally:
                registry.stop("verify/broker")


if __name__ == "__main__":
    unittest.main()
