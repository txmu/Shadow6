import json, tempfile, unittest
from pathlib import Path
from Deployment.service_registry import ServiceRegistry

class ServiceLifecycleTests(unittest.TestCase):
    def test_full_idempotent_lifecycle_preserves_core_and_lock(self):
        with tempfile.TemporaryDirectory() as d:
            registry=ServiceRegistry(Path(d)/"services.json")
            registry.init(); config={"config_path":"/tmp/core.json"}
            registry.create("home/nas",core="go",config=config,spec={"endpoint":{"mode":"private"}})
            registry.configure("home/nas",core="go",config=config); registry.apply("home/nas")
            first=registry.run("home/nas"); digest=first["deploymentLock"]["digest"]
            second=registry.run("home/nas")
            self.assertEqual(second["runtime"]["core"],"go"); self.assertEqual(second["deploymentLock"]["digest"],digest)
            restarted=registry.restart("home/nas"); self.assertEqual(restarted["runtime"]["core"],"go")
            self.assertEqual(registry.stop("home/nas")["state"],"stopped")
            self.assertEqual(registry.run("home/nas")["state"],"running")
            registry.remove("home/nas")
            with self.assertRaises(ValueError): registry.inspect("home/nas")

if __name__ == "__main__": unittest.main()
