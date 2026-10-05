import json
import tempfile
import unittest
from pathlib import Path

from Deployment.core_catalog import CoreCatalog
from Deployment.service_registry import ServiceRegistry


class CoreExplicitTests(unittest.TestCase):
    def test_catalog_has_all_builtin_descriptors_and_schemas(self):
        catalog = CoreCatalog()
        self.assertEqual(len(catalog.list()), 12)
        for item in catalog.list():
            self.assertEqual(item["configurationSchema"]["core"], item["id"])
            self.assertTrue(item["configurationSchema"]["fields"])

    def test_invalid_config_is_rejected(self):
        with self.assertRaises(ValueError):
            CoreCatalog().binding("go", {})

    def test_single_candidate_requires_selection_but_recorded_binding_is_reused(self):
        from Deployment.connection_plan import resolve_connection
        from Deployment.protocol_context import minimal_context
        catalog = CoreCatalog()
        catalog._items = {'go': catalog.inspect('go')}
        self.assertTrue(catalog.resolve({})['bindingRequired'])
        context = minimal_context('go')
        with self.assertRaisesRegex(ValueError, '^CoreSelectionRequired$'):
            resolve_connection(context=context, catalog=catalog)
        binding = catalog.binding('go', {'config_path': '/tmp/go.json'})
        self.assertEqual(resolve_connection(context=context, catalog=catalog, binding=binding)['core'], 'go')

    def test_reconfiguration_without_selection_preserves_record(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = ServiceRegistry(Path(directory) / 'services.json')
            original = registry.create('home/nas', core='go', config={'config_path': '/tmp/go.json'})
            for operation in (registry.configure, registry.upgrade):
                with self.assertRaisesRegex(ValueError, '^CoreSelectionRequired$'):
                    operation('home/nas', core=None, config={})
                self.assertEqual(registry.inspect('home/nas'), original)

    def test_imported_descriptor_is_explicit_and_resolvable(self):
        catalog = CoreCatalog()
        descriptor = catalog.inspect("go").copy()
        descriptor.update({"id": "vendor-x", "source": "imported"})
        descriptor["configurationSchema"] = json.loads(json.dumps(descriptor["configurationSchema"]))
        descriptor["configurationSchema"]["core"] = "vendor-x"
        catalog.register(descriptor)
        self.assertEqual(catalog.inspect("vendor-x")["source"], "imported")

    def test_named_service_requires_explicit_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = ServiceRegistry(Path(directory) / "services.json")
            with self.assertRaisesRegex(ValueError, '^CoreSelectionRequired$'):
                registry.create("home/nas", core=None, config=None)
            self.assertEqual(registry.list(), [])
            registry.create("home/nas", core="go", config={"config_path":"/tmp/go.json"})
            self.assertEqual(registry.require_binding("home/nas")["core"], "go")


if __name__ == "__main__":
    unittest.main()
