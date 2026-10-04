import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Deployment.core_catalog import CoreCatalog
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write
from Deployment.topology_services import materialize_local_topology


class TopologyServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-topology-services-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = CoreCatalog(Path(__file__).resolve().parents[1])
        binary = self.root / 'fixture-core'
        binary.write_text('#!/bin/false\n')
        binary.chmod(0o700)
        self.catalog._items['go']['executable'] = str(binary)
        self.registry = ServiceRegistry(self.root / 'registry.json', self.catalog)
        self.topology = {'version':'1.0','global':{},'nodes':[
            {'name':'broker','type':'broker','engines':['shadow6-go']},
            {'name':'agent','type':'agent','engines':['shadow6-go']},
            {'name':'client','type':'client','engines':['shadow6-go']}]}
        self.paths = {}
        for role in ('broker','agent','client'):
            path = self.root / (role + '.json')
            atomic_write(path, json.dumps({'core':'go','role':role}).encode())
            self.paths[role] = path
        self.availability = patch('Deployment.topology_services.inspect_profile',
            return_value={'available':True,'diagnostics':[]})
        self.availability.start(); self.addCleanup(self.availability.stop)

    def test_generated_roles_become_locked_services_without_starting(self):
        records = materialize_local_topology(topology=self.topology,
            config_paths=self.paths, namespace='home', catalog=self.catalog,
            registry=self.registry)
        self.assertEqual([item['name'] for item in records],
            ['home/broker','home/agent','home/client'])
        self.assertTrue(all(item['state'] == 'applied' for item in records))
        self.assertEqual([item['protocolContext']['role'] for item in records],
            ['broker','agent','client'])
        self.assertTrue(all(item.get('runtime') is None for item in records))

    def test_failed_batch_removes_every_created_service(self):
        self.paths['client'].chmod(0o644)
        with self.assertRaises(ValueError):
            materialize_local_topology(topology=self.topology,
                config_paths=self.paths, namespace='home', catalog=self.catalog,
                registry=self.registry)
        self.assertEqual(self.registry.list(), [])

    def test_existing_service_is_never_overwritten(self):
        self.registry.create('home/broker', core='go', profile='go-kcp',
            config={'config_path':str(self.paths['broker'])})
        with self.assertRaisesRegex(ValueError, 'explicit stopped service upgrade'):
            materialize_local_topology(topology=self.topology,
                config_paths=self.paths, namespace='home', catalog=self.catalog,
                registry=self.registry)

    def test_remote_topology_is_rejected_for_local_named_service(self):
        self.topology['nodes'][1]['ssh_host'] = '192.0.2.20'
        with self.assertRaisesRegex(ValueError, 'only realize local topology'):
            materialize_local_topology(topology=self.topology,
                config_paths=self.paths, namespace='home', catalog=self.catalog,
                registry=self.registry)


if __name__ == '__main__':
    unittest.main()
