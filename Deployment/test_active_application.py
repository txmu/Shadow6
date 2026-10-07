"""An accepted owned application flow is distinct from a reusable listener."""
import copy
import os
import socket
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from Deployment.runtime_observation import validate_observation
from Deployment.service_runtime import native_observed_endpoints
from Deployment.service_registry import ServiceRegistry
from Deployment.core_catalog import CoreCatalog


class ActiveApplicationTests(unittest.TestCase):
    def test_real_owned_connection_survives_listener_close_and_expires_on_socket_close(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            port = listener.getsockname()[1]
            boundary = {'host': '127.0.0.1', 'port': port, 'boundary': 'stream', 'mode': 'localhost-tcp-proxy'}
            with socket.create_connection(('127.0.0.1', port)) as client:
                server, _ = listener.accept()
                with server:
                    before = native_observed_endpoints(os.getpid(), {'role': 'client'}, boundary)
                    self.assertFalse(any(e['observation'] == 'process-owned-application-connection' for e in before))
                    listener.close()
                    active = native_observed_endpoints(os.getpid(), {'role': 'client'}, boundary)
                    matched = [e for e in active if e['observation'] == 'process-owned-application-connection']
                    self.assertEqual(len(matched), 1)
                    self.assertEqual(matched[0]['remotePort'], client.getsockname()[1])
            after = native_observed_endpoints(os.getpid(), {'role': 'client'}, boundary)
            self.assertFalse(any(e['observation'] == 'process-owned-application-connection' for e in after))

    def test_active_observation_requires_exact_private_flow_tuple_and_owner(self):
        identity = 'a' * 8 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 12 + ':123'
        owner = {'pid': 42, 'processIdentity': identity}
        flow = {'host': '127.0.0.1', 'port': 12345, 'remoteHost': '127.0.0.1',
                'remotePort': 23456, 'transport': 'tcp', 'observation': 'process-owned-application-connection'}
        endpoint = {key: flow[key] for key in ('host', 'port', 'remoteHost', 'remotePort')}
        endpoint.update(boundary='stream', mode='localhost-tcp-proxy',
                        observation='structured-ready-active-flow', owner=owner)
        value = {'observedAt': 1, 'pid': 43, 'processIdentity': identity, 'processes': [owner],
                 'nativeEndpoints': [flow], 'endpoints': [flow], 'endpoint': endpoint,
                 'readiness': 'application-active', 'transportReadiness': 'unknown', 'applicationReadiness': 'ready'}
        self.assertEqual(validate_observation(value)['readiness'], 'application-active')
        for field, replacement in (('remotePort', 34567), ('remoteHost', '192.0.2.1'),
                                   ('owner', {'pid': 44, 'processIdentity': identity})):
            invalid = copy.deepcopy(value)
            invalid['endpoint'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): validate_observation(invalid)
        invalid = copy.deepcopy(value); invalid['nativeEndpoints'] = []
        with self.assertRaises(ValueError): validate_observation(invalid)

    def test_active_attachment_rejects_a_second_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ServiceRegistry(root / 'services.json', CoreCatalog(descriptor_path=root / 'cores.json'))
            with patch.object(registry, 'connection_inputs', return_value=({'runtime': {'readiness': 'application-active'}}, {})):
                with self.assertRaisesRegex(ValueError, 'ApplicationBoundaryBusy'):
                    registry.connect('lab/client')


if __name__ == '__main__': unittest.main()
