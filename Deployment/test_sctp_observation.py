"""Native SCTP listener facts and envelope admission; no Core wire parsing."""
import os
import socket
import subprocess
import sys
import unittest
from Deployment import runtime_observation as observation, service_runtime
from Deployment.broker_set import endpoint


class SCTPObservationTests(unittest.TestCase):
    def socket(self):
        if not sys.platform.startswith('linux'):
            self.skipTest('Linux SCTP socket observation unavailable')
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM,132)
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1',0))
        return listener

    def test_owned_listener_and_transport_are_actual_facts(self):
        listener=self.socket();port=listener.getsockname()[1]
        self.assertFalse(any(e.get('port')==port and e['transport']=='sctp' for e in observation.sockets(os.getpid())))
        listener.listen(1)
        expected={'host':'127.0.0.1','port':port,'transport':'sctp','observation':'process-owned-socket'}
        self.assertIn(expected,observation.sockets(os.getpid()))
        target=endpoint(f'127.0.0.1:{port}')
        self.assertFalse(observation.endpoint_matches(expected,target))
        self.assertTrue(observation.endpoint_matches(expected,target,transport='sctp'))
        listener.close()
        self.assertNotIn(expected,observation.sockets(os.getpid()))

    def test_foreign_process_socket_does_not_prove_ownership(self):
        # Ensure kernel support before launching a bounded local fixture.
        self.socket()
        code="import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,132); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1],flush=True); time.sleep(5)"
        child=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,text=True)
        try:
            port=int(child.stdout.readline())
            expected={'host':'127.0.0.1','port':port,'transport':'sctp','observation':'process-owned-socket'}
            self.assertIn(expected,observation.sockets(child.pid))
            self.assertNotIn(expected,observation.sockets(os.getpid()))
        finally:
            child.terminate();child.wait(timeout=3);child.stdout.close()

    def test_socket_budget_includes_sctp_listeners(self):
        from unittest.mock import patch
        listener=self.socket();listener.listen(1)
        with patch.object(observation,'MAX_SOCKETS',0):
            with self.assertRaisesRegex(ValueError,'listener observation limit'):
                observation.sockets(os.getpid())

    def test_sctp_config_is_explicit_bounded_and_rejects_tls(self):
        fields={'role':'server','mode':'message','carrier':'sctp','listen':'127.0.0.1:19343',
                'upstream':'127.0.0.1:19344','auth_key':'test-only-key-0123456789',
                'message_channels':'0:ordered:reliable,1:unordered:retransmits:0','sctp_streams':'4'}
        self.assertEqual(service_runtime.validate_envelope(fields),fields)
        self.assertEqual(service_runtime.envelope_tls_material(fields),{})
        for override in ({'carrier':'raw'},{'mode':'stream'},{'sctp_streams':'65'},
                         {'message_channels':'0:unordered:reliable'},
                         {'message_channels':'0:ordered:reliable,0:ordered:reliable'},
                         {'message_channels':'0:ordered:reliable,4:ordered:reliable'},
                         {'message_channels':'0:ordered:reliable,1:unordered:lifetime:60001'},
                         {'tls_peer_name':'unexpected'},{'upstream':'unix:/tmp/sctp'}):
            with self.subTest(override=override),self.assertRaises(ValueError):
                service_runtime.validate_envelope({**fields,**override})

    def test_datagram_admission_requires_private_persistent_replay_state(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='shadow6-dgram-admission-') as directory:
            root=Path(directory);root.chmod(0o700)
            fields={'role':'server','mode':'datagram','listen':'127.0.0.1:19345',
                    'upstream':'127.0.0.1:19346','auth_key':'test-only-key-0123456789',
                    'replay_path':str(root/'replay.state')}
            self.assertEqual(service_runtime.validate_envelope(fields),fields)
            with self.assertRaisesRegex(ValueError,'persistent replay_path'):
                service_runtime.validate_envelope({k:v for k,v in fields.items() if k!='replay_path'})
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'private and owner-controlled'):
                service_runtime.validate_envelope(fields)
            root.chmod(0o700)
            state=root/'replay.state';state.write_bytes(b'S6EPE-REPLAY-1 0000000000000001\n')
            state.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'private'):
                service_runtime.validate_envelope(fields)
            state.chmod(0o600)
            state.unlink();state.symlink_to(root/'missing-target')
            with self.assertRaisesRegex(ValueError,'private'):
                service_runtime.validate_envelope(fields)
            stream={**fields,'mode':'stream','replay_path':str(root/'replay.state')}
            with self.assertRaisesRegex(ValueError,'datagram-only'):
                service_runtime.validate_envelope(stream)


if __name__=='__main__':unittest.main()
