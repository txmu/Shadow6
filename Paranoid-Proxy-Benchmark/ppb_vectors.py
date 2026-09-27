"""Independent named adversarial cases derived from Shadow6 security contracts."""
import unittest
from shadow6_network import ReliableAdapter, PROFILES
from shadow_protocols import strict_json, decode_frame, encode_frame, ProtocolError
from native_config import validate

class Vectors(unittest.TestCase):
    pass

def tamper(profile, offset):
    def case(self):
        sender = ReliableAdapter(profile, bytes(range(32)), 0)
        receiver = ReliableAdapter(profile, bytes(range(32)), 1)
        frame = bytearray(sender.send(0, b'authenticated-data')[0])
        frame[offset] ^= 1
        with self.assertRaises(ValueError): receiver.receive(bytes(frame))
        self.assertFalse(receiver.incoming)
        self.assertEqual(receiver.incoming_bytes, 0)
    return case

# Every header byte plus ciphertext and tag; all 12 families and Micro-Mux.
for profile in PROFILES:
    for offset in (*range(28), -17, -1):
        setattr(Vectors, f'test_{profile.replace("-", "_")}_tamper_{offset % 100}', tamper(profile, offset))

def malformed_json(data):
    def case(self):
        with self.assertRaises((ValueError, ProtocolError)): strict_json(data)
    return case

for index, data in enumerate((b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
        b'{"a":1.5}', b'{"a":1e100}', b'{"a":"\xff"}', b'{}{}', b'{', b'[]')):
    setattr(Vectors, f'test_strict_json_{index}', malformed_json(data))

def truncated(size):
    def case(self):
        frame = encode_frame({'protocol':'shadow.test','version':1,'value':'中文'})
        with self.assertRaises(ProtocolError): decode_frame(frame[:size])
    return case
for size in range(16):
    setattr(Vectors, f'test_truncated_frame_{size}', truncated(size))

def config_unknown(core):
    def case(self):
        with self.assertRaises(ValueError): validate({'core':core, 'role':'client', 'listen_port':41000, 'command':'forbidden'})
    return case
for core in ('hare','pony','carp','idris'):
    setattr(Vectors, 'test_native_unknown_fields_' + core, config_unknown(core))

from shadow_protocols import ReplayWindow
from shadow6_network import Limits

def state_contract(profile, scenario):
    def case(self):
        now = [0.0]
        key = bytes(range(32))
        limits = Limits(max_message=4096, max_inflight=4096, payload_bytes=64, window_frames=8)
        left = ReliableAdapter(profile, key, 0, clock=lambda:now[0], limits=limits)
        right = ReliableAdapter(profile, key, 1, clock=lambda:now[0], limits=limits)
        if scenario == 'wrong-key':
            wrong = ReliableAdapter(profile, bytes(32), 1, limits=limits)
            with self.assertRaises(ValueError): wrong.receive(left.send(0,b'key-bound')[0])
        elif scenario == 'reflection':
            with self.assertRaises(ValueError): left.receive(left.send(0,b'direction-bound')[0])
        elif scenario == 'backpressure':
            left.send(0,b'x'*4096)
            with self.assertRaises(BufferError): left.send(1,b'x')
            self.assertEqual(left.buffered,4096)
        else:
            frames = left.send(0,b'x'*400)
            delivered = []
            lost = frames[0]
            for frame in reversed(frames[1:]):
                for _ in range(2):
                    acks, messages, _ = right.receive(frame)
                    delivered.extend(messages)
                    for ack in acks: left.receive(ack)
            self.assertFalse(delivered)
            now[0] = 1
            for frame in left.retransmit():
                acks,messages,_ = right.receive(frame); delivered.extend(messages)
                for ack in acks: left.receive(ack)
            self.assertEqual(delivered,[(0,b'x'*400)])
            self.assertEqual(left.buffered,0)
            self.assertFalse(right.receive(lost)[1])
    return case
for profile in PROFILES:
    for scenario in ('wrong-key','reflection','backpressure','loss-reorder-duplicate-ack'):
        setattr(Vectors, f'test_{profile.replace("-","_")}_{scenario.replace("-","_")}', state_contract(profile,scenario))

class ReplayVectors(unittest.TestCase):
    def test_saturation_does_not_evict_live_replay_ids(self):
        window = ReplayWindow(2)
        window.accept_until('a',110,100); window.accept_until('b',110,100)
        with self.assertRaises(ProtocolError): window.accept_until('c',110,100)
        with self.assertRaises(ProtocolError): window.accept_until('a',110,100)
        window.accept_until('c',120,111)
    def test_stale_and_future_timestamp_rejected(self):
        for timestamp in (-301,301):
            with self.subTest(timestamp=timestamp), self.assertRaises(ProtocolError):
                ReplayWindow().accept('id',timestamp,0)

from shadow_protocols import ShadowIdentity
from native_config import secure_read, write_new, topology_configs, ROLES
import os
from pathlib import Path
import tempfile

class IdentityVectors(unittest.TestCase):
    def test_valid_signature_does_not_override_expiry_or_domain(self):
        issuer = ShadowIdentity.generate('issuer')
        assertion = issuer.assertion('subject','work',{'role':'reader'},ttl=30)
        for now, domains in ((assertion['issued_at']-1,{'work'}),
                (assertion['expires_at']+1,{'work'}), (assertion['issued_at'],{'vault'})):
            with self.subTest(now=now,domains=domains), self.assertRaises(ProtocolError):
                ShadowIdentity.verify(assertion,issuer.public_hex(),domains,now=now)
    def test_signed_claims_replay_and_wrong_issuer(self):
        issuer = ShadowIdentity.generate('issuer')
        assertion = issuer.assertion('subject','work',{'role':'reader'})
        replay = ReplayWindow()
        ShadowIdentity.verify(assertion,issuer.public_hex(),{'work'},replay_window=replay)
        with self.assertRaises(ProtocolError):
            ShadowIdentity.verify(assertion,issuer.public_hex(),{'work'},replay_window=replay)
        with self.assertRaises(ProtocolError):
            ShadowIdentity.verify(assertion,ShadowIdentity.generate('other').public_hex(),{'work'})
        for field,value in (('subject','other'),('domain','vault'),('claims',{'role':'admin'}),('nonce','00'*16)):
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                ShadowIdentity.verify(dict(assertion,**{field:value}),issuer.public_hex(),{'work','vault'})

class NativeInputVectors(unittest.TestCase):
    def test_valid_config_then_single_field_mutations(self):
        for core in ('hare','pony','carp','idris'):
            topo = {'nodes':[{'name':role,'type':role,'engines':['shadow6-'+core]} for role in ROLES]}
            keys = {role:(str(i)*64,str(i+3)*64) for i,role in enumerate(ROLES,1)}
            config = topology_configs(topo,keys,'ab'*32)['client']
            validate(config)
            for patch in ({'listen_port':True},{'listen_port':1.5},{'listen_port':65536},
                          {'listen_port':0},{'command':'forbidden'},{'role':'unknown'}):
                with self.subTest(core=core,patch=patch), self.assertRaises(ValueError):
                    validate(dict(config,**patch))
    @unittest.skipIf(os.name == 'nt','POSIX owner/mode/symlink contract')
    def test_secret_file_mode_symlink_size_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'secret'; write_new(path,b'private')
            self.assertEqual(secure_read(path),b'private')
            with self.assertRaises(FileExistsError): write_new(path,b'overwrite')
            with self.assertRaises(ValueError): secure_read(path,3)
            link = Path(directory)/'link'; link.symlink_to(path)
            with self.assertRaises((ValueError,OSError)): secure_read(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError): secure_read(path)
