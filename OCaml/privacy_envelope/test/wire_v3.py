"""Independent test peer for the v3 wire, using the installed libsodium ABI."""
import ctypes as c
import ctypes.util
import hmac
import secrets
import struct

lib = c.CDLL(ctypes.util.find_library('sodium') or 'libsodium.so')
if lib.sodium_init() < 0:
    raise RuntimeError('sodium init failed')
for name, signature in {
    'crypto_secretstream_xchacha20poly1305_statebytes': [],
    'crypto_secretstream_xchacha20poly1305_init_push': [c.c_void_p]*3,
    'crypto_secretstream_xchacha20poly1305_init_pull': [c.c_void_p]*3,
    'crypto_secretstream_xchacha20poly1305_push': [c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_ulonglong,c.c_ubyte],
    'crypto_secretstream_xchacha20poly1305_pull': [c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_ulonglong],
    'crypto_kx_keypair': [c.c_void_p,c.c_void_p],
    'crypto_kx_client_session_keys': [c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p],
    'crypto_aead_xchacha20poly1305_ietf_encrypt': [c.c_void_p,c.c_void_p,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_void_p,c.c_void_p],
    'crypto_aead_xchacha20poly1305_ietf_decrypt': [c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_ulonglong,c.c_void_p,c.c_void_p],
}.items():
    getattr(lib,name).argtypes = signature
    getattr(lib,name).restype = c.c_size_t if name.endswith('statebytes') else c.c_int


def exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part: raise EOFError('truncated wire')
        data += part
    return data


def derive(salt, material, info):
    prk = hmac.digest(salt, material, 'sha256')
    return hmac.digest(prk, info+b'\x01', 'sha256')


class Peer:
    ad = b'S6EPE/3 stream record'
    def __init__(self, sock, key, fragmented=False):
        self.sock = sock
        server = exact(sock,88)
        if server[:8] != b'S6EP3S00': raise ValueError('not v3')
        client_public, client_secret = c.create_string_buffer(32), c.create_string_buffer(32)
        if lib.crypto_kx_keypair(client_public,client_secret) != 0: raise RuntimeError('client keypair')
        client = b'S6EP3C00'+secrets.token_bytes(32)+client_public.raw+b'0000000000000001'
        proof = hmac.digest(key.encode(), b'S6EPE/3 client'+server+client, 'sha256')
        if fragmented:
            for byte in client+proof: sock.sendall(bytes([byte]))
        else: sock.sendall(client+proof)
        expected = hmac.digest(key.encode(), b'S6EPE/3 server'+server+client, 'sha256')
        if not hmac.compare_digest(exact(sock,32), expected): raise ValueError('server proof')
        salt = hmac.digest(key.encode(),server+client,'sha256')
        rx, tx = c.create_string_buffer(32), c.create_string_buffer(32)
        server_public = c.create_string_buffer(server[40:72],32)
        if lib.crypto_kx_client_session_keys(rx,tx,client_public,client_secret,server_public) != 0:
            raise ValueError('server key exchange')
        rx_key, tx_key = derive(salt,rx.raw,b'S6EPE/3 stream'), derive(salt,tx.raw,b'S6EPE/3 stream')
        c.memset(client_secret,0,32)
        self.tx = c.create_string_buffer(lib.crypto_secretstream_xchacha20poly1305_statebytes())
        self.rx = c.create_string_buffer(lib.crypto_secretstream_xchacha20poly1305_statebytes())
        header = c.create_string_buffer(24)
        assert lib.crypto_secretstream_xchacha20poly1305_init_push(self.tx,header,tx_key) == 0
        sock.sendall(header.raw)
        assert lib.crypto_secretstream_xchacha20poly1305_init_pull(self.rx,exact(sock,24),rx_key) == 0

    def send(self, payload, tag=0):
        payload = payload if tag == 3 else b'\x00'+struct.pack('!I',len(payload))+payload
        output = c.create_string_buffer(len(payload)+17)
        assert lib.crypto_secretstream_xchacha20poly1305_push(self.tx,output,None,payload,len(payload),self.ad,len(self.ad),tag) == 0
        packet=struct.pack('!I',len(output.raw))+output.raw
        self.sock.sendall(packet)
        return packet

    def receive(self):
        size, = struct.unpack('!I',exact(self.sock,4))
        self.last_record_size=size
        if not 17 <= size <= 131072: raise ValueError('record bound')
        cipher = exact(self.sock,size)
        plain = c.create_string_buffer(max(1,size-17)); tag = c.c_ubyte()
        if lib.crypto_secretstream_xchacha20poly1305_pull(self.rx,plain,None,c.byref(tag),cipher,size,self.ad,len(self.ad)) != 0:
            raise ValueError('record auth')
        data=plain.raw[:size-17]
        if tag.value==3:return data,tag.value
        if len(data)<5:raise ValueError('inner record')
        payload_size,=struct.unpack('!I',data[1:5])
        if payload_size>len(data)-5:raise ValueError('inner size')
        if data[0]==1:return b'',1
        if data[0]!=0:raise ValueError('inner type')
        return data[5:5+payload_size],tag.value


def capsule(key, direction, payload, stamp, nonce=None):
    nonce = nonce or secrets.token_bytes(24)
    header = b'S6EP3D00'+f'{stamp:016x}'.encode()+b'0000000000000001'+nonce
    derived = derive(key.encode(), direction, b'S6EPE/3 datagram')
    ad = direction+header
    cipher = c.create_string_buffer(len(payload)+16)
    assert lib.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher,None,payload,len(payload),ad,len(ad),None,nonce,derived) == 0
    return header+cipher.raw


def open_capsule(key, direction, packet):
    header, cipher = packet[:64], packet[64:]
    derived = derive(key.encode(),direction,b'S6EPE/3 datagram')
    ad = direction+header
    plain = c.create_string_buffer(max(1,len(cipher)-16))
    if lib.crypto_aead_xchacha20poly1305_ietf_decrypt(plain,None,None,cipher,len(cipher),ad,len(ad),header[40:],derived) != 0:
        raise ValueError('capsule auth')
    return plain.raw[:len(cipher)-16]
