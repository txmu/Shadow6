"""Bounded persistent loopback control client. Never carries application data."""
import http.client
import json
import threading
from pathlib import Path
from .boundary import ConnectionError
from Deployment.service_storage import private_read, strict_json


class ControlClient:
    def __init__(self, token_file, *, port=9466, timeout=15):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('invalid loopback Control Center port')
        if type(timeout) not in (int,float) or not 0 < timeout <= 30:
            raise ValueError('invalid control timeout')
        token = private_read(Path(token_file), limit=4096).decode('ascii').strip()
        if not 32 <= len(token) <= 4096 or any(not 33 <= ord(char) <= 126 for char in token):
            raise ValueError('invalid backend credential')
        self._authorization = 'Bearer '+token
        self._connection = http.client.HTTPConnection('127.0.0.1',port,timeout=timeout)
        self._lock = threading.RLock()
        self._closed = False

    def call(self, method, params):
        if not isinstance(method,str) or not 1 <= len(method) <= 128 or not isinstance(params,dict):
            raise ValueError('invalid control operation')
        raw = json.dumps({'method':method,'params':params},ensure_ascii=True,
                         allow_nan=False,separators=(',',':')).encode()
        if len(raw) > 65536: raise ConnectionError('ControlRequestTooLarge')
        with self._lock:
            if self._closed: raise ConnectionError('ControlClientClosed')
            try:
                self._connection.request('POST','/v1/rpc',body=raw,
                    headers={'Authorization':self._authorization,'Content-Type':'application/json'})
                response = self._connection.getresponse()
                payload = response.read(1048577)
                if len(payload) > 1048576:
                    raise ConnectionError('ControlResponseTooLarge')
                result = strict_json(payload)
                if not isinstance(result,dict) or set(result) - {'id','ok','result','error'}:
                    raise ConnectionError('InvalidControlResponse')
                if response.status != 200 or result.get('ok') is not True:
                    code = (result.get('error') or {}).get('code','ControlRequestRejected')
                    if not isinstance(code,str) or not code.isascii() or not code.isalpha() or len(code)>96:
                        code = 'ControlRequestRejected'
                    raise ConnectionError(code)
                return result['result']
            except (OSError,http.client.HTTPException):
                self._connection.close()
                # Mutations and stale reviewed operations are never retried.
                raise ConnectionError('ControlCenterUnavailable',retryable=True) from None
            except (ValueError,KeyError):
                self._connection.close()
                raise ConnectionError('InvalidControlResponse') from None

    def close(self):
        with self._lock:
            self._closed = True
            self._connection.close()
            self._authorization = ''

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class RegistryControl:
    """Read-only in-process bridge to an existing canonical ServiceRegistry.

    Useful for embedded operator tooling and Test Lab. Lifecycle writes remain
    on Control Center/CLI; this adapter does not create a second registry.
    """
    def __init__(self, registry):
        self._registry = registry
        self._lock = threading.RLock()

    def call(self, method, params):
        methods = {'service.connect':self._registry.connect,
                   'service.status':self._registry.status,
                   'service.connection_review':self._registry.connection_review}
        if method not in methods or set(params) != {'name'}:
            raise ConnectionError('UnsupportedControlOperation')
        with self._lock:
            return methods[method](params['name'])
