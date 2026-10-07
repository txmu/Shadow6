"""Python ownership wrapper for the existing C application ABI, no packet RPC."""
import ctypes
import os
from pathlib import Path
import socket
import stat
import tempfile
from threading import Event, Thread
from Deployment.service_storage import strict_json
from .boundary import ConnectionError


class _Options(ctypes.Structure):
    _fields_=[('abi_version',ctypes.c_uint32),('timeout_ms',ctypes.c_uint32),('cancel_fd',ctypes.c_int)]


class _Error(ctypes.Structure):
    _fields_=[('abi_version',ctypes.c_uint32),('code',ctypes.c_char*96)]


class NativeAttachment:
    def __init__(self,library,handle,connection,snapshot):self.library,self.handle,self.socket,self.snapshot=library,handle,connection,snapshot
    def close(self):
        if self.handle is None:return
        self.socket.close();self.library.s6_connection_destroy(self.handle);self.handle=None;self.snapshot.cleanup()


def open_native(name,*,timeout,cancellation=None):
    path=Path(os.environ['SHADOW6_APPLICATION_LIBRARY'])
    info=path.lstat()
    if (not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or
            info.st_uid not in {0,os.geteuid()} or info.st_mode&0o022 or info.st_size>16*1024*1024):
        raise ConnectionError('UnsafeApplicationLibrary')
    source=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    snapshot=tempfile.TemporaryDirectory(prefix='shadow6-application-abi-')
    try:
        fingerprint=lambda item:(item.st_dev,item.st_ino,item.st_uid,item.st_mode,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        if fingerprint(info)!=fingerprint(os.fstat(source)):raise ConnectionError('ApplicationLibraryChanged')
        copied=Path(snapshot.name)/'libshadow6.so'
        target=os.open(copied,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o500)
        with os.fdopen(target,'wb') as stream:
            remaining=info.st_size
            while remaining:
                chunk=os.read(source,min(65536,remaining))
                if not chunk:raise ConnectionError('ApplicationLibraryChanged')
                stream.write(chunk);remaining-=len(chunk)
        if fingerprint(info)!=fingerprint(os.fstat(source)) or fingerprint(info)!=fingerprint(path.lstat()):
            raise ConnectionError('ApplicationLibraryChanged')
        library=ctypes.CDLL(str(copied))
    except BaseException:
        snapshot.cleanup();raise
    finally:os.close(source)
    library.s6_application_abi.restype=ctypes.c_uint32
    if library.s6_application_abi()!=1:raise ConnectionError('UnsupportedApplicationABI')
    library.s6_connection_open_with_options.argtypes=[ctypes.c_uint32,ctypes.c_char_p,ctypes.POINTER(_Options),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(_Error)]
    library.s6_connection_dup_fd.argtypes=[ctypes.c_void_p];library.s6_connection_dup_fd.restype=ctypes.c_int
    library.s6_connection_descriptor.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    library.s6_connection_destroy.argtypes=[ctypes.c_void_p]
    handle=ctypes.c_void_p();error=_Error();read_fd=write_fd=-1;watcher=None;stop=Event();fd=-1
    try:
        if cancellation is not None:
            read_fd,write_fd=os.pipe()
            def watch():
                while not stop.wait(.01):
                    if cancellation.is_set():
                        try:os.write(write_fd,b'cancel')
                        except OSError:pass
                        return
            watcher=Thread(target=watch,name='shadow6-connect-cancel',daemon=True);watcher.start()
            if cancellation.is_set():raise ConnectionError('ConnectionCancelled',state='cancelled')
        options=_Options(1,max(1,min(30000,int(timeout*1000))),read_fd)
        if library.s6_connection_open_with_options(1,name.encode('utf-8'),ctypes.byref(options),ctypes.byref(handle),ctypes.byref(error)):
            code=error.code.decode('ascii','strict')
            if not code.isalpha() or len(code)>96:code='ConnectionRejected'
            raise ConnectionError(code,state='cancelled' if code=='ConnectionCancelled' else 'failed',retryable=code in {'ConnectionTimedOut','FDControlUnavailable'})
        required=ctypes.c_size_t()
        if library.s6_connection_descriptor(handle,None,0,ctypes.byref(required))!=-2 or not 1<=required.value<=65537:
            raise ConnectionError('InvalidApplicationDescriptor')
        buffer=ctypes.create_string_buffer(required.value)
        if library.s6_connection_descriptor(handle,buffer,len(buffer),ctypes.byref(required)):
            raise ConnectionError('InvalidApplicationDescriptor')
        metadata=strict_json(buffer.value,limit=65536)
        fd=library.s6_connection_dup_fd(handle)
        if fd<0:raise ConnectionError('ResourceUnavailable')
        connection=socket.socket(fileno=fd);fd=-1;connection.set_inheritable(False)
        result=NativeAttachment(library,handle,connection,snapshot);handle=None;snapshot=None
        return result,metadata
    finally:
        stop.set()
        if watcher is not None:watcher.join(.2)
        if read_fd>=0:os.close(read_fd)
        if write_fd>=0:os.close(write_fd)
        if handle:library.s6_connection_destroy(handle)
        if fd>=0:os.close(fd)
        if snapshot is not None:snapshot.cleanup()
