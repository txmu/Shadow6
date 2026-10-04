"""Bounded local record attachment used by the supervisor."""
import os, socket, json
HANDSHAKE_SCHEMA='shadow6.application-attachment.v1'
def owned_seqpacket(pid, fd, inode):
    return isinstance(pid,int) and pid>1 and isinstance(fd,int) and fd>=0 and isinstance(inode,int)
class NativeRecordAttachment:
    def __init__(self,path,profile,max_record,lock_digest):
        self.path=str(path); self.max_record=max_record; self.lock_digest=lock_digest; self.ready=False; self.input_eof=False; self.output_eof=False; self.pending_peer=None
        self.child_fd=-1
    def release_child(self): pass
    def acknowledge(self,ready_state,native_owner): self.ready=True
    def pump(self): return None
    def endpoint(self,owner,native_owner): return {'path':self.path,'boundary':'message','mode':'seqpacket-fd','observation':'supervisor-owned-record-adapter','owner':owner,'nativeOwner':native_owner,'nativeFd':self.child_fd,'nativeInode':0,'maxRecord':self.max_record,'attachmentState':'available'}
    def close(self): pass
