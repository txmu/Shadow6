#!/usr/bin/env python3
"""Signed bounded Shadow6 online repository builder, verifier, fetcher and server."""
from __future__ import annotations
import argparse,hashlib,json,os,re,ssl,stat,tempfile,threading,urllib.parse,urllib.request
from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
MAX_INDEX=1_048_576;MAX_PACKAGE=256*1024*1024;MAX_TOTAL_DOWNLOAD=512*1024*1024;MAX_PACKAGES=2048
def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise ValueError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(ValueError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise ValueError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise ValueError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise ValueError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise ValueError("invalid Unicode scalar") from exc
            if size > 65_536 or "\x00" in item:
                raise ValueError("unsafe or oversized JSON string")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise ValueError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise ValueError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise ValueError("JSON document exceeds size limit")
    return encoded


def secure_read(path: Path, limit: int, *, secret: bool = False, dir_fd: int | None = None) -> bytes:
    """Validate the opened inode, not merely the pathname checked earlier."""
    def check(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("file must be bounded and regular")
        if secret:
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("private key must be owner-controlled with mode 0600")
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    check(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        check(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        check(after)
        if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("file grew or changed during read")
        return data
    finally:
        os.close(descriptor)



def regular(path:Path,limit:int)->bytes:
 return secure_read(path,limit)

def _package_name(name):
 if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,239}\.(?:s6pkg|zip|tar\.gz)",name):raise ValueError("invalid portable package name")
 if re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?",name):raise ValueError("reserved package name")
 return name

def _atomic_write(path,data):
 fd,tmp=tempfile.mkstemp(prefix=".repo-",dir=path.parent)
 try:
  with os.fdopen(fd,"wb") as output:output.write(data);output.flush();os.fsync(output.fileno())
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def build(root:Path,output:Path,key_path:Path,signer:str)->dict:
 if not isinstance(signer,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",signer):raise ValueError("invalid signer id")
 packages=[]
 for p in sorted(root.iterdir()):
  if p.is_file() and not p.is_symlink() and (p.suffix in {".zip",".s6pkg"} or p.name.endswith(".tar.gz")):
   _package_name(p.name)
   data=regular(p,MAX_PACKAGE)
   if not data:raise ValueError("empty repository package")
   packages.append({"name":p.name,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()})
   if len(packages)>MAX_PACKAGES:raise ValueError("too many packages")
 if len(packages)>MAX_PACKAGES:raise ValueError("too many packages")
 key=serialization.load_pem_private_key(secure_read(key_path,16384,secret=True),None)
 if not isinstance(key,Ed25519PrivateKey):raise ValueError("repository key must be Ed25519")
 doc={"schema":"shadow6-repository-v1","signer":signer,"packages":packages};doc["signature"]=key.sign(canonical(doc)).hex();data=json.dumps(doc,ensure_ascii=False,indent=2).encode()+b"\n"
 if len(data)>MAX_INDEX:raise ValueError("repository index too large")
 _atomic_write(output,data);return {"index":str(output),"packages":len(packages)}
def verify(data:bytes,trust:Path)->dict:
 if len(data)>MAX_INDEX:raise ValueError("repository index too large")
 doc=strict_json(data,MAX_INDEX);required={"schema","signer","packages","signature"}
 if set(doc)!=required or doc["schema"]!="shadow6-repository-v1" or not isinstance(doc["packages"],list) or len(doc["packages"])>MAX_PACKAGES:raise ValueError("invalid repository index")
 if not isinstance(doc["signer"],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",doc["signer"]) or not isinstance(doc["signature"],str) or not re.fullmatch(r"[0-9a-f]{128}",doc["signature"]):raise ValueError("invalid repository signature fields")
 store=strict_json(regular(trust,65536),65536)
 if set(store) not in ({"signers"},{"schema_version","signers"}) or ("schema_version" in store and (type(store["schema_version"]) is not int or store["schema_version"]!=1)) or not isinstance(store["signers"],dict) or not 1<=len(store["signers"])<=256:raise ValueError("invalid repository trust schema")
 for signer,encoded in store["signers"].items():
  if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",signer) or not isinstance(encoded,str) or not re.fullmatch(r"[0-9a-f]{64}",encoded):raise ValueError("invalid trusted signer")
 encoded=store["signers"].get(doc["signer"])
 if encoded is None:raise ValueError("untrusted repository signer")
 unsigned={k:v for k,v in doc.items() if k!="signature"}
 Ed25519PublicKey.from_public_bytes(bytes.fromhex(encoded)).verify(bytes.fromhex(doc["signature"]),canonical(unsigned))
 seen=set()
 for item in doc["packages"]:
  if not isinstance(item,dict) or set(item)!={"name","size","sha256"} or type(item["size"]) is not int or not 0<item["size"]<=MAX_PACKAGE or not isinstance(item["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",item["sha256"]):raise ValueError("invalid package entry")
  name=_package_name(item["name"])
  if name.casefold() in seen:raise ValueError("duplicate repository package name")
  seen.add(name.casefold())
 return doc
def source_url(value:str)->str:
 if not isinstance(value,str) or len(value)>4096 or any(ord(c)<33 for c in value) or "\\" in value:raise ValueError("invalid repository URL")
 parsed=urllib.parse.urlparse(value)
 if parsed.scheme=="http" and parsed.hostname not in {"127.0.0.1","::1","localhost"}:raise ValueError("remote repositories require HTTPS")
 if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query:raise ValueError("invalid repository URL")
 if parsed.port is not None and not 1<=parsed.port<=65535:raise ValueError("invalid repository port")
 return value.rstrip("/")

class _SafeRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  source_url(newurl)
  if urllib.parse.urlparse(req.full_url).scheme=="https" and urllib.parse.urlparse(newurl).scheme!="https":raise ValueError("HTTPS downgrade redirect rejected")
  return super().redirect_request(req,fp,code,msg,headers,newurl)

def _fetch(url,limit,timeout):
 opener=urllib.request.build_opener(_SafeRedirect())
 with opener.open(url,timeout=timeout) as response:
  payload=response.read(limit+1)
  if len(payload)>limit:raise ValueError("download exceeds size limit")
  return payload
def sync(url:str,trust:Path,destination:Path,names:list[str])->dict:
 base=source_url(url);data=_fetch(base+"/index.json",MAX_INDEX,15);doc=verify(data,trust);wanted=set(names);selected=[x for x in doc["packages"] if not wanted or x["name"] in wanted]
 if wanted-{x["name"] for x in selected}:raise ValueError("requested package is absent from signed index")
 if sum(x["size"] for x in selected)>MAX_TOTAL_DOWNLOAD:raise ValueError("selected packages exceed total download limit")
 if destination.is_symlink():raise ValueError("destination must not be a symlink")
 destination.mkdir(parents=True,exist_ok=True);downloaded=[]
 for item in selected:
  payload=_fetch(base+"/"+urllib.parse.quote(item["name"],safe=""),item["size"],30)
  if len(payload)!=item["size"] or hashlib.sha256(payload).hexdigest()!=item["sha256"]:raise ValueError("download digest mismatch")
  target=destination/item["name"];_atomic_write(target,payload);downloaded.append(str(target))
 return {"source":base,"downloaded":downloaded,"signer":doc["signer"]}
def serve(root:Path,host:str,port:int,cert:Path|None,key:Path|None):
 if host not in {"127.0.0.1","::1","localhost"} and (not cert or not key):raise ValueError("public repository serving requires explicit TLS certificate and key")
 class Handler(SimpleHTTPRequestHandler):
  def __init__(self,*a,**kw):super().__init__(*a,directory=str(root),**kw)
  def log_message(self,fmt,*args):super().log_message(fmt,*args)
 server=ThreadingHTTPServer((host,port),Handler)
 if cert and key:ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);server.socket=ctx.wrap_socket(server.socket,server_side=True)
 server.serve_forever()
def main():
 p=argparse.ArgumentParser();s=p.add_subparsers(dest="command",required=True)
 q=s.add_parser("build");q.add_argument("--root",type=Path,required=True);q.add_argument("--output",type=Path,required=True);q.add_argument("--private-key",type=Path,required=True);q.add_argument("--signer",required=True)
 q=s.add_parser("verify");q.add_argument("--index",type=Path,required=True);q.add_argument("--trust-store",type=Path,required=True)
 q=s.add_parser("sync");q.add_argument("--url",required=True);q.add_argument("--trust-store",type=Path,required=True);q.add_argument("--destination",type=Path,required=True);q.add_argument("--name",action="append",default=[])
 q=s.add_parser("serve");q.add_argument("--root",type=Path,required=True);q.add_argument("--host",default="127.0.0.1");q.add_argument("--port",type=int,default=9470);q.add_argument("--cert",type=Path);q.add_argument("--key",type=Path)
 a=p.parse_args()
 if a.command=="build":result=build(a.root.resolve(strict=True),a.output,a.private_key,a.signer)
 elif a.command=="verify":result=verify(regular(a.index,MAX_INDEX),a.trust_store)
 elif a.command=="sync":result=sync(a.url,a.trust_store,a.destination,a.name)
 else:return serve(a.root.resolve(strict=True),a.host,a.port,a.cert,a.key)
 print(json.dumps(result,ensure_ascii=False,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
