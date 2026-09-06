#!/usr/bin/env python3
"""Bounded, manifest-driven Shadow6 migration CLI; never executes imported content."""
from __future__ import annotations
import argparse, gzip, hashlib, io, json, os, re, shutil, stat, tarfile, tempfile, zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

VERSION="1.0"; MAX_FILES=4096; MAX_FILE=64*1024*1024; MAX_TOTAL=512*1024*1024
SCOPES={
 "config": ("config.mk","*.json","Service-Init/*.service"),
 "gate": ("Gate/*.json","Gate/*.example.json"),
 "plugins": ("plugins/*/plugin.json","plugins/*/manifest.json","Plugin-System/trusted_signers.json"),
 "state": ("Auto-Orchestrator/generated/*.json",),
 "identities": ("*.key","*.pub","*.pem"),
}
class MigrationError(ValueError): pass
def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MigrationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise MigrationError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(MigrationError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise MigrationError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise MigrationError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise MigrationError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise MigrationError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise MigrationError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise MigrationError("invalid Unicode scalar") from exc
            if size > 65_536 or "\x00" in item:
                raise MigrationError("unsafe or oversized JSON string")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise MigrationError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise MigrationError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise MigrationError("JSON document exceeds size limit")
    return encoded


def secure_read(path: Path, limit: int, *, secret: bool = False, dir_fd: int | None = None) -> bytes:
    """Validate the opened inode, not merely the pathname checked earlier."""
    def check(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise MigrationError("file must be bounded and regular")
        if secret:
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise MigrationError("private key must be owner-controlled with mode 0600")
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    check(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        check(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise MigrationError("file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        check(after)
        if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MigrationError("file grew or changed during read")
        return data
    finally:
        os.close(descriptor)


@contextmanager
def directory_fd(root: Path, parts: tuple[str, ...] = (), *, create: bool = False):
    """Walk below a caller-selected root using no-follow directory descriptors."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if root.is_symlink():
        raise MigrationError("directory must not be a symlink")
    descriptor = os.open(root, flags)
    try:
        for part in (None, *parts):
            if part is not None:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise MigrationError("directory must be owner-controlled and not group/other writable")
        yield descriptor
    finally:
        os.close(descriptor)


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise MigrationError("package path must be a string")
    path = PurePosixPath(value)
    if not value or len(value) > 1024 or path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise MigrationError(f"unsafe package path: {value!r}")
    if any(len(part.encode("utf-8")) > 255 or any(c in part for c in '\\:*?"<>|') or any(ord(c) < 32 for c in part)
           or part.endswith((".", " ")) or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part) for part in path.parts):
        raise MigrationError(f"invalid package path: {value!r}")
    return path



def _root(value:str)->Path:
 p=Path(value).expanduser()
 if not p.is_dir() or p.is_symlink(): raise MigrationError("root must be a real directory")
 return p.resolve(strict=True)
def select(root:Path, scopes:list[str], include_secrets:bool=False)->list[Path]:
 if not scopes or "all" in scopes: scopes=list(SCOPES)
 unknown=set(scopes)-set(SCOPES)
 if unknown: raise MigrationError(f"unknown scopes: {sorted(unknown)}")
 if "identities" in scopes and not include_secrets: raise MigrationError("identity migration requires --include-secrets")
 found=set()
 for scope in scopes:
  for pattern in SCOPES[scope]:
   for path in root.glob(pattern):
    if path.is_symlink(): raise MigrationError("migration source symlinks are forbidden")
    if path.is_file():
     relative=path.relative_to(root);_safe_relative(relative.as_posix())
     with directory_fd(root,relative.parts[:-1]):pass
     found.add(path)
     if len(found)>MAX_FILES:raise MigrationError("migration exceeds file-count bound")
 files=sorted(found)
 if len(files)>MAX_FILES: raise MigrationError("migration exceeds file-count bound")
 total=sum(p.stat().st_size for p in files)
 if total>MAX_TOTAL or any(p.stat().st_size>MAX_FILE for p in files): raise MigrationError("migration exceeds size bound")
 return files
def manifest(root:Path, files:list[Path], scopes:list[str])->dict:
 entries=[]
 for p in files:
  parts=p.relative_to(root).parts
  with directory_fd(root,parts[:-1]) as parent:data=secure_read(Path(parts[-1]),MAX_FILE,secret=p.suffix in {".key",".pem"},dir_fd=parent)
  entries.append({"path":p.relative_to(root).as_posix(),"size":len(data),"mode":stat.S_IMODE(p.lstat().st_mode),"sha256":hashlib.sha256(data).hexdigest()})
 return {"format":"shadow6-migration-v1","version":VERSION,"scopes":sorted(set(scopes)) if scopes and "all" not in scopes else sorted(SCOPES),"files":entries}
def plan(root:Path, scopes:list[str], include_secrets:bool=False)->dict:
 files=select(root,scopes,include_secrets);return manifest(root,files,scopes)
def export(root:Path,out:Path,form:str,scopes:list[str],include_secrets:bool=False)->dict:
 files=select(root,scopes,include_secrets); doc=manifest(root,files,scopes)
 if not out.is_absolute() or form not in {"directory","tar.gz","zip"}: raise MigrationError("output must be absolute and form supported")
 out.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix="shadow6-migrate-",dir="/tmp") as tmp:
  stage=Path(tmp)/"bundle";stage.mkdir();(stage/"manifest.json").write_text(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
  for src,item in zip(files,doc["files"]):
   parts=src.relative_to(root).parts
   with directory_fd(root,parts[:-1]) as parent:data=secure_read(Path(parts[-1]),MAX_FILE,secret=src.suffix in {".key",".pem"},dir_fd=parent)
   if len(data)!=item["size"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:raise MigrationError("source changed during export")
   dst=stage/"files"/src.relative_to(root);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data);os.chmod(dst,0o600)
  # Random sibling staging avoids clobbering a predictable .tmp file/link.
  with tempfile.TemporaryDirectory(prefix=".migration-export-",dir=out.parent) as output_tmp:
   temporary=Path(output_tmp)/"archive"
   if form=="directory":shutil.copytree(stage,temporary);temporary.chmod(0o700)
   elif form=="tar.gz":
    with tarfile.open(temporary,"w:gz") as archive:archive.add(stage,arcname="bundle",recursive=True)
   else:
    with zipfile.ZipFile(temporary,"w",zipfile.ZIP_DEFLATED) as archive:
     for p in stage.rglob("*"):
      if p.is_file():archive.write(p,(Path("bundle")/p.relative_to(stage)).as_posix())
   if form!="directory":temporary.chmod(0o600)
   os.replace(temporary,out)
 return {"output":str(out),"form":form,"files":len(files),"bytes":sum(p["size"] for p in doc["files"])}
def _safe_member(name:str)->Path:
 p=_safe_relative(name)
 if p.parts[0]!="bundle": raise MigrationError("unsafe archive path")
 return Path(*p.parts)

def _validate_manifest(doc:dict)->None:
 if set(doc)!={"format","version","scopes","files"} or doc["format"]!="shadow6-migration-v1" or doc["version"]!=VERSION:raise MigrationError("invalid manifest")
 if not isinstance(doc["scopes"],list) or any(not isinstance(x,str) or x not in SCOPES for x in doc["scopes"]) or len(set(doc["scopes"]))!=len(doc["scopes"]):raise MigrationError("invalid migration scopes")
 if not isinstance(doc["files"],list) or len(doc["files"])>MAX_FILES:raise MigrationError("invalid migration files")
 seen=set();total=0
 for item in doc["files"]:
  if not isinstance(item,dict) or set(item)!={"path","size","mode","sha256"}:raise MigrationError("invalid manifest entry")
  rel=str(_safe_relative(item["path"]));folded=rel.casefold()
  if folded in seen or any(folded.startswith(p+"/") or p.startswith(folded+"/") for p in seen):raise MigrationError("duplicate or conflicting manifest paths")
  seen.add(folded)
  if type(item["size"]) is not int or not 0<=item["size"]<=MAX_FILE or type(item["mode"]) is not int or not 0<=item["mode"]<=0o777:raise MigrationError("invalid manifest size or mode")
  if not isinstance(item["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",item["sha256"]):raise MigrationError("invalid manifest digest")
  total+=item["size"]
  if total>MAX_TOTAL:raise MigrationError("migration exceeds total size bound")

class _TarBudget:
 def __init__(self,stream):self.stream=stream;self.remaining=MAX_TOTAL+16*1024*1024
 def read(self,size):
  if size<0 or size>self.remaining:raise MigrationError("decompressed tar exceeds total size bound")
  data=self.stream.read(size);self.remaining-=len(data);return data

def import_bundle(source:Path,destination:Path,dry_run:bool=True)->dict:
 destination=_root(str(destination))
 if source.is_symlink():raise MigrationError("migration source must not be a symlink")
 with tempfile.TemporaryDirectory(prefix="shadow6-import-",dir="/tmp") as tmp:
  stage=Path(tmp)
  seen=set();total=0;count=0
  def extract(name,size,is_dir,reader):
   nonlocal total,count
   count+=1;rel=_safe_member(name.rstrip("/") if is_dir else name);folded=str(rel).casefold()
   if folded in seen or count>MAX_FILES*4+4:raise MigrationError("duplicate or excessive archive entries")
   seen.add(folded)
   if size<0 or size>MAX_FILE:raise MigrationError("archive member too large")
   total+=size
   if total>MAX_TOTAL:raise MigrationError("archive exceeds total size bound")
   target=stage/rel
   if is_dir:
    target.mkdir(parents=True,exist_ok=True)
    target.chmod(0o700)
    return
   target.parent.mkdir(parents=True,exist_ok=True)
   with reader() as src,target.open("xb") as dst:
    remaining=size
    while remaining:
     chunk=src.read(min(65536,remaining))
     if not chunk:raise MigrationError("truncated archive member")
     dst.write(chunk);remaining-=len(chunk)
    if src.read(1):raise MigrationError("archive member exceeds declared size")
   target.chmod(0o600)
  if source.is_dir():
   bundle=source
  elif source.name.endswith(".zip"):
   with zipfile.ZipFile(io.BytesIO(secure_read(source,MAX_TOTAL+16*1024*1024))) as a:
    if len(a.infolist())>MAX_FILES*4+4:raise MigrationError("archive has too many entries")
    for info in a.infolist():
     if stat.S_IFMT(info.external_attr>>16) not in {0,stat.S_IFREG,stat.S_IFDIR}:raise MigrationError("unsupported archive member")
     extract(info.filename,info.file_size,info.is_dir(),lambda:a.open(info))
   bundle=stage/"bundle"
  else:
   with gzip.GzipFile(fileobj=io.BytesIO(secure_read(source,MAX_TOTAL+16*1024*1024))) as compressed:
    with tarfile.open(fileobj=_TarBudget(compressed),mode="r|") as a:
     for item in a:
      if not item.isfile() and not item.isdir():raise MigrationError("unsupported archive member")
      extract(item.name,item.size,item.isdir(),lambda:a.extractfile(item))
   bundle=stage/"bundle"
  # Archive formats may omit explicit directory entries; normalize the
  # extracted bundle root before applying strict directory checks.
  for directory in (bundle, *[p for p in bundle.rglob("*") if p.is_dir()]):
   directory.chmod(0o700)
  with directory_fd(bundle) as parent:doc=strict_json(secure_read(Path("manifest.json"),1_048_576,dir_fd=parent))
  _validate_manifest(doc)
  actions=[]
  validated=stage/"validated";validated.mkdir()
  for item in doc["files"]:
   rel=Path(*_safe_relative(item["path"]).parts)
   with directory_fd(bundle,("files",*rel.parts[:-1])) as parent:data=secure_read(Path(rel.name),MAX_FILE,dir_fd=parent)
   if len(data)!=item["size"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:raise MigrationError("manifest digest mismatch")
   snapshot=validated/str(len(actions));snapshot.write_bytes(data);snapshot.chmod(0o600);actions.append(str(rel))
   # Validate existing destination ancestors for dry-run as well as apply.
   cursor=destination
   for part in rel.parts[:-1]:
    cursor=cursor/part
    if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):raise MigrationError("unsafe destination ancestor")
  if not dry_run:
   for index,item in enumerate(doc["files"]):
    rel=_safe_relative(item["path"])
    with directory_fd(destination,rel.parts[:-1],create=True) as parent:
     name=".migrate-"+os.urandom(16).hex()
     fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=parent)
     try:
      with os.fdopen(fd,"wb") as dst,(validated/str(index)).open("rb") as src:
       shutil.copyfileobj(src,dst,65536);dst.flush();os.fsync(dst.fileno())
       os.fchmod(dst.fileno(),0o600 if item["mode"]&0o077==0 else 0o644)
      os.replace(name,rel.name,src_dir_fd=parent,dst_dir_fd=parent)
     finally:
      try:os.unlink(name,dir_fd=parent)
      except FileNotFoundError:pass
  return {"validated":True,"dry_run":dry_run,"destination":str(destination),"files":actions}
def main()->int:
 p=argparse.ArgumentParser(description="Shadow6 one-stop migration tool");sub=p.add_subparsers(dest="command",required=True)
 for name in ("plan","export"):
  q=sub.add_parser(name);q.add_argument("--root",default=".");q.add_argument("--scope",action="append",choices=[*SCOPES,"all"],default=[]);q.add_argument("--include-secrets",action="store_true")
  if name=="export":q.add_argument("--output",type=Path,required=True);q.add_argument("--form",choices=("directory","tar.gz","zip"),default="tar.gz")
 q=sub.add_parser("import");q.add_argument("--source",type=Path,required=True);q.add_argument("--destination",default=".");q.add_argument("--apply",action="store_true")
 a=p.parse_args()
 if a.command=="plan":result=plan(_root(a.root),a.scope,a.include_secrets)
 elif a.command=="export":result=export(_root(a.root),a.output,a.form,a.scope,a.include_secrets)
 else:result=import_bundle(a.source.expanduser(),_root(a.destination),not a.apply)
 print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
