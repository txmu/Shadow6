#!/usr/bin/env python3
"""Build a filesystem-free OTP boot image backed by an in-memory BEAM ROM."""
from __future__ import annotations
import argparse, shutil, subprocess
from pathlib import Path

PRELOADED = ("erl_prim_loader init prim_buffer prim_file prim_inet socket_registry "
 "prim_socket prim_net zlib prim_zip erl_init erts_code_purger erlang erts_internal "
 "erl_tracer erts_literal_area_collector erts_trace_cleaner "
 "erts_dirty_process_signal_handler atomics counters persistent_term prim_eval").split()

def run(*args: str, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def erl_bytes(data: bytes) -> str:
    return ",".join(map(str, data))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--otp-source", required=True, type=Path)
    ap.add_argument("--otp-root", required=True, type=Path)
    ap.add_argument("--core-ebin", required=True, type=Path)
    a = ap.parse_args()
    source, otp_root, core_ebin = (a.otp_source.resolve(strict=True),
        a.otp_root.resolve(strict=True), a.core_ebin.resolve(strict=True))
    erl, erlc = otp_root/"bin/erl", otp_root/"bin/erlc"
    original_boot = otp_root/"lib/erlang/bin/start_clean.boot"
    src, ebin = source/"erts/preloaded/src", source/"erts/preloaded/ebin"
    embedded_boot = src/"shadow6_start_clean.boot"
    core_beams = sorted(b for b in core_ebin.glob("*.beam")
        if "@" not in b.name and not b.stem.endswith(("_test", "_test_support")))
    core_modules = ",".join(b.stem for b in core_beams)
    expression = (f'{{ok,B}}=file:read_file("{original_boot}"),'
      '{script,I,C}=binary_to_term(B),'
      'C1=C,IsNotLoad=fun({primLoad,_})->false;(_)->true end,'
      '{Before,After}=lists:splitwith(IsNotLoad,C1),C2=Before++[{apply,{shadow6_rom,load,[]}}|After],'
      f'N=lists:sublist(C2,length(C2)-1)++[{{primLoad,[{core_modules}]}},'
      '{apply,{shadow6_sodium,load,[]}},{apply,{shadow6_cli,main,[]}},lists:last(C1)],'
      f'ok=file:write_file("{embedded_boot}",term_to_binary({{script,I,N}},[deterministic])),halt().')
    run(str(erl), "-noshell", "-noinput", "-eval", expression)
    boot_src = src/"shadow6_boot.erl"
    boot_src.write_text("-module(shadow6_boot).\n-export([get_file/1]).\n"+
      f'get_file(_) -> {{ok, <<{erl_bytes(embedded_boot.read_bytes())}>>, "embedded:start_clean.boot"}}.\n',
      encoding="ascii")

    list_expression = (f'{{ok,B}}=file:read_file("{embedded_boot}"),'
      '{script,_,C}=binary_to_term(B),M=lists:usort(lists:flatten([X||{primLoad,X}<-C])),'
      'lists:foreach(fun(X)->io:format("~s\\n",[code:which(X)]) end,M),halt().')
    done = run(str(erl), "-noshell", "-noinput", "-eval", list_expression,
               capture_output=True)
    boot_beams = [Path(x) for x in done.stdout.splitlines() if x.endswith(".beam")]
    all_beams = {b.name:b for b in [*boot_beams, *core_beams]}
    required_library = [*otp_root.glob("lib/erlang/lib/kernel-*/ebin/*.beam"),
                        *otp_root.glob("lib/erlang/lib/stdlib-*/ebin/*.beam")]
    absent_library = sorted(b.name for b in required_library if b.name not in all_beams)
    if absent_library:
        raise SystemExit("boot ROM is missing kernel/stdlib modules: " + ", ".join(absent_library))
    missing = [str(p) for p in all_beams.values() if not p.is_file()]
    if missing: raise SystemExit("missing BEAM files: "+", ".join(missing))
    rom_src = src/"shadow6_rom.erl"
    rom_src.write_text("-module(shadow6_rom).\n-export([load/0,read_file/1]).\n"
      "load() -> erlang:load_nif(\"shadow6_rom\", 0).\n"
      "read_file(_) -> erlang:nif_error(nif_not_loaded).\n", encoding="ascii")
    c_lines = ['#define STATIC_ERLANG_NIF_LIBNAME shadow6_rom',
      '#include "erl_nif.h"', '#include <string.h>',
      'struct rom_entry { const char *name; const unsigned char *data; size_t size; };']
    entries = []
    for index, (name, path) in enumerate(sorted(all_beams.items())):
        symbol = f"rom_{index}"
        c_lines.append(f'static const unsigned char {symbol}[] = {{{erl_bytes(path.read_bytes())}}};')
        entries.append(f'{{"{name}", {symbol}, sizeof({symbol})}}')
    c_lines.extend([
      'static const struct rom_entry rom[] = {'+','.join(entries)+'};',
      'static ERL_NIF_TERM atom_ok, atom_error, atom_enoent;',
      'static ERL_NIF_TERM read_file(ErlNifEnv *env,int argc,const ERL_NIF_TERM argv[]){',
      ' ErlNifBinary path,out; const unsigned char *base; size_t n,i;',
      ' if(argc!=1 || !enif_inspect_iolist_as_binary(env,argv[0],&path)) return enif_make_badarg(env);',
      ' base=path.data; n=path.size; for(i=n;i>0;i--) if(path.data[i-1]==47){base=path.data+i;n-=i;break;}',
      ' for(i=0;i<sizeof(rom)/sizeof(rom[0]);i++) if(strlen(rom[i].name)==n && !memcmp(base,rom[i].name,n)){',
      '  if(!enif_alloc_binary(rom[i].size,&out)) return enif_make_badarg(env);',
      '  memcpy(out.data,rom[i].data,rom[i].size); return enif_make_tuple2(env,atom_ok,enif_make_binary(env,&out));}',
      ' return enif_make_tuple2(env,atom_error,atom_enoent);}',
      'static int load(ErlNifEnv *env,void **p,ERL_NIF_TERM info){(void)p;(void)info;',
      ' atom_ok=enif_make_atom(env,"ok"); atom_error=enif_make_atom(env,"error"); atom_enoent=enif_make_atom(env,"enoent"); return 0;}',
      'static ErlNifFunc funcs[]={{"read_file",1,read_file,0}};',
      'ERL_NIF_INIT(shadow6_rom,funcs,load,NULL,NULL,NULL)'])
    (Path(__file__).parents[1]/"obj/shadow6_rom.c").write_text("\n".join(c_lines)+"\n",encoding="ascii")

    init_path = src/"init.erl"
    text = init_path.read_text()
    old,new = "case erl_prim_loader:get_file(BootFile) of","case shadow6_boot:get_file(BootFile) of"
    if text.count(old)==1: init_path.write_text(text.replace(old,new))
    elif text.count(new)!=1: raise SystemExit("unexpected OTP init.erl boot-loader layout")
    loader = src/"erl_prim_loader.erl"
    text = loader.read_text()
    old,new = "try prim_file:read_file(File) of","try shadow6_rom:read_file(File) of"
    if text.count(old)==1: loader.write_text(text.replace(old,new))
    elif text.count(new)!=1: raise SystemExit("unexpected OTP module-loader layout")
    run(str(erlc), "+deterministic", "-I", str(source/"lib/kernel/src"),
        "-o", str(ebin), str(init_path), str(loader),
        str(boot_src), str(rom_src))
    preload = [ebin/f"{m}.beam" for m in PRELOADED]+[ebin/"shadow6_boot.beam",ebin/"shadow6_rom.beam"]
    missing = [str(p) for p in preload if not p.is_file()]
    if missing: raise SystemExit("missing preloaded BEAM files: "+", ".join(missing))
    targets = list((source/"erts/emulator").glob("*-linux-*/Makefile"))
    if len(targets)!=1: raise SystemExit(f"expected one ERTS target, found {targets}")
    preload_c = targets[0].parent/"opt/emu/preload.c"
    preload_c.parent.mkdir(parents=True, exist_ok=True)
    with preload_c.open("w") as out:
        subprocess.run([str(source/"erts/emulator/utils/make_preload"),"-old",*map(str,preload)],
                       check=True, stdout=out)
    shutil.copy2(Path(__file__).parents[1]/"c_src/main.c", source/"erts/emulator/sys/unix/erl_main.c")
    print(f"Embedded {len(all_beams)} ROM modules through {len(preload)} preloaded modules")
    return 0

if __name__ == "__main__": raise SystemExit(main())
