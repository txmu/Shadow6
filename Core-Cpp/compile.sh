#!/usr/bin/env bash
set -euo pipefail

out="shadow6-cpp.tmp.$$"
trap 'rm -f "$out"' EXIT
: "${CXX:=c++}"
declare -a flags
flags+=( "-std=c++20" "-O3" "-flto" "-Wall" "-Wextra" "-Wpedantic" "-Wconversion" "-Wshadow" )
flags+=( "-Wformat=2" "-Werror=format-security" "-fno-exceptions" "-fno-rtti" )
flags+=( "-U_FORTIFY_SOURCE" "-D_FORTIFY_SOURCE=3" "-D_GNU_SOURCE" )
flags+=( "-fPIE" "-pie" "-fstack-protector-strong" )
flags+=( "-Wl,-z,relro,-z,now" "-Wl,-z,noexecstack" "-Wl,-z,defs" "-Wl,--as-needed" )
for optional in -Wtrampolines -fstack-clash-protection -fcf-protection=full -ftrivial-auto-var-init=zero; do
  if printf 'int shadow6_probe;\n' | "$CXX" -std=c++20 -x c++ -c -o /dev/null "$optional" - 2>/dev/null; then
    flags+=("$optional")
  fi
done
"$CXX" "${flags[@]}" -o "$out" src/main.cpp
mv -f "$out" shadow6-cpp
chmod 0755 shadow6-cpp
printf '%s\n' '[+] Built Core-Cpp: shadow6-cpp'
