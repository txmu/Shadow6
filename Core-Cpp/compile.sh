#!/usr/bin/env bash
set -euo pipefail

out="shadow6-cpp.tmp.$$"
trap 'rm -f "$out"' EXIT
: "${CXX:=c++}"
declare -a flags
flags+=( "-std=c++20" "-O3" "-Wall" "-Wextra" "-Wpedantic" "-Wconversion" "-Wshadow" )
flags+=( "-Wformat=2" "-Werror=format-security" "-fno-exceptions" "-fno-rtti" )
flags+=( "-fPIE" "-pie" "-fstack-protector-strong" )
case "$(uname -s)" in
  Linux)
    flags+=( "-flto" "-U_FORTIFY_SOURCE" "-D_FORTIFY_SOURCE=3" "-D_GNU_SOURCE" )
    flags+=( "-Wl,-z,relro,-z,now" "-Wl,-z,noexecstack" "-Wl,-z,defs" "-Wl,--as-needed" )
    ;;
  FreeBSD|NetBSD|OpenBSD)
    flags+=( "-Wl,-z,relro,-z,now" "-Wl,-z,noexecstack" "-Wl,-z,defs" )
    ;;
  Darwin) ;; # Mach-O uses different linker hardening controls.
  *) echo 'Unsupported native Core-Cpp platform' >&2; exit 1 ;;
esac
read -r -a cppflags <<< "${CPPFLAGS:-}"
read -r -a ldflags <<< "${LDFLAGS:-}"
for optional in -Wtrampolines -fstack-clash-protection -fcf-protection=full -ftrivial-auto-var-init=zero; do
  if printf 'int shadow6_probe;\n' | "$CXX" -std=c++20 -Werror -x c++ -c -o /dev/null "$optional" - 2>/dev/null; then
    flags+=("$optional")
  fi
done
"$CXX" "${flags[@]}" "${cppflags[@]}" -pthread -o "$out" src/main.cpp "${ldflags[@]}" -lssl -lcrypto
mv -f "$out" shadow6-cpp
chmod 0755 shadow6-cpp
printf '%s\n' '[+] Built Core-Cpp: shadow6-cpp'
