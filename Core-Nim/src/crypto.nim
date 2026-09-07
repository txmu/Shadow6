import std/strutils
import strictjson
{.compile: "native.c".}
{.passL: "-lcrypto".}
proc secureRead(path: cstring; data: pointer; cap: cint): cint {.importc: "nim_secure_read".}
proc randomBytes(data: pointer; n: cint): cint {.importc: "nim_random".}
proc digest(data: pointer; n: csize_t; output: pointer): cint {.importc: "nim_hash".}
proc publicBytes(seed, output: pointer): cint {.importc: "nim_public".}
proc signature(signing: cint; key, data: pointer; n: csize_t; sig: pointer): cint {.importc: "nim_signature".}

proc readOwned*(path: string): string =
  require(path.len in 1..4095 and '\0' notin path)
  result = newString(MaxDocument)
  let n = secureRead(path.cstring, addr result[0], MaxDocument)
  require(n >= 0, "file must be unchanged, regular, owned, non-symlink and mode 0600")
  result.setLen(n)

proc unhex*(text: string; size: int): string =
  require(text.len == size*2)
  result = newString(size)
  for i in 0..<size:
    require(text[2*i] in HexDigits and text[2*i+1] in HexDigits)
    result[i] = char(parseHexInt(text[2*i..2*i+1]))
proc hex*(data: string): string =
  for c in data: result.add toHex(ord(c), 2).toLowerAscii
proc randomHex*(size: int): string =
  require(size in 1..1024)
  var data = newString(size)
  require(randomBytes(addr data[0], size.cint) == 1)
  hex(data)
proc sha256*(text: string): string =
  var output = newString(32)
  require(digest(text.cstring, text.len.csize_t, addr output[0]) == 1)
  hex(output)
proc publicKey*(privateKey: string): string =
  require(privateKey.len in [64,128])
  let seed = unhex(privateKey[0..<64], 32)
  var output = newString(32)
  require(publicBytes(seed.cstring, addr output[0]) == 1)
  result = hex(output)
  if privateKey.len == 128: require(privateKey[64..^1].toLowerAscii == result)
proc sign*(privateKey, data: string): string =
  discard publicKey(privateKey)
  let seed = unhex(privateKey[0..<64], 32)
  var sig = newString(64)
  require(signature(1, seed.cstring, data.cstring, data.len.csize_t, addr sig[0]) == 1)
  hex(sig)
proc verify*(publicKey, data, sig: string): bool =
  let key = unhex(publicKey, 32)
  var raw = unhex(sig, 64)
  signature(0, key.cstring, data.cstring, data.len.csize_t, addr raw[0]) == 1
