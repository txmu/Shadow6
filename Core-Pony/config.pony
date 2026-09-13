use "files"
use "lib:stdc++"
use @s6p_config[I32](path: Pointer[U8] tag, out: Pointer[U8] tag, cap: USize)

class val Configuration
  let client: Bool
  let listen_port: U16
  let peer_port: U16
  let application_port: U16
  let seed: Array[U8] val
  let peer_key: Array[U8] val
  new val create(bytes: Array[U8] iso) ? =>
    if bytes.size() != 71 then error end
    client = bytes(0)? == 1
    listen_port = (bytes(1)?.u16() << 8) or bytes(2)?.u16()
    peer_port = (bytes(3)?.u16() << 8) or bytes(4)?.u16()
    application_port = (bytes(5)?.u16() << 8) or bytes(6)?.u16()
    let s = recover iso Array[U8](32) end
    let p = recover iso Array[U8](32) end
    var i: USize = 0
    while i < 32 do s.push(bytes(7 + i)?); p.push(bytes(39 + i)?); i = i + 1 end
    seed = consume s
    peer_key = consume p
    @sodium_memzero(bytes.cpointer(), bytes.size())

actor ConfigReader
  new create(auth: FileAuth, path: String, main: Main, check: Bool, debug: Bool) =>
    try
      if (path.size() == 0) or (path.size() > 4096) or path.contains(String.from_array([U8(0)])) then error end
      let bytes = recover iso Array[U8].init(0, 71) end
      if @s6p_config(path.cstring(), bytes.cpointer(), bytes.size()) != 0 then error end
      main.configured(Configuration(consume bytes)?, check, debug)
    else main.failed() end
