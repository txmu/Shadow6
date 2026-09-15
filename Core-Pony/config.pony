use "files"
use "lib:stdc++"
use @s6p_config[I32](path: Pointer[U8] tag, out: Pointer[U8] tag, cap: USize)

class val Configuration
  let role: U8
  let client: Bool
  let broker: Bool
  let allow_external: Bool
  let listen_port: U16
  let peer_port: U16
  let application_port: U16
  let seed: Array[U8] val
  let peer_key: Array[U8] val
  let peer_keys: Array[Array[U8] val] val
  let bind_host: String
  let peer_host: String
  let application_host: String
  new val create(bytes: Array[U8] iso) ? =>
    let data: Array[U8] ref = consume bytes
    if data.size() != 9034 then error end
    role = data(0)?
    if role > 2 then error end
    allow_external = data(1)? == 1
    client = role == 1
    broker = role == 2
    listen_port = (data(2)?.u16() << 8) or data(3)?.u16()
    peer_port = (data(4)?.u16() << 8) or data(5)?.u16()
    application_port = (data(6)?.u16() << 8) or data(7)?.u16()
    let s = recover iso Array[U8](32) end
    let p = recover iso Array[U8](32) end
    var i: USize = 0
    while i < 32 do s.push(data(8 + i)?); p.push(data(40 + i)?); i = i + 1 end
    seed = consume s
    peer_key = consume p
    let count = (data(840)?.usize() << 8) or data(841)?.usize()
    if (count == 0) or (count > 256) then error end
    let pins = recover iso Array[Array[U8] val](count) end
    var pin_index: USize = 0
    while pin_index < count do
      let pin = recover iso Array[U8](32) end
      i = 0
      while i < 32 do pin.push(data(842 + (pin_index * 32) + i)?); i = i + 1 end
      pins.push(consume pin)
      pin_index = pin_index + 1
    end
    peer_keys = consume pins
    bind_host = ConfigString(data, 72)?
    peer_host = ConfigString(data, 328)?
    application_host = ConfigString(data, 584)?
    @sodium_memzero(data.cpointer(), data.size())

primitive ConfigString
  fun apply(bytes: Array[U8] ref, offset: USize): String ? =>
    let result = recover iso Array[U8](255) end
    var i: USize = 0
    while (i < 255) and (bytes(offset + i)? != 0) do
      result.push(bytes(offset + i)?)
      i = i + 1
    end
    if result.size() == 0 then error end
    String.from_array(consume result)

actor ConfigReader
  new create(auth: FileAuth, path: String, main: Main, check: Bool, debug: Bool) =>
    try
      if (path.size() == 0) or (path.size() > 4096) or path.contains(String.from_array([U8(0)])) then error end
      let bytes = recover iso Array[U8].init(0, 9034) end
      if @s6p_config(path.cstring(), bytes.cpointer(), bytes.size()) != 0 then error end
      main.configured(Configuration(consume bytes)?, check, debug)
    else main.failed() end
