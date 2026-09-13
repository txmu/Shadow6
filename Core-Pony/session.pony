use "lib:s6p"
use "lib:sodium"

use @s6p_start[I32](seed: Pointer[U8] tag, n: USize, peer: Pointer[U8] tag, pn: USize,
  state: Pointer[U8] tag, sn: USize, out: Pointer[U8] tag, cap: USize, now: U64)
use @s6p_respond[I32](seed: Pointer[U8] tag, n: USize, peer: Pointer[U8] tag, pn: USize,
  hello: Pointer[U8] tag, hn: USize, out: Pointer[U8] tag, cap: USize,
  keys: Pointer[U8] tag, kn: USize, now: U64)
use @s6p_finish[I32](state: Pointer[U8] tag, sn: USize, response: Pointer[U8] tag,
  rn: USize, keys: Pointer[U8] tag, kn: USize, now: U64)
use @s6p_seal[I32](packet: Pointer[U8] tag, cap: USize, size: USize,
  keys: Pointer[U8] tag, kn: USize, sequence: U64, kind: U32)
use @s6p_open[I32](packet: Pointer[U8] tag, size: USize, keys: Pointer[U8] tag, kn: USize)
use @sodium_memzero[None](p: Pointer[U8] tag, size: USize)
use @s6p_public[I32](seed: Pointer[U8] tag, n: USize, pk: Pointer[U8] tag, cap: USize)

// These FFI calls mutate only exclusively owned output buffers, synchronously.
// They are not marked readnone/readonly: AEAD has observable writes. Pointers
// never escape the call. Immutable key storage is only passed as const in C.
class val OCapToken
  let _keys: Array[U8] val
  new val create(keys: Array[U8] iso) ? =>
    if keys.size() != 96 then error end
    _keys = consume keys

  fun seal(packet: Array[U8] iso, sequence: U64, kind: U32): Array[U8] iso^ ? =>
    let size = packet.size()
    if (size < 12) or (size > 1184) then error end
    var i: USize = 0
    while i < 16 do packet.push(0); i = i + 1 end
    if @s6p_seal(packet.cpointer(), packet.size(), size, _keys.cpointer(),
      _keys.size(), sequence, kind) != 0 then error end
    consume packet

  fun open(packet: Array[U8] iso): Array[U8] iso^ ? =>
    if @s6p_open(packet.cpointer(), packet.size(), _keys.cpointer(), _keys.size()) != 0 then error end
    packet.truncate(packet.size() - 16)
    consume packet

class Handshake
  let _state: Array[U8] ref = Array[U8].init(0, 236)
  var _pending: Bool = false

  fun ref start(seed: Array[U8] box, peer: Array[U8] box, now: U64): Array[U8] iso^ ? =>
    clear()
    let out = recover iso Array[U8].init(0, 140) end
    if @s6p_start(seed.cpointer(), seed.size(), peer.cpointer(), peer.size(),
      _state.cpointer(), _state.size(), out.cpointer(), out.size(), now) != 0 then error end
    _pending = true
    consume out

  fun ref finish(response: Array[U8] iso, now: U64): OCapToken ? =>
    if not _pending then error end
    _pending = false
    let keys = recover iso Array[U8].init(0, 96) end
    if @s6p_finish(_state.cpointer(), _state.size(), response.cpointer(), response.size(),
      keys.cpointer(), keys.size(), now) != 0 then clear(); error end
    OCapToken(consume keys)?

  fun ref clear() =>
    @sodium_memzero(_state.cpointer(), _state.size())
    _pending = false

primitive AgentHandshake
  fun apply(seed: Array[U8] box, peer: Array[U8] box, hello: Array[U8] box,
    now: U64): (Array[U8] iso^, OCapToken) ?
  =>
    let out = recover iso Array[U8].init(0, 172) end
    let keys = recover iso Array[U8].init(0, 96) end
    if @s6p_respond(seed.cpointer(), seed.size(), peer.cpointer(), peer.size(),
      hello.cpointer(), hello.size(), out.cpointer(), out.size(),
      keys.cpointer(), keys.size(), now) != 0 then error end
    (consume out, OCapToken(consume keys)?)

primitive Frame
  fun empty(): Array[U8] iso^ => recover iso Array[U8].init(0, 12) end
  fun sequence(packet: Array[U8] iso): U64 ? =>
    var n: U64 = 0
    var i: USize = 4
    while i < 12 do n = (n << 8) or packet(i)?.u64(); i = i + 1 end
    n
