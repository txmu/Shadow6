## A DataChannel message carries one explicit big-endian Shadow6 frame.
## The enclosing SCTP/DTLS association authenticates the message; its SDP must
## first be signed by the configured peer through the authenticated control plane.
import strictjson
const MaxPayload* = 16384
type
  FrameHeader* = object
    version*: uint8
    kind*: uint8
    sequence*: uint32
    length*: uint16
  Frame* = object
    header*: FrameHeader
    payload*: string

proc encode*(payload: string; sequence: uint32; kind: uint8 = 1): string =
  require(payload.len <= MaxPayload and kind in [1'u8, 2'u8])
  require(kind != 2 or payload.len == 0)
  result = newString(8+payload.len)
  result[0] = char(1)
  result[1] = char(kind)
  for i in 0..<4: result[2+i] = char((sequence shr (24-i*8)) and 255)
  result[6] = char(payload.len shr 8)
  result[7] = char(payload.len and 255)
  for i,c in payload: result[8+i] = c
proc decode*(wire: string; expected: uint32): Frame =
  require(wire.len in 8..MaxPayload+8)
  result.header.version = uint8(wire[0])
  result.header.kind = uint8(wire[1])
  for i in 0..<4: result.header.sequence = (result.header.sequence shl 8) or uint32(wire[2+i])
  result.header.length = (uint16(wire[6]) shl 8) or uint16(wire[7])
  require(result.header.version == 1 and result.header.kind in [1'u8, 2'u8])
  require(result.header.sequence == expected and result.header.length.int == wire.len-8)
  require(result.header.kind != 2 or result.header.length == 0)
  result.payload = wire[8..^1]
