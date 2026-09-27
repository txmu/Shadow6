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

proc encode*(payload: openArray[char]; sequence: uint32; kind: uint8 = 1): string =
  require(payload.len <= MaxPayload and kind in [1'u8, 2'u8])
  require(kind != 2 or payload.len == 0)
  result = newString(8+payload.len)
  result[0] = char(1)
  result[1] = char(kind)
  for i in 0..<4: result[2+i] = char((sequence shr (24-i*8)) and 255)
  result[6] = char(payload.len shr 8)
  result[7] = char(payload.len and 255)
  if payload.len > 0:
    copyMem(addr result[8], unsafeAddr payload[0], payload.len)
proc decodeHeader*(wire: string; expected: uint32): FrameHeader =
  require(wire.len in 8..MaxPayload+8)
  result.version = uint8(wire[0])
  result.kind = uint8(wire[1])
  for i in 0..<4: result.sequence = (result.sequence shl 8) or uint32(wire[2+i])
  result.length = (uint16(wire[6]) shl 8) or uint16(wire[7])
  require(result.version == 1 and result.kind in [1'u8, 2'u8])
  require(result.sequence == expected and result.length.int == wire.len-8)
  require(result.kind != 2 or result.length == 0)

proc decode*(wire: string; expected: uint32): Frame =
  result.header = decodeHeader(wire, expected)
  result.payload = wire[8..^1]
