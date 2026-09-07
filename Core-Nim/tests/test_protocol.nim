import std/unittest
import strictjson, crypto, frames

suite "bounded protocol and crypto":
  test "duplicate, floats, overflow, nesting, malformed escapes":
    for value in ["{\"a\":1,\"a\":2}", "{\"a\":1.0}", "{\"a\":9007199254740992}",
                  "{\"a\":01}", "{\"a\":true,}", "{\"a\":\"\\x41\"}", "{}{}"]:
      expect ValueError: discard strictJson(value)
  test "macro rejects extra and incorrectly typed fields":
    let doc = strictJson("{\"version\":true}")
    expect ValueError: schema(doc,"version:JInt")
    expect ValueError: schema(doc,"other:JBool")
  test "Ed25519 tamper":
    let seed = randomHex(32)
    let sig = sign(seed,"hello")
    check verify(publicKey(seed),"hello",sig)
    check not verify(publicKey(seed),"changed",sig)
  test "explicit network byte order and sequence checks":
    let wire = frames.encode("payload",0x01020304'u32)
    check wire[2..5] == "\x01\x02\x03\x04"
    check frames.decode(wire,0x01020304'u32).payload == "payload"
    expect ValueError: discard frames.decode(wire,1)
    expect ValueError: discard frames.decode(wire[0..^2],0x01020304'u32)
