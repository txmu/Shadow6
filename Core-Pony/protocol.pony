// Pure protocol checks shared by the actor data plane. Network code must call
// these before forwarding an iso datagram to Decryptor.
primitive ProtocolLimits
  fun max_frame(): USize => 1200
  fun handshake_window(): U64 => 30_000

class val HandshakeTranscript
  let version: U8
  let client_nonce: Array[U8] val
  let agent_nonce: Array[U8] val
  let client_key: Array[U8] val
  let agent_key: Array[U8] val
  new val create(cn: Array[U8] iso, an: Array[U8] iso, ck: Array[U8] iso, ak: Array[U8] iso) ? =>
    if (cn.size() != 32) or (an.size() != 32) or (ck.size() != 32) or (ak.size() != 32) then error end
    version = 1
    client_nonce = consume cn; agent_nonce = consume an
    client_key = consume ck; agent_key = consume ak

primitive ReplayWindow
  fun accept(previous: U64, candidate: U64): Bool =>
    (candidate > previous) and ((candidate - previous) <= 1_000_000)
