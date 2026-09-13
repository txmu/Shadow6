use "collections"

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

primitive SessionLimits
  fun max_clients(): USize => 256
  fun max_pending(): USize => 32
  fun reconnect_delay(attempt: U8): U64 =>
    let bounded = if attempt > 6 then 6 else attempt end
    U64(250_000_000) << bounded.u64()

class ref ReliableSession
  var _next: U64 = 1
  var _acked: U64 = 0
  var _attempt: U8 = 0
  var _connected: Bool = false

  fun ref connected() => _connected = true; _attempt = 0
  fun ref disconnected() => _connected = false; _attempt = _attempt + 1
  fun ref acknowledge(sequence: U64): Bool =>
    if (sequence <= _acked) or (sequence >= _next) then false
    else _acked = sequence; true end
  fun ref next_sequence(): U64 ? =>
    if (not _connected) or ((_next - _acked) > SessionLimits.max_pending().u64()) then error end
    let value = _next; _next = _next + 1; value
  fun retry_delay(): U64 => SessionLimits.reconnect_delay(_attempt)

class ref SessionTable
  let _sessions: Map[String, ReliableSession] = Map[String, ReliableSession]
  fun ref add(id: String): Bool =>
    if ((id.size() == 0) or (id.size() > 64)) or (_sessions.size() >= SessionLimits.max_clients()) then false
    elseif _sessions.contains(id) then false
    else _sessions(id) = ReliableSession; true end
  fun ref remove(id: String): Bool =>
    try _sessions.remove(id)?; true else false end
  fun ref get(id: String): (ReliableSession ref | None) =>
    try _sessions(id)? else None end
  fun size(): USize => _sessions.size()
