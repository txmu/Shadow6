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
  fun max_pending(): USize => 4096
  fun reconnect_delay(attempt: U8): U64 =>
    let bounded = if attempt > 6 then 6 else attempt end
    U64(250_000_000) << bounded.u64()

primitive PluginLimits
  fun max_id(): USize => 64
  fun max_payload(): USize => 1024
  fun max_plugins(): USize => 32

class val PluginRequest
  let plugin_id: String
  let capability: String
  let nonce: Array[U8] val
  let payload: Array[U8] val
  let signature: Array[U8] val
  new val create(id: String, cap: String, n: Array[U8] iso,
    body: Array[U8] iso, sig: Array[U8] iso) ? =>
    if ((id.size() == 0) or (id.size() > PluginLimits.max_id()) or
      (cap.size() == 0) or (cap.size() > PluginLimits.max_id()) or
      (n.size() != 24) or (body.size() > PluginLimits.max_payload()) or (sig.size() != 64)) then error end
    plugin_id = id; capability = cap; nonce = consume n
    payload = consume body; signature = consume sig

class val PluginDescriptor
  let id: String
  let capabilities: Array[String] val
  let socket: String
  new val create(name: String, caps: Array[String] val, endpoint: String) ? =>
    if ((name.size() == 0) or (name.size() > PluginLimits.max_id()) or
      (caps.size() > 16) or (endpoint.size() == 0) or (endpoint.size() > 108)) then error end
    id = name; capabilities = caps; socket = endpoint

class ref PluginTable
  let _plugins: Map[String, PluginDescriptor val] = Map[String, PluginDescriptor val]
  fun ref register(plugin: PluginDescriptor val): Bool =>
    if ((_plugins.size() >= PluginLimits.max_plugins()) or _plugins.contains(plugin.id)) then false
    else _plugins(plugin.id) = plugin; true end
  fun get(id: String): (PluginDescriptor val | None) => try _plugins(id)? else None end
  fun size(): USize => _plugins.size()

class ref ReliableSession
  var _next: U64 = 2
  var _send_base: U64 = 2
  var _receive_next: U64 = 2
  var _attempt: U8 = 0
  var _connected: Bool = false
  let _sent: Map[U64, PendingPacket] = Map[U64, PendingPacket]
  let _received: Map[U64, Array[U8] val] = Map[U64, Array[U8] val]
  var _srtt: U64 = 0
  var _rttvar: U64 = 0

  fun ref connected() => _connected = true; _attempt = 0
  fun ref disconnected() => _connected = false; _attempt = (_attempt + 1).min(6)
  fun ref clear() => _connected = false; _sent.clear(); _received.clear()
  fun can_send(): Bool =>
    _connected and (_next < U64.max_value()) and
      ((_next - _send_base) < SessionLimits.max_pending().u64())
  fun ref acknowledge(sequence: U64, now: U64): Bool =>
    try
      let packet = _sent(sequence)?
      // Karn: an ACK after retransmission is ambiguous and provides no sample.
      if packet.retries == 0 then sample_rtt(now - packet.first_sent) end
      _sent.remove(sequence)?
      while (_send_base < _next) and (not _sent.contains(_send_base)) do
        _send_base = _send_base + 1
      end
      true
    else false end
  fun ref next_sequence(): U64 ? =>
    if not can_send() then error end
    let value = _next; _next = _next + 1; value
  fun ref sent(sequence: U64, wire: Array[U8] val, now: U64) =>
    _sent(sequence) = PendingPacket(wire, now, rto())
  fun retry_delay(): U64 => SessionLimits.reconnect_delay(_attempt)
  fun ref accept_receive(sequence: U64, payload: Array[U8] iso): Bool =>
    if (sequence < 2) or (sequence == U64.max_value()) then false
    elseif sequence < _receive_next then true
    elseif (sequence - _receive_next) >= SessionLimits.max_pending().u64() then false
    elseif _received.contains(sequence) then true
    else _received(sequence) = consume payload; true end
  fun ref deliver(): Array[Array[U8] val] iso^ =>
    let result = recover iso Array[Array[U8] val] end
    while _received.contains(_receive_next) do
      try
        (_, let payload) = _received.remove(_receive_next)?
        result.push(payload)
        _receive_next = _receive_next + 1
      else break end
    end
    consume result
  fun ref retransmit(now: U64): Array[Array[U8] val] iso^ ? =>
    let due = recover iso Array[Array[U8] val] end
    for packet in _sent.values() do
      if (now >= packet.last_sent) and ((now - packet.last_sent) >= packet.timeout) then
        if packet.retries >= 8 then error end
        packet.retries = packet.retries + 1
        packet.last_sent = now
        packet.timeout = (packet.timeout * 2).min(5_000_000_000)
        due.push(packet.wire)
      end
    end
    consume due
  fun ref sample_rtt(sample: U64) =>
    if sample == 0 then return end
    if _srtt == 0 then _srtt = sample; _rttvar = sample / 2; return end
    let deviation = if _srtt >= sample then _srtt - sample else sample - _srtt end
    _rttvar = ((_rttvar * 3) + deviation) / 4
    _srtt = ((_srtt * 7) + sample) / 8
  fun rto(): U64 =>
    if _srtt == 0 then 1_000_000_000
    else (_srtt + (_rttvar * 4).max(10_000_000)).max(100_000_000).min(5_000_000_000) end

class ref PendingPacket
  let wire: Array[U8] val
  let first_sent: U64
  var last_sent: U64
  var timeout: U64
  var retries: U8 = 0
  new create(bytes: Array[U8] val, now: U64, rto: U64) =>
    wire = bytes; first_sent = now; last_sent = now; timeout = rto

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
