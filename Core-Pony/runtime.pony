use "net"
use "time"
use "collections"
use @s6_app_flow_recv[I32](fd: I32, out: Pointer[U8] tag, capacity: USize)
use @s6_app_flow_send[I32](fd: I32, data: Pointer[U8] tag, size: USize)
use @s6_app_flow_close[None](fd: I32)

interface tag DatagramReceiver
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor)
  be received_batch(batch: Array[InboundDatagram iso] iso, application: Bool, source: SocketActor)
  be bound(application: Bool)
  be failed()

// Exclusive ownership of every packet is retained across a batched actor
// handoff. Decryption still mutates only the individual iso payload buffer.
class iso InboundDatagram
  var _data: Array[U8] iso
  let from: NetAddress val
  new iso create(data: Array[U8] iso, address: NetAddress val) =>
    _data = consume data
    from = address
  fun ref take(): Array[U8] iso^ => _data = recover iso Array[U8] end

actor SocketActor is (UDPSocketActor & UDPLifecycleEventReceiver)
  var _udp: UDPSocket = UDPSocket.none()
  let _receiver: DatagramReceiver
  let _application: Bool
  let _ingress: Bool
  var _inflight: USize = 0
  var _admitting: USize = 0
  var _batch: Array[InboundDatagram iso] iso = recover iso Array[InboundDatagram iso](64) end
  var _batch_receiver: (DatagramReceiver | None) = None
  var _flush_pending: Bool = false
  let _routes: Map[U64, DatagramReceiver] = Map[U64, DatagramReceiver]
  new create(auth: NetAuth, host: String, port: String, receiver: DatagramReceiver, application: Bool, ingress: Bool = true) =>
    _receiver = receiver
    _application = application
    _ingress = ingress
    _udp = UDPSocket(UDPAuth(auth), host, port, this, this,
      DefaultReadBufferSize(), IP4, 16)
  fun ref _socket(): UDPSocket => _udp
  fun ref _on_bind_failure() => _receiver.failed()
  fun ref _on_bound() =>
    // Per-socket requests only; the OS may clamp these bounded buffers.
    _udp.set_so_rcvbuf(1_048_576)
    _udp.set_so_sndbuf(1_048_576)
    _receiver.bound(_application)
  fun ref _on_received(data: Array[U8] iso, from: NetAddress val): ReadAction =>
    if _application and not _ingress then return KeepReading end
    if _inflight >= 1024 then return YieldReading end
    if data.size() > ProtocolLimits.max_frame() then return KeepReading end
    if not _application then
      try
        if not ProtocolLimits.wire_frame(data.size(), data(0)?, data(1)?, data(2)?, data(3)?) then
          return KeepReading
        end
      else return KeepReading end
      try
        // All configured sockets are IPv4. A packed address/port avoids
        // getnameinfo, String allocations and a Runtime mailbox hop per frame.
        let receiver = _routes(PeerRoute(from)?)?
        _inflight = _inflight + 1
        _enqueue(consume data, from, receiver)
        return if _inflight >= 1024 then YieldReading else KeepReading end
      end
      // Unknown peers can only request admission with a shaped hello. Keep
      // their work separate so a flood cannot fill all established credits.
      if (data.size() != 140) or (_admitting >= 16) then return KeepReading end
      try if (data(2)? != 81) or (data(3)? != 49) then return KeepReading end end
      _admitting = _admitting + 1
    end
    _inflight = _inflight + 1
    if _application then _enqueue(consume data, from, _receiver)
    else _receiver.received(consume data, from, false, this) end
    // Yield at the credit bound so consumed messages can run promptly.
    // This net API has no UDP mute/unmute; YieldReading is a bounded turn.
    if _inflight >= 1024 then YieldReading else KeepReading end
  fun ref _enqueue(data: Array[U8] iso, from: NetAddress val, receiver: DatagramReceiver) =>
    if _batch_receiver isnt receiver then _flush() end
    _batch_receiver = receiver
    _batch.push(InboundDatagram(consume data, from))
    // Always queue a flush for short bursts, including a single handshake
    // response. A batch never waits for another packet or a timer to arrive.
    if not _flush_pending then _flush_pending = true; flush() end
    if _batch.size() >= 64 then _flush() end
  fun ref _flush() =>
    if _batch.size() == 0 then return end
    match _batch_receiver
    | let receiver: DatagramReceiver =>
      receiver.received_batch(_batch = recover iso Array[InboundDatagram iso](64) end,
        _application, this)
    end
    _batch_receiver = None
  be flush() => _flush_pending = false; _flush()
  be consumed(count: USize = 1) => _inflight = _inflight - count.min(_inflight)
  be admitted() =>
    if _admitting > 0 then _admitting = _admitting - 1 end
  be route(peer: NetAddress val, receiver: DatagramReceiver) =>
    try
      let id = PeerRoute(peer)?
      if _routes.contains(id) or (_routes.size() < SessionLimits.max_clients()) then
        _routes(id) = receiver
      end
    end
  be unroute(peer: NetAddress val, receiver: DatagramReceiver) =>
    try
      let id = PeerRoute(peer)?
      if _routes(id)? is receiver then _routes.remove(id)? end
    end
  be send(data: Array[U8] val, target: NetAddress val) =>
    if _udp.is_open() then _udp.send_to(data, target) end
  be send_batch(batch: Array[Array[U8] val] iso, target: NetAddress val) =>
    // Internal callers cap batches at 16, preserving scheduler fairness.
    if _udp.is_open() then
      let items: Array[Array[U8] val] ref = consume batch
      for data in items.values() do _udp.send_to(data, target) end
    end

class _Tick is TimerNotify
  let _runtime: Runtime
  new iso create(runtime: Runtime) => _runtime = runtime
  fun ref apply(timer: Timer, count: U64): Bool => _runtime.tick(); true

primitive PeerID
  fun apply(from: NetAddress val): String ? =>
    (let host, let port) = from.name()?
    host + ":" + port

primitive PeerRoute
  fun apply(from: NetAddress val): U64 ? =>
    if not from.ip4() then error end
    (from.ipv4_addr().u64() << 16) or from.port().u64()

// Only a signed, pinned hello may allocate an agent session or app socket.
// Each actor receives its own token, never the listener's signing secrets.
actor Runtime is DatagramReceiver
  let _auth: NetAuth
  let _cfg: Configuration
  let _main: Main
  let _out: OutStream
  let _network: SocketActor
  let _sessions: Map[String, ClientSession] = Map[String, ClientSession]
  let _relays: Map[String, RelaySession] = Map[String, RelaySession]
  let _recent: Map[String, U64] = Map[String, U64]
  let _timers: Timers = Timers
  var _peer: NetAddress val = recover NetAddress end
  var _target: NetAddress val = recover NetAddress end
  var _credits: U64 = 256
  var _refilled: U64 = Time.nanos()
  var _closed: Bool = false
  var _flow_fd: I32 = -1
  var _flow_done: Bool = false
  var _reconnect_at: U64 = 0
  var _reconnect_attempt: U8 = 0
  new create(auth: NetAuth, config: Configuration, out: OutStream, err: OutStream, main: Main, debug: Bool, flow_fd: I32 = -1) =>
    _auth = auth; _cfg = config; _main = main; _out = out
    _flow_fd = flow_fd
    try
      let peers: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), config.peer_host, config.peer_port.string())
      _peer = peers(0)?
      let targets: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), config.application_host, config.application_port.string())
      _target = targets(0)?
    else
      _closed = true
      if _flow_fd >= 0 then @s6_app_flow_close(_flow_fd); _flow_fd = -1 end
      _main.failed()
    end
    _network = SocketActor(auth, config.bind_host, config.listen_port.string(), this, false, true)
    _timers(Timer(_Tick(this), 1_000_000, 1_000_000))
  be failed() =>
    if not _closed then
      _closed = true; _network.dispose(); _timers.dispose(); _main.failed()
      if _flow_fd >= 0 then @s6_app_flow_close(_flow_fd); _flow_fd = -1 end
      for session in _sessions.values() do session.close() end
      for relay in _relays.values() do relay.close() end
    end
  be bound(application: Bool) =>
    if _closed then return end
    if _cfg.client then
      try
        let id = PeerID(_peer)?
        _sessions(id) = ClientSession.client(_auth, _cfg, this, _network, _peer, _target, id, _out, _flow_fd)
        _network.route(_peer, _sessions(id)?)
        // The actor has confirmed the native bind and installed the flow
        // consumer. Main/config admission alone cannot establish readiness.
        if _flow_fd >= 0 then
          _out.print("{\"event\":\"shadow6.ready\",\"schema\":1,\"core\":\"shadow6-pony\",\"role\":\"client\",\"application_boundary\":{\"kind\":\"message\",\"mode\":\"seqpacket-fd\",\"endpoint\":{\"fd\":" + _flow_fd.string() + "}}}")
        end
      else failed() end
    else _out.print(if _cfg.broker then "ready: broker" else "ready: listener" end) end
  be tick() =>
    if _closed then return end
    let now = Time.nanos()
    if _cfg.client and (_sessions.size() == 0) and (_reconnect_at != 0) and (now >= _reconnect_at) then
      try
        let id = PeerID(_peer)?
        _sessions(id) = ClientSession.client(_auth, _cfg, this, _network, _peer, _target, id, _out, _flow_fd)
        _network.route(_peer, _sessions(id)?)
        _reconnect_at = 0
      end
    end
    for session in _sessions.values() do session.tick(now) end
    for relay in _relays.values() do relay.tick(now) end
    let expired = Array[String]
    for (id, expires_at) in _recent.pairs() do if now >= expires_at then expired.push(id) end end
    for id in expired.values() do try _recent.remove(id)? end end
  be retired(id: String, session: ClientSession) =>
    try
      if _sessions(id)? is session then
        _sessions.remove(id)?
        if _cfg.client and not _flow_done then
          _reconnect_at = Time.nanos() + SessionLimits.reconnect_delay(_reconnect_attempt)
          _reconnect_attempt = (_reconnect_attempt + 1).min(6)
        elseif _flow_done then
          _closed = true; _network.dispose(); _timers.dispose(); _main.finished()
        end
      end
    end
  be established() => _reconnect_attempt = 0
  be flow_closed() => _flow_done = true
  be flow_drained() =>
    if _flow_fd >= 0 then @s6_app_flow_close(_flow_fd); _flow_fd = -1 end
    _flow_done = true
  be flow_failed() => failed()
  be relay_retired(id: String, relay: RelaySession) =>
    try if _relays(id)? is relay then _relays.remove(id)? end end
  fun ref _admit(): Bool =>
    let now = Time.nanos()
    let extra = (now - _refilled) / 15_625_000
    if extra > 0 then _credits = (_credits + extra).min(256); _refilled = now end
    if _credits == 0 then false else _credits = _credits - 1; true end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
    source.admitted()
    if _closed then source.consumed(); return end
    try
      let id = PeerID(from)?
      if _sessions.contains(id) then
        _sessions(id)?.received(consume data, from, false, source)
        return
      end
      if _cfg.broker and _relays.contains(id) then
        _relays(id)?.received(consume data, from, false, source)
        return
      end
      if _cfg.client or (data.size() != 140) or (not _admit()) then source.consumed(); return end
      if (data(0)? != 83) or (data(1)? != 54) or (data(2)? != 81) or (data(3)? != 49) then
        source.consumed(); return
      end
      if _cfg.broker then
        if _relays.size() >= SessionLimits.max_clients() then source.consumed(); return end
        let hello: Array[U8] val = consume data
        _relays(id) = RelaySession(_auth, _cfg.bind_host, this, _network, id, from, _peer, hello)
        _network.route(from, _relays(id)?)
      else
        if (_sessions.size() >= SessionLimits.max_clients()) or (_recent.size() >= 1024) then
          source.consumed(); return
        end
        let hello: Array[U8] val = consume data
        // Copy the authenticated nonce into an immutable buffer before using
        // it as a map key; slice() yields a mutable view in Pony 0.72.
        let nonce_bytes: Array[U8] iso = recover iso Array[U8](32) end
        for byte in hello.slice(12, 44).values() do nonce_bytes.push(byte) end
        let nonce_data: Array[U8] val = consume nonce_bytes
        let nonce = String.from_array(nonce_data)
        if _recent.contains(nonce) then source.consumed(); return end
        let peer_key = AgentHandshake.select_peer(_cfg.peer_keys, hello)?
        (let response, let token) = AgentHandshake(_cfg.seed, peer_key, hello, Time.now()._1.u64())?
        // Replay state outlives session retirement; never evict unexpired IDs.
        _recent(nonce) = Time.nanos() + 60_000_000_000
        _sessions(id) = ClientSession.agent(_auth, _cfg.bind_host, this, _network,
          from, _target, id, hello, consume response, token, _out)
        _network.route(from, _sessions(id)?)
      end
    end
    source.consumed()
  be received_batch(batch: Array[InboundDatagram iso] iso, application: Bool, source: SocketActor) =>
    // Admissions use single-packet delivery; this fallback preserves the
    // interface if a future application socket is owned by Runtime.
    batch.reverse_in_place()
    while batch.size() > 0 do
      try
        let packet = batch.pop()?
        received(packet.take(), packet.from, application, source)
      end
    end

// Each broker route has an ephemeral upstream socket so responses cannot be
// delivered to a different client's application. No plaintext or key at broker.
actor RelaySession is DatagramReceiver
  let _owner: Runtime
  let _id: String
  let _network: SocketActor
  let _upstream: SocketActor
  let _client: NetAddress val
  let _peer: NetAddress val
  let _hello: Array[U8] val
  var _last: U64 = Time.nanos()
  var _confirmed: Bool = false
  var _closed: Bool = false
  new create(auth: NetAuth, host: String, owner: Runtime, network: SocketActor,
    id: String, client: NetAddress val, peer: NetAddress val, hello: Array[U8] val)
  =>
    _owner = owner; _id = id; _network = network
    _client = client; _peer = peer; _hello = hello
    _upstream = SocketActor(auth, host, "0", this, true)
  be bound(application: Bool) => if not _closed then _upstream.send(_hello, _peer) end
  be failed() => _close()
  be close() => _close()
  fun ref _close() =>
    if not _closed then
      _closed = true; _upstream.dispose(); _network.unroute(_client, this)
      _owner.relay_retired(_id, this)
    end
  be tick(now: U64) =>
    if (now >= _last) and ((now - _last) >
      (if _confirmed then U64(60_000_000_000) else U64(5_000_000_000) end)) then _close() end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
    _receive(consume data, from, application)
    source.consumed()
  be received_batch(batch: Array[InboundDatagram iso] iso, application: Bool, source: SocketActor) =>
    let count = batch.size()
    let output = recover iso Array[Array[U8] val](16) end
    batch.reverse_in_place()
    while batch.size() > 0 do
      try
        let packet = batch.pop()?
        if not _closed then
          if application and (packet.from == _peer) then
            _confirmed = true; _last = Time.nanos()
            output.push(packet.take())
          elseif (not application) and (packet.from == _client) then
            output.push(packet.take())
          end
        end
      end
    end
    if output.size() > 0 then
      if application then _network.send_batch(consume output, _client)
      else _upstream.send_batch(consume output, _peer) end
    end
    source.consumed(count)
  fun ref _receive(data: Array[U8] iso, from: NetAddress val, application: Bool) =>
    if not _closed then
      if application and (from == _peer) then
        _confirmed = true; _last = Time.nanos(); _network.send(consume data, _client)
      elseif (not application) and (from == _client) then _upstream.send(consume data, _peer) end
    end

actor ClientSession is DatagramReceiver
  let _owner: Runtime
  let _id: String
  let _network: SocketActor
  let _app: SocketActor
  let _peer: NetAddress val
  let _out: OutStream
  let _client: Bool
  let _handshake: Handshake = Handshake
  let _session: ReliableSession = ReliableSession
  var _token: (OCapToken | None) = None
  var _local: (NetAddress val | None) = None
  var _stage: U8 = 0
  var _hello: Array[U8] val = recover val Array[U8] end
  var _retry: Array[U8] val = recover val Array[U8] end
  let _started: U64 = Time.nanos()
  var _last_activity: U64 = Time.nanos()
  var _handshake_sent: U64 = 0
  var _closed: Bool = false
  var _flow_fd: I32 = -1
  var _flow_attached: Bool = false
  var _flow_eof: Bool = false
  var _flow_drained: Bool = false
  var _network_output: Array[Array[U8] val] iso = recover iso Array[Array[U8] val](16) end
  var _app_output: Array[Array[U8] val] iso = recover iso Array[Array[U8] val](16) end
  new client(auth: NetAuth, cfg: Configuration, owner: Runtime, network: SocketActor,
    peer: NetAddress val, target: NetAddress val, id: String, out: OutStream, flow_fd: I32)
  =>
    _owner = owner; _network = network; _peer = peer; _id = id; _out = out; _client = true
    if flow_fd >= 0 then _local = target end
    _flow_fd = flow_fd
    _flow_attached = flow_fd >= 0
    _app = SocketActor(auth, cfg.bind_host, cfg.application_port.string(), this, true, flow_fd < 0)
    try
      _hello = _handshake.start(cfg.seed, cfg.peer_key, Time.now()._1.u64())?
      _retry = _hello; _stage = 1
    else _close() end
  new agent(auth: NetAuth, host: String, owner: Runtime, network: SocketActor,
    peer: NetAddress val, target: NetAddress val, id: String, hello: Array[U8] val,
    response: Array[U8] iso, token: OCapToken, out: OutStream)
  =>
    _owner = owner; _network = network; _peer = peer; _id = id; _out = out; _client = false
    _local = target; _hello = hello; _retry = consume response; _token = token; _stage = 2
    _app = SocketActor(auth, host, "0", this, true, true)
  be bound(application: Bool) =>
    if not _closed then _network.send(_retry, _peer); _handshake_sent = Time.nanos() end
  be failed() => _close()
  be close() => _close()
  fun ref _close() =>
    if not _closed then
      if _flow_fd >= 0 then
        _flow_fd = -1
        _owner.flow_failed()
      elseif _flow_eof and not _flow_drained then
        _owner.flow_failed()
      end
      _closed = true; _handshake.clear(); _token = None; _session.clear()
      _network.unroute(_peer, this)
      _app.dispose(); _owner.retired(_id, this)
    end
  be tick(now: U64) =>
    if _closed or (now < _started) then return end
    if _stage < 3 then
      if (now - _started) > 5_000_000_000 then _close()
      elseif (now >= _handshake_sent) and ((now - _handshake_sent) >= 250_000_000) then
        _network.send(_retry, _peer); _handshake_sent = now
      end
      return
    end
    if (now >= _last_activity) and ((now - _last_activity) > 60_000_000_000) then _close(); return end
    try
      for wire in _session.retransmit(now)?.values() do _send(wire) end
      _flush_output()
      _read_flow()?
      if _flow_eof and (_session.pending_count() == 0) and (_app_output.size() == 0) then
        _flow_drained = true
        _flow_fd = -1
        _owner.flow_drained(); _close()
      end
    else _close() end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
    _receive(consume data, from, application)
    _flush_output()
    source.consumed()
  be received_batch(batch: Array[InboundDatagram iso] iso, application: Bool, source: SocketActor) =>
    let count = batch.size()
    batch.reverse_in_place()
    while batch.size() > 0 do
      try
        let packet = batch.pop()?
        _receive(packet.take(), packet.from, application)
      end
    end
    _flush_output()
    source.consumed(count)
  fun ref _receive(data: Array[U8] iso, from: NetAddress val, application: Bool) =>
    if not _closed then
      try
        if application then _plaintext(consume data, from)?
        elseif from == _peer then _encrypted(consume data)? end
      end
    end
  fun ref _plaintext(data: Array[U8] iso, from: NetAddress val) ? =>
    if (_stage != 3) or (data.size() > 1172) or (not _session.can_send()) then return end
    match _local
    | let local: NetAddress val => if from != local then return end
    | None => _local = from
    end
    let token = _token as OCapToken
    let sequence = _session.next_sequence()?
    let bytes: Array[U8] val = consume data
    let packet = Frame.payload(bytes)
    let wire: Array[U8] val = token.seal(consume packet, sequence, 2)?
    _session.sent(sequence, wire, Time.nanos())
    _send(wire)
    _last_activity = Time.nanos()
  fun ref _send_flow_message(data: Array[U8] iso) ? =>
    if (_stage != 3) or (data.size() > 1172) or (not _session.can_send()) then return end
    let token = _token as OCapToken
    let sequence = _session.next_sequence()?
    let packet = Frame.payload(consume data)
    let wire: Array[U8] val = token.seal(consume packet, sequence, 2)?
    _session.sent(sequence, wire, Time.nanos())
    _send(wire)
    _last_activity = Time.nanos()
  fun ref _read_flow() ? =>
    if (_flow_fd < 0) or _flow_eof or (_stage != 3) then return end
    var count: USize = 0
    while (count < 16) and _session.can_send() do
      let input = recover iso Array[U8](1173) end
      input.undefined(1173)
      let result = @s6_app_flow_recv(_flow_fd, input.cpointer(), input.size())
      if result == -1 then return end
      if result == -2 then
        _flow_eof = true
        _owner.flow_closed()
        return
      elseif result == -3 then
        count = count + 1
      elseif result < 0 then
        _owner.failed(); _close(); return
      else
        input.truncate(result.usize())
        _send_flow_message(consume input)?
        count = count + 1
      end
    end
  fun ref _encrypted(data: Array[U8] iso) ? =>
    if _client and (_stage == 1) then
      if data.size() != 172 then return end
      let token = _handshake.finish(consume data, Time.now()._1.u64())?
      _token = token; _retry = token.seal(Frame.empty(), 1, 0)?; _stage = 2
      _send(_retry)
      return
    end
    if (not _client) and (data.size() == 140) then
      if _same(consume data, _hello) then _send(_retry) end
      return
    end
    let token = _token as OCapToken
    let packet = token.open(consume data)?
    var sequence: U64 = 0
    var i: USize = 4
    while i < 12 do sequence = (sequence << 8) or packet(i)?.u64(); i = i + 1 end
    let kind = packet(3)?
    if (not _client) and (sequence == 1) and (kind == 0) and (packet.size() == 12) then
      _retry = token.seal(Frame.empty(), 1, 1)?
      _send(_retry)
      if _stage == 2 then _stage = 3; _session.connected() end
      _last_activity = Time.nanos()
      return
    end
    if _client and (_stage == 2) and (sequence == 1) and (kind == 1) and (packet.size() == 12) then
      _stage = 3; _session.connected(); _last_activity = Time.nanos()
      _owner.established(); _out.print("ready: client")
      return
    end
    if _stage != 3 then return end
    if kind == 3 then
      if (packet.size() == 12) and _session.acknowledge(sequence, Time.nanos()) then _last_activity = Time.nanos() end
      return
    end
    if kind != 2 then return end
    packet.trim_in_place(12)
    if _session.receive_in_order(sequence) then
      // Normal ordered traffic needs neither a receive-map entry nor a
      // temporary delivery array. Drain the map only after actual reordering.
      let payload: Array[U8] val = consume packet
      if not _deliver(payload) then return end
    elseif not _session.accept_receive(sequence, consume packet) then return end
    _last_activity = Time.nanos()
    let ack = Frame.empty()
    _send(token.seal(consume ack, sequence, 3)?)
    if _session.has_buffered() then
      for payload in _session.deliver().values() do
        if not _deliver(payload) then return end
      end
    end
  fun ref _send(wire: Array[U8] val) =>
    _network_output.push(wire)
    if _network_output.size() >= 16 then _flush_network() end
  fun ref _flush_network() =>
    if _network_output.size() > 0 then
      _network.send_batch(_network_output = recover iso Array[Array[U8] val](16) end, _peer)
    end
  fun ref _flush_output() =>
    _flush_network()
    if _flow_attached and (_app_output.size() > 0) then
      let outgoing: Array[Array[U8] val] val = consume _app_output
      _app_output = recover iso Array[Array[U8] val](16) end
      let pending = recover iso Array[Array[U8] val](16) end
      var blocked = false
      for payload in outgoing.values() do
        if blocked then
          pending.push(payload)
        else
          let result = @s6_app_flow_send(_flow_fd, payload.cpointer(), payload.size())
          if result == 0 then
            blocked = true
            pending.push(payload)
          elseif result < 0 then
            _close(); return
          end
        end
      end
      _app_output = consume pending
    elseif (not _flow_attached) and (_app_output.size() > 0) then
      match _local
      | let local: NetAddress val =>
        _app.send_batch(_app_output = recover iso Array[Array[U8] val](16) end, local)
      end
    end
  fun ref _deliver(payload: Array[U8] val): Bool =>
    if _flow_attached then
      if _app_output.size() >= 256 then
        _close(); return false
      end
      _app_output.push(payload)
      _flush_output()
      not _closed
    else
      match _local
      | let local: NetAddress val =>
        _app_output.push(payload)
        if _app_output.size() >= 16 then _flush_output() end
        true
      | None => true
      end
    end
  fun _same(a: Array[U8] iso, b: Array[U8] box): Bool =>
    if a.size() != b.size() then return false end
    try
      var i: USize = 0
      while i < a.size() do if a(i)? != b(i)? then return false end; i = i + 1 end
      true
    else false end
