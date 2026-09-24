use "net"
use "time"
use "collections"

interface tag DatagramReceiver
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor)
  be bound(application: Bool)
  be failed()

actor SocketActor is (UDPSocketActor & UDPLifecycleEventReceiver)
  var _udp: UDPSocket = UDPSocket.none()
  let _receiver: DatagramReceiver
  let _application: Bool
  var _inflight: USize = 0
  new create(auth: NetAuth, host: String, port: String, receiver: DatagramReceiver, application: Bool) =>
    _receiver = receiver
    _application = application
    _udp = UDPSocket(UDPAuth(auth), host, port, this, this,
      DefaultReadBufferSize(), IP4, 16)
  fun ref _socket(): UDPSocket => _udp
  fun ref _on_bind_failure() => _receiver.failed()
  fun ref _on_bound() => _receiver.bound(_application)
  fun ref _on_received(data: Array[U8] iso, from: NetAddress val): ReadAction =>
    // Cross-actor credit bounds the mailbox when consumers are slower than UDP.
    if (data.size() <= ProtocolLimits.max_frame()) and (_inflight < 32) then
      _inflight = _inflight + 1
      _receiver.received(consume data, from, _application, this)
    end
    // UDPSocket limits each turn to 16 datagrams; retain the 32-credit
    // mailbox bound while avoiding an actor reschedule for every packet.
    KeepReading
  be consumed() => if _inflight > 0 then _inflight = _inflight - 1 end
  be send(data: Array[U8] val, target: NetAddress val) =>
    if _udp.is_open() then _udp.send_to(data, target) end

class _Tick is TimerNotify
  let _runtime: Runtime
  new iso create(runtime: Runtime) => _runtime = runtime
  fun ref apply(timer: Timer, count: U64): Bool => _runtime.tick(); true

primitive PeerID
  fun apply(from: NetAddress val): String ? =>
    (let host, let port) = from.name()?
    host + ":" + port

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
  var _reconnect_at: U64 = 0
  var _reconnect_attempt: U8 = 0
  new create(auth: NetAuth, config: Configuration, out: OutStream, err: OutStream, main: Main, debug: Bool) =>
    _auth = auth; _cfg = config; _main = main; _out = out
    try
      let peers: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), config.peer_host, config.peer_port.string())
      _peer = peers(0)?
      let targets: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), config.application_host, config.application_port.string())
      _target = targets(0)?
    else _closed = true; _main.failed() end
    _network = SocketActor(auth, config.bind_host, config.listen_port.string(), this, false)
    _timers(Timer(_Tick(this), 10_000_000, 10_000_000))
  be failed() =>
    if not _closed then
      _closed = true; _network.dispose(); _timers.dispose(); _main.failed()
      for session in _sessions.values() do session.close() end
      for relay in _relays.values() do relay.close() end
    end
  be bound(application: Bool) =>
    if _closed then return end
    if _cfg.client then
      try
        let id = PeerID(_peer)?
        _sessions(id) = ClientSession.client(_auth, _cfg, this, _network, _peer, id, _out)
      else failed() end
    else _out.print(if _cfg.broker then "ready: broker" else "ready: listener" end) end
  be tick() =>
    if _closed then return end
    let now = Time.nanos()
    if _cfg.client and (_sessions.size() == 0) and (_reconnect_at != 0) and (now >= _reconnect_at) then
      try
        let id = PeerID(_peer)?
        _sessions(id) = ClientSession.client(_auth, _cfg, this, _network, _peer, id, _out)
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
        if _cfg.client then
          _reconnect_at = Time.nanos() + SessionLimits.reconnect_delay(_reconnect_attempt)
          _reconnect_attempt = (_reconnect_attempt + 1).min(6)
        end
      end
    end
  be established() => _reconnect_attempt = 0
  be relay_retired(id: String, relay: RelaySession) =>
    try if _relays(id)? is relay then _relays.remove(id)? end end
  fun ref _admit(): Bool =>
    let now = Time.nanos()
    let extra = (now - _refilled) / 15_625_000
    if extra > 0 then _credits = (_credits + extra).min(256); _refilled = now end
    if _credits == 0 then false else _credits = _credits - 1; true end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
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
      end
    end
    source.consumed()

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
    if not _closed then _closed = true; _upstream.dispose(); _owner.relay_retired(_id, this) end
  be tick(now: U64) =>
    if (now >= _last) and ((now - _last) >
      (if _confirmed then U64(60_000_000_000) else U64(5_000_000_000) end)) then _close() end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
    if not _closed then
      if application and (from == _peer) then
        _confirmed = true; _last = Time.nanos(); _network.send(consume data, _client)
      elseif (not application) and (from == _client) then _upstream.send(consume data, _peer) end
    end
    source.consumed()

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
  new client(auth: NetAuth, cfg: Configuration, owner: Runtime, network: SocketActor,
    peer: NetAddress val, id: String, out: OutStream)
  =>
    _owner = owner; _network = network; _peer = peer; _id = id; _out = out; _client = true
    _app = SocketActor(auth, cfg.bind_host, cfg.application_port.string(), this, true)
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
    _app = SocketActor(auth, host, "0", this, true)
  be bound(application: Bool) =>
    if not _closed then _network.send(_retry, _peer); _handshake_sent = Time.nanos() end
  be failed() => _close()
  be close() => _close()
  fun ref _close() =>
    if not _closed then
      _closed = true; _handshake.clear(); _token = None; _session.clear()
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
      for wire in _session.retransmit(now)?.values() do _network.send(wire, _peer) end
    else _close() end
  be received(data: Array[U8] iso, from: NetAddress val, application: Bool, source: SocketActor) =>
    if not _closed then
      try
        if application then _plaintext(consume data, from)?
        elseif from == _peer then _encrypted(consume data)? end
      end
    end
    source.consumed()
  fun ref _plaintext(data: Array[U8] iso, from: NetAddress val) ? =>
    if (_stage != 3) or (data.size() > 1172) or (not _session.can_send()) then return end
    match _local
    | let local: NetAddress val => if from != local then return end
    | None => _local = from
    end
    let token = _token as OCapToken
    let sequence = _session.next_sequence()?
    let packet = Frame.empty()
    let bytes: Array[U8] val = consume data
    packet.append(bytes)
    let wire: Array[U8] val = token.seal(consume packet, sequence, 2)?
    _session.sent(sequence, wire, Time.nanos())
    _network.send(wire, _peer)
    _last_activity = Time.nanos()
  fun ref _encrypted(data: Array[U8] iso) ? =>
    if _client and (_stage == 1) then
      if data.size() != 172 then return end
      let token = _handshake.finish(consume data, Time.now()._1.u64())?
      _token = token; _retry = token.seal(Frame.empty(), 1, 0)?; _stage = 2
      _network.send(_retry, _peer)
      return
    end
    if (not _client) and (data.size() == 140) then
      if _same(consume data, _hello) then _network.send(_retry, _peer) end
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
      _network.send(_retry, _peer)
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
    if not _session.accept_receive(sequence, consume packet) then return end
    _last_activity = Time.nanos()
    let ack = Frame.empty()
    _network.send(token.seal(consume ack, sequence, 3)?, _peer)
    for payload in _session.deliver().values() do
      match _local
      | let local: NetAddress val => _app.send(payload, local)
      end
    end
  fun _same(a: Array[U8] iso, b: Array[U8] box): Bool =>
    if a.size() != b.size() then return false end
    try
      var i: USize = 0
      while i < a.size() do if a(i)? != b(i)? then return false end; i = i + 1 end
      true
    else false end
