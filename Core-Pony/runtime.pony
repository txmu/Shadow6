use "net"
use "time"

actor SocketActor is (UDPSocketActor & UDPLifecycleEventReceiver)
  var _udp: UDPSocket = UDPSocket.none()
  let _runtime: Runtime
  let _application: Bool
  var _busy: Bool = false

  new create(auth: NetAuth, port: String, runtime: Runtime, application: Bool) =>
    _runtime = runtime
    _application = application
    let size = DefaultReadBufferSize()
    _udp = UDPSocket(UDPAuth(auth), "127.0.0.1", port, this, this,
      size, IP4, 16)

  fun ref _socket(): UDPSocket => _udp
  fun ref _on_bind_failure() => _runtime.failed()
  fun ref _on_bound() => _runtime.bound(_application)
  fun ref _on_received(data: Array[U8] iso, from: NetAddress val): ReadAction =>
    if (not _busy) and (data.size() <= 1200) then
      _busy = true
      _runtime.received(consume data, from, _application)
    end
    // Keep the actor's receive gate open. The runtime may need to process a
    // retransmission/ACK while an application datagram is being delivered.
    YieldReading

  be ack() => _busy = false
  be send(data: Array[U8] val, target: NetAddress val) =>
    if _udp.is_open() then _udp.send_to(data, target) end

class _Tick is TimerNotify
  let _runtime: Runtime
  new iso create(runtime: Runtime) => _runtime = runtime
  fun ref apply(timer: Timer, count: U64): Bool => _runtime.tick(); true

actor Runtime
  let _cfg: Configuration
  let _main: Main
  let _out: OutStream
  let _network: SocketActor
  let _app: SocketActor
  var _peer: NetAddress val = recover NetAddress end
  var _local: (NetAddress val | None) = None
  let _handshake: Handshake = Handshake
  let _session: ReliableSession = ReliableSession
  var _token: (OCapToken | None) = None
  var _stage: U8 = 0
  var _ready_count: U8 = 0
  var _rx: U64 = 0
  var _tx: U64 = 1
  let _started: U64 = Time.nanos()
  var _handshake_started: U64 = 0
  var _next_retry: U64 = 0
  var _last_wire: Array[U8] val = recover val Array[U8] end
  var _last_sequence: U64 = 0
  var _last_sent: U64 = 0
  var _hello: Array[U8] val = recover val Array[U8] end
  var _retry: Array[U8] val = recover val Array[U8] end
  let _timers: Timers = Timers
  var _closed: Bool = false

  new create(auth: NetAuth, config: Configuration, out: OutStream, main: Main) =>
    _cfg = config
    _main = main
    _out = out
    let peer: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), "127.0.0.1", config.peer_port.string())
    try _peer = peer(0)? else _main.failed() end
    if not config.client then
      let local: Array[NetAddress] val = DNS.ip4(DNSAuth(auth), "127.0.0.1", config.application_port.string())
      try _local = local(0)? else _main.failed() end
    end
    _network = SocketActor(auth, config.listen_port.string(), this, false)
    _app = SocketActor(auth, if config.client then config.application_port.string() else "0" end, this, true)
    _timers(Timer(_Tick(this), 250_000_000, 250_000_000))

  be failed() =>
    if not _closed then _main.failed(); _close() end

  fun ref _close() =>
    _closed = true
    _handshake.clear()
    _token = None
    _network.dispose()
    _app.dispose()
    _timers.dispose()

  be bound(application: Bool) =>
    if _closed then return end
    _ready_count = _ready_count + 1
    if _ready_count != 2 then return end
    if _cfg.client then
      try
        _retry = _handshake.start(_cfg.seed, _cfg.peer_key, Time.now()._1.u64())?
        _hello = _retry
        _stage = 1
        _session.disconnected()
        _handshake_started = Time.nanos()
        _network.send(_retry, _peer)
      else failed() end
    end

  be tick() =>
    if _closed then return end
    let elapsed = Time.nanos() - _started
    if elapsed >= 300_000_000_000 then _close(); return end
    if (_stage > 0) and (_stage < 3) then
      if (Time.nanos() - _handshake_started) > 5_000_000_000 then
        if _next_retry == 0 then
          _session.disconnected()
          _next_retry = Time.nanos() + _session.retry_delay()
        elseif Time.nanos() >= _next_retry then
          try
            _handshake.clear()
            _token = None
            _stage = 1
            _retry = _handshake.start(_cfg.seed, _cfg.peer_key, Time.now()._1.u64())?
            _hello = _retry
            _handshake_started = Time.nanos()
            _next_retry = 0
            _network.send(_retry, _peer)
          end
        end
      else
        _network.send(_retry, _peer)
      end
    elseif (_stage == 3) and (_last_sequence > _rx) and ((Time.nanos() - _last_sent) > 750_000_000) then
      _network.send(_last_wire, _peer)
      _last_sent = Time.nanos()
    end

  be received(data: Array[U8] iso, from: NetAddress val, application: Bool) =>
    if not _closed then
      try
        if application then _plaintext(consume data, from)?
        elseif from == _peer then _encrypted(consume data)? end
      end
    end
    if application then _app.ack() else _network.ack() end

  fun ref _plaintext(data: Array[U8] iso, from: NetAddress val) ? =>
    if (_stage != 3) or (data.size() > 1172) then return end
    match _local
    | let local: NetAddress val => if from != local then return end
    | None => _local = from
    end
    if _tx >= 1000000 then _close(); return end
    let token = _token as OCapToken
    let frame = Frame.empty()
    let bytes: Array[U8] val = consume data
    frame.append(bytes)
    _tx = _tx + 1
    let wire: Array[U8] val = token.seal(consume frame, _tx, 2)?
    _last_wire = wire
    _last_sequence = _tx
    _last_sent = Time.nanos()
    _network.send(wire, _peer)

  fun ref _encrypted(data: Array[U8] iso) ? =>
    if (not _cfg.client) and (_stage == 0) then
      _hello = consume data
      (let response, let token) = AgentHandshake(_cfg.seed, _cfg.peer_key, _hello, Time.now()._1.u64())?
      _retry = consume response
      _token = token
      _stage = 2
      _handshake_started = Time.nanos()
      _network.send(_retry, _peer)
      return
    end
    if _cfg.client and (_stage == 1) then
      let token = _handshake.finish(consume data, Time.now()._1.u64())?
      _token = token
      _retry = token.seal(Frame.empty(), 1, 0)?
      _stage = 2
      _network.send(_retry, _peer)
      return
    end
    if (not _cfg.client) and (_stage == 2) and (data.size() == 140) then
      if _same(consume data, _hello) then _network.send(_retry, _peer) end
      return
    end
    let token = _token as OCapToken
    let packet = token.open(consume data)?
    var sequence: U64 = 0
    var index: USize = 4
    while index < 12 do sequence = (sequence << 8) or packet(index)?.u64(); index = index + 1 end
    let kind = packet(3)?
    if (not _cfg.client) and (sequence == 1) and (kind == 0) and (packet.size() == 12) then
      _retry = token.seal(Frame.empty(), 1, 1)?
      _network.send(_retry, _peer)
      if _stage == 2 then _rx = 1; _stage = 3; _out.print("ready: agent") end
      _session.connected()
      return
    end
    if _cfg.client and (_stage == 2) and (sequence == 1) and (kind == 1) and (packet.size() == 12) then
      _rx = 1; _stage = 3; _out.print("ready: client")
      _session.connected()
      return
    end
    if kind == 3 then
      _session.acknowledge(sequence)
      if sequence >= _last_sequence then _last_sequence = 0 end
      return
    end
    if (_stage != 3) or (kind != 2) then return end
    if not ReplayWindow.accept(_rx, sequence) then
      return
    end
    _rx = sequence
    packet.trim_in_place(12)
    let plaintext: Array[U8] val = consume packet
    match _local
    | let local: NetAddress val => _app.send(plaintext, local)
    end
    // ACK is emitted only after authenticated payload acceptance and local
    // delivery, so a peer never acknowledges data the application rejected.
    let ack = Frame.empty()
    try _network.send(token.seal(consume ack, sequence, 3)?, _peer) end

  fun _same(a: Array[U8] iso, b: Array[U8] box): Bool =>
    if a.size() != b.size() then return false end
    try
      var i: USize = 0
      while i < a.size() do if a(i)? != b(i)? then return false end; i = i + 1 end
      true
    else false end
