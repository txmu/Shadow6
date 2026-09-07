## Bounded control signalling and one forwarding session per endpoint process.
## The broker authenticates both directions; peer signatures bind SDP (including
## DTLS fingerprints), session identity, destination, and expiry end to end.
import std/[os, times, monotimes, base64, tables]
import strictjson, crypto, crosed, configuration, rtc, frames

proc tcpListen(): cint {.importc: "nim_tcp_listen".}
proc tcpPort(fd: cint): cint {.importc: "nim_tcp_port".}
proc tcpAccept(fd: cint): cint {.importc: "nim_tcp_accept".}
proc tcpConnect(port: cint): cint {.importc: "nim_tcp_connect".}
proc tcpRead(fd: cint; data: pointer; size: cint): cint {.importc: "nim_tcp_read".}
proc tcpWrite(fd: cint; data: pointer; size: cint): cint {.importc: "nim_tcp_write".}
proc tcpClose(fd: cint) {.importc: "nim_tcp_close".}
proc tcpHalfclose(fd: cint) {.importc: "nim_tcp_halfclose".}

proc clock(): int64 = getMonoTime().ticks div 1_000_000
proc sendJson(id: cint; node: JsonNode) =
  let encoded = canonical(node)
  require(encoded.len <= 65536 and buffered(id) < 262144)
  require(sendMessage(id, encoded.cstring, -1) == 0, "control send failed")
proc receive(id: cint; binary: bool): string =
  var buf: array[65537,char]
  var size = 65536.cint
  let status = receiveMessage(id, addr buf[0], addr size)
  if status == -3: return ""
  require(status == 0)
  if binary:
    require(size in 1..16392)
  else:
    require(size < 0 and size >= -65536)
    size = -size
    if size > 0 and buf[size-1] == '\0': dec size
  result = newString(size)
  if size > 0: copyMem(addr result[0], addr buf[0], size)
proc receiveJson(id: cint; timeout = 10000): JsonNode =
  let deadline = clock()+timeout
  while clock() < deadline:
    require(not isClosed(id))
    let data = receive(id, false)
    if data.len > 0: return strictJson(data)
    sleep(5)
  raise newException(ValueError, "control timeout")
proc awaitOpen(id: cint) =
  require(id >= 0)
  let deadline = clock()+10000
  while not isOpen(id):
    require(clock() < deadline and not isClosed(id), "connection timeout")
    sleep(5)
proc authPayload(identity, nonce: string): string =
  result = "shadow6-control-auth-v1"
  for field in [identity,nonce]:
    for shift in [24,16,8,0]: result.add char((field.len shr shift) and 255)
    result.add field
proc challenge(id: cint): string =
  result = unhex(randomHex(32),32)
  sendJson(id, %*{"version":1,"type":"challenge","nonce":base64.encode(result)})
proc getChallenge(node: JsonNode): string =
  schema(node,"version:JInt type:JString nonce:JString")
  require(node["version"].getInt == 1 and node.text("type") == "challenge")
  result = base64.decode(node.text("nonce"))
  require(result.len == 32)
proc authReply(id: cint; identity, key, nonce: string) =
  sendJson(id, %*{"version":1,"type":"auth","peer_id":identity,
    "signature":base64.encode(unhex(sign(key,authPayload(identity,nonce)),64))})
proc verifyAuth(node: JsonNode; key, identity, nonce: string) =
  schema(node,"version:JInt type:JString peer_id:JString signature:JString")
  require(node["version"].getInt == 1 and node.text("type") == "auth" and node.text("peer_id") == identity)
  require(verify(key,authPayload(identity,nonce),hex(base64.decode(node.text("signature")))), "authentication denied")

proc peerEntry(cfg: JsonNode; identity: string): tuple[entry: JsonNode, agent: bool] =
  for group in ["agents","clients"]:
    for peer in cfg[group]:
      if peer.text("id") == identity: return (peer,group == "agents")
  raise newException(ValueError,"unknown peer")

proc broker(cfg: JsonNode) =
  let address = endpoint(cfg.text("listen_addr"))
  let cert = if cfg.text("tls_cert") == "": "" else: readOwned(cfg.text("tls_cert"))
  let key = if cfg.text("tls_key") == "": "" else: readOwned(cfg.text("tls_key"))
  let server = wsServer(address.host.cstring,address.port.cint,cert.cstring,key.cstring)
  require(server >= 0)
  echo "Broker ready"
  defer: discard deleteServer(server)
  var peers = initTable[cint,string]()
  defer:
    for ws in peers.keys: discard deleteWs(ws)
  while true:
    let accepted = wsAccept()
    if accepted >= 0:
      try:
        require(peers.len < 16)
        awaitOpen(accepted)
        let nonce = challenge(accepted)
        let reply = receiveJson(accepted)
        let identity = reply.text("peer_id")
        let entry = peerEntry(cfg,identity).entry
        for existing in peers.values: require(existing != identity)
        verifyAuth(reply,entry.text("pubkey"),identity,nonce)
        authReply(accepted,"broker",cfg.text("private_key"),getChallenge(receiveJson(accepted)))
        peers[accepted] = identity
      except CatchableError:
        discard deleteWs(accepted)
    var removed: seq[cint]
    for ws, identity in peers:
      try:
        require(not isClosed(ws))
        let raw = receive(ws,false)
        if raw.len == 0: continue
        let request = strictJson(raw)
        schema(request,"jsonrpc:JString id:JInt method:JString params:JObject")
        require(request.text("jsonrpc") == "2.0" and request["id"].getInt > 0)
        case request.text("method")
        of "Core.Features": sendJson(ws,%*{"jsonrpc":"2.0","id":request["id"],"result":features()})
        of "WebRTC.Signal":
          let signal = request["params"]
          schema(signal,"session:JString sender:JString recipient:JString kind:JString sdp:JString issued_at:JInt signature:JString")
          require(signal.text("sender") == identity)
          let recipient = signal.text("recipient")
          let source = peerEntry(cfg,identity)
          let target = peerEntry(cfg,recipient)
          require(source.agent != target.agent)
          let client = if source.agent: target.entry else: source.entry
          let agent = if source.agent: identity else: recipient
          require(%agent in client["allowed_agents"])
          var unsigned = signal.copy
          unsigned.delete("signature")
          require(verify(source.entry.text("pubkey"),canonical(unsigned),signal.text("signature")))
          require(signal["issued_at"].getBiggestInt in getTime().toUnix-30..getTime().toUnix+30)
          var destination = -1.cint
          for id, name in peers:
            if name == recipient: destination = id
          require(destination >= 0,"recipient unavailable")
          sendJson(destination,request)
        else:
          sendJson(ws,%*{"jsonrpc":"2.0","id":request["id"],"error":{"code": -32601,"message":"method not found"}})
      except CatchableError: removed.add ws
    for ws in removed:
      peers.del(ws)
      discard deleteWs(ws)
    sleep(5)

proc signal(ws,pc: cint; cfg: JsonNode; session, recipient, kind: string) =
  let deadline = clock()+15000
  while gathered() == 0:
    require(clock() < deadline,"ICE gathering timeout")
    sleep(5)
  var buffer: array[16385,char]
  let size = getDescription(pc,addr buffer[0],buffer.len.cint)
  require(size > 0 and size <= buffer.len)
  let sdp = $cast[cstring](addr buffer[0])
  var document = %*{"session":session,"sender":cfg.text("id"),"recipient":recipient,
    "kind":kind,"sdp":sdp,"issued_at":getTime().toUnix}
  document["signature"] = %sign(cfg.text("private_key"),canonical(document))
  sendJson(ws,%*{"jsonrpc":"2.0","id":1,"method":"WebRTC.Signal","params":document})

proc forward(dc: cint; cfg: JsonNode; client: bool) =
  var listener = -1.cint
  var socket = -1.cint
  defer:
    tcpClose(socket)
    tcpClose(listener)
  if client:
    listener = tcpListen()
    require(listener >= 0)
    echo "Local proxy listening on 127.0.0.1:", tcpPort(listener)
    let deadline = clock()+120000
    while socket < 0:
      require(clock() < deadline and isOpen(dc))
      socket = tcpAccept(listener)
      sleep(5)
  else: socket = tcpConnect(cfg["target_port"].getInt.cint)
  require(socket >= 0)
  var outgoing, incoming: uint32
  var localEof, peerEof = false
  var pending = ""
  var offset = 0
  var buffer: array[MaxPayload,char]
  let seconds = if cfg.hasKey("auto_close_after"): cfg["auto_close_after"].getInt else: 7200
  let deadline = clock()+int64(seconds)*1000
  while not (localEof and peerEof and pending.len == 0):
    require(clock() < deadline and isOpen(dc),"session closed or expired")
    if not localEof and buffered(dc) < 131072:
      let n = tcpRead(socket,addr buffer[0],buffer.len.cint)
      if n >= 0:
        require(outgoing < high(uint32))
        var payload = newString(n)
        if n > 0: copyMem(addr payload[0],addr buffer[0],n)
        let wire = frames.encode(payload,outgoing,if n == 0: 2'u8 else: 1'u8)
        require(sendMessage(dc,wire.cstring,wire.len.cint) == 0)
        inc outgoing
        if n == 0: localEof = true
      else: require(n == -2)
    if pending.len == 0 and not peerEof:
      let wire = receive(dc,true)
      if wire.len > 0:
        require(incoming < high(uint32))
        let frame = frames.decode(wire,incoming)
        inc incoming
        if frame.header.kind == 2:
          peerEof = true
          tcpHalfclose(socket)
        else: pending = frame.payload
    if pending.len > 0:
      let n = tcpWrite(socket,unsafeAddr pending[offset],(pending.len-offset).cint)
      if n > 0:
        offset += n
        if offset == pending.len: pending = ""; offset = 0
      else: require(n == -2)
    sleep(2)

proc endpointRun(cfg: JsonNode; client: bool) =
  let ws = wsClient(cfg["broker_addrs"][0].getStr.cstring)
  require(ws >= 0)
  defer: discard deleteWs(ws)
  awaitOpen(ws)
  authReply(ws,cfg.text("id"),cfg.text("private_key"),getChallenge(receiveJson(ws)))
  let nonce = challenge(ws)
  verifyAuth(receiveJson(ws),cfg.text("broker_pubkey"),"broker",nonce)
  echo "Control authenticated"
  let pc = createPeer("")
  require(pc >= 0)
  defer: discard deletePeer(pc)
  let dc = createChannel(pc)
  require(dc >= 0)
  defer: discard deleteChannel(dc)
  let session = if client: randomHex(16) else: ""
  if client:
    require(localDescription(pc,"offer") == 0)
    signal(ws,pc,cfg,session,cfg.text("target_agent"),"offer")
  # The endpoint accepts exactly one peer session then exits. Restart is an
  # explicit supervisor operation; no unbounded replay cache or session pool.
  let request = receiveJson(ws,120000)
  schema(request,"jsonrpc:JString id:JInt method:JString params:JObject")
  require(request.text("jsonrpc") == "2.0" and request.text("method") == "WebRTC.Signal")
  let document = request["params"]
  schema(document,"session:JString sender:JString recipient:JString kind:JString sdp:JString issued_at:JInt signature:JString")
  require(document.text("recipient") == cfg.text("id"))
  require(document["issued_at"].getBiggestInt in getTime().toUnix-30..getTime().toUnix+30)
  discard unhex(document.text("session"),16)
  var unsigned = document.copy
  unsigned.delete("signature")
  let sender = document.text("sender")
  var key: string
  if client:
    require(sender == cfg.text("target_agent") and document.text("session") == session and document.text("kind") == "answer")
    key = cfg.text("agent_pubkey")
  else:
    require(cfg["client_pubkeys"].hasKey(sender) and document.text("kind") == "offer")
    key = cfg["client_pubkeys"][sender].getStr
  require(verify(key,canonical(unsigned),document.text("signature")),"unauthenticated SDP")
  require(remoteDescription(pc,document.text("sdp").cstring,document.text("kind").cstring) == 0)
  if not client:
    require(localDescription(pc,"answer") == 0)
    signal(ws,pc,cfg,document.text("session"),sender,"answer")
  awaitOpen(dc)
  forward(dc,cfg,client)

proc run*(doc: JsonNode) =
  configuration.validate(doc)
  defer: cleanup()
  let role = doc.text("role")
  if role == "broker": broker(doc[role])
  else: endpointRun(doc[role],role == "client")
