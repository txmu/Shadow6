import std/[strutils, uri]
import strictjson, crypto, crosed

proc endpoint*(address: string): tuple[host: string, port: int] =
  let split = address.rfind(':')
  require(split > 0 and split < address.high)
  result.host = address[0..<split]
  if result.host.startsWith("[") and result.host.endsWith("]"):
    result.host = result.host[1..^2]
  require(result.host.len in 1..253)
  for c in result.host: require(c in Letters+Digits+{'.', '-', ':'})
  result.port = parseInt(address[split+1..^1])
  require(result.port in 1..65535)
proc loopback*(host: string): bool = host in ["127.0.0.1", "::1", "localhost"]
proc validate*(doc: JsonNode) =
  schema(doc, "role:JString broker?:JObject agent?:JObject client?:JObject")
  let role = doc.text("role")
  require(role in ["broker", "agent", "client"] and doc.len == 2 and doc.hasKey(role))
  let cfg = doc[role]
  if role == "broker":
    schema(cfg, "listen_addr:JString private_key:JString agents:JArray clients:JArray webhook_url?:JString stealth_mode?:JBool tls_cert?:JString tls_key?:JString")
    let address = endpoint(cfg.text("listen_addr"))
    require(cfg.text("webhook_url") == "")
    require((cfg.text("tls_cert") == "") == (cfg.text("tls_key") == ""))
    require(loopback(address.host) or cfg.text("tls_cert") != "", "non-loopback control requires WSS")
    if cfg.text("tls_cert") != "":
      discard readOwned(cfg.text("tls_cert"))
      discard readOwned(cfg.text("tls_key"))
    var names, agentNames: seq[string]
    for group in ["agents", "clients"]:
      require(cfg[group].len <= 16)
      for peer in cfg[group]:
        if group == "agents": schema(peer, "id:JString pubkey:JString")
        else: schema(peer, "id:JString pubkey:JString allowed_agents:JArray")
        require(identifier(peer.text("id")) and peer.text("id") notin names)
        names.add peer.text("id")
        discard unhex(peer.text("pubkey"), 32)
        if group == "agents": agentNames.add peer.text("id")
        else:
          var seen: seq[string]
          for name in peer["allowed_agents"]:
            require(name.kind == JString and name.getStr in agentNames and name.getStr notin seen)
            seen.add name.getStr
  else:
    if role == "agent":
      schema(cfg, "id:JString broker_addrs:JArray broker_pubkey:JString private_key:JString transport:JString target_port:JInt auto_close_after?:JInt allow_local_discovery?:JBool client_pubkeys:JObject")
      require(cfg["target_port"].getInt in 1..65535)
      if cfg.hasKey("auto_close_after"): require(cfg["auto_close_after"].getInt in 1..86400)
      require(cfg["client_pubkeys"].len <= 16)
      for name, key in cfg["client_pubkeys"]:
        require(identifier(name) and key.kind == JString)
        discard unhex(key.getStr, 32)
    else:
      schema(cfg, "id:JString broker_addrs:JArray broker_pubkey:JString private_key:JString transport:JString target_agent:JString agent_pubkey:JString on_success?:JString allow_local_discovery?:JBool")
      require(identifier(cfg.text("target_agent")) and cfg.text("on_success") == "")
      discard unhex(cfg.text("agent_pubkey"), 32)
    require(identifier(cfg.text("id")) and cfg.text("transport") == "webrtc")
    require(not cfg.hasKey("allow_local_discovery") or not cfg["allow_local_discovery"].getBool)
    discard unhex(cfg.text("broker_pubkey"), 32)
    require(cfg["broker_addrs"].len in 1..8)
    for address in cfg["broker_addrs"]:
      require(address.kind == JString and address.getStr.len <= 2048)
      let url = parseUri(address.getStr)
      require(url.scheme in ["ws", "wss"] and url.path == "/ws" and url.username == "" and url.password == "" and url.query == "" and url.anchor == "")
      require(url.scheme == "wss" or loopback(url.hostname))
      require(url.hostname.len > 0 and (url.port == "" or parseInt(url.port) in 1..65535))
  discard publicKey(cfg.text("private_key"))
