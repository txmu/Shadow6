## Signed Crosed v1, L0-L5 capability intersection, explicit domain binding.
import std/[macros, strutils, algorithm, times]
import strictjson, crypto

const CrosedLevel* {.intdefine.} = 0
static: doAssert CrosedLevel in 0..5
when not (defined(gcArc) or defined(gcOrc)):
  {.error: "Core-Nim must be compiled with --mm:arc or --mm:orc".}

macro capabilityMap*(entries: untyped): untyped =
  ## Validate the map at compile time; generate a direct string dispatch.
  let name = ident"name"
  var branch = newTree(nnkCaseStmt, name)
  var seen: seq[string]
  for entry in entries:
    expectKind(entry, nnkExprColonExpr)
    let cap = entry[0].strVal
    let level = entry[1].intVal
    if cap in seen or level notin 1..5: error("invalid capability table", entry)
    seen.add cap
    branch.add newTree(nnkOfBranch, newLit(cap), newLit(level))
  branch.add newTree(nnkElse, newLit(0))
  result = quote do:
    proc capabilityLevel*(`name`: string): int = `branch`

capabilityMap {
  "observe.version": 1, "observe.health": 1,
  "policy.request": 2, "policy.config": 2,
  "transport.metadata": 3, "transport.application": 3,
  "identity.assert": 4, "identity.resolve": 4,
  "core.lifecycle": 5, "core.hook": 5}

const CROSED_CAPABILITIES* = ["core.hook", "core.lifecycle", "identity.assert",
  "identity.resolve", "observe.health", "observe.version", "policy.config",
  "policy.request", "transport.application", "transport.metadata"]

proc features*(): JsonNode =
  var caps: seq[string]
  for name in CROSED_CAPABILITIES:
    if capabilityLevel(name) <= CrosedLevel: caps.add name
  result = %*{"core": "shadow6-nim", "version": "1.1.0",
    "crosed_compiled": CrosedLevel > 0, "crosed_max_level": CrosedLevel,
    "app_transport": CrosedLevel >= 3, "qubes_isolation": CrosedLevel > 0,
    "gate_compiled": false, "gate_enabled_by_default": false, "utf8": true,
    "crosed_capabilities": caps, "transport": "webrtc",
    "memory_model": (when defined(gcArc): "arc" else: "orc")}

proc identifier*(s: string): bool =
  if s.len notin 1..64 or s[0] notin Letters+Digits: return false
  for c in s:
    if c notin Letters+Digits+{'-', '_', '.'}: return false
  true
proc domain*(s: string): bool =
  if s.len notin 1..32 or s[0] notin {'a'..'z'}: return false
  for c in s:
    if c notin {'a'..'z', '0'..'9', '-'}: return false
  true
proc text*(n: JsonNode; field: string; fallback = ""): string =
  if not n.hasKey(field): return fallback
  require(n[field].kind == JString)
  n[field].getStr
proc capabilities(n: JsonNode): seq[string] =
  require(n.kind == JArray and n.len <= 10)
  for child in n:
    require(child.kind == JString)
    let cap = child.getStr
    require(capabilityLevel(cap) > 0 and cap notin result)
    result.add cap
  result.sort()
proc replay(path: cstring; digest: pointer; now: int64): cint {.importc: "nim_replay".}

proc negotiate*(requestPath, trustPath: string): JsonNode =
  result = features()
  result["status"] = %"denied"
  result["granted_level"] = %0
  result["granted_capabilities"] = newJArray()
  let request = strictJson(readOwned(requestPath))
  schema(request, "version:JInt mod_id:JString nonce:JString issued_at:JInt requested_level:JInt capabilities:JArray source_domain?:JString target_domain?:JString payload:JObject signature:JString")
  result["mod_id"] = request["mod_id"]
  let now = getTime().toUnix
  let level = request["requested_level"].getInt
  require(request["version"].getInt == 1 and identifier(request.text("mod_id")))
  discard unhex(request.text("nonce"), 16)
  require(level in 1..5 and request["issued_at"].getBiggestInt in now-300..now+300)
  let caps = capabilities(request["capabilities"])
  if CrosedLevel == 0: return
  let trust = strictJson(readOwned(trustPath))
  schema(trust, "mods:JObject domain?:JString")
  require(trust["mods"].hasKey(request.text("mod_id")))
  let policy = trust["mods"][request.text("mod_id")]
  schema(policy, "pubkey:JString max_level:JInt capabilities:JArray allowed_domains?:JArray source_domain?:JString")
  require(policy["max_level"].getInt in 1..5)
  let allowed = capabilities(policy["capabilities"])
  let signed = @["1", request.text("mod_id"), request.text("nonce"),
    $request["issued_at"].getBiggestInt, $level, caps.join(","),
    sha256(canonical(request["payload"])), request.text("source_domain"), request.text("target_domain")].join("\n")
  require(verify(policy.text("pubkey"), signed, request.text("signature")), "invalid Crosed signature")
  if level > CrosedLevel or level > policy["max_level"].getInt: return
  for cap in caps:
    if cap notin allowed or capabilityLevel(cap) > level: return
  let source = request.text("source_domain", "default")
  let target = request.text("target_domain", "default")
  require(domain(source) and domain(target))
  # Legacy trust has no source binding: it may authorize only the local default
  # domain. Explicit compartments require both independent trust bindings.
  if source != policy.text("source_domain", "default") or target != trust.text("domain", "default"): return
  if source != target:
    require(policy.hasKey("allowed_domains"))
    var found = false
    for d in policy["allowed_domains"]:
      require(d.kind == JString and domain(d.getStr))
      if d.getStr == target: found = true
    if not found: return
  let key = unhex(sha256(policy.text("pubkey") & ":" & request.text("nonce")), 32)
  require(replay((trustPath & ".replay").cstring, key.cstring, now) == 1, "replayed or saturated request")
  result["status"] = %"granted"
  result["granted_level"] = %level
  result["granted_capabilities"] = %caps
