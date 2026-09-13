// OCAP-style Crosed authorization. Grants are immutable and attenuated.

class val CrosedGrant
  let build_level: U8
  let request_level: U8
  let mod_level: U8
  let signed: Bool
  let capability: String
  let source_domain: String
  let target_domain: String

  new val create(build: U8, request: U8, mod: U8, is_signed: Bool,
    name: String, source: String, target: String) ?
  =>
    if build > 5 then error end
    if request > 5 then error end
    if mod > 5 then error end
    if (name.size() == 0) or (name.size() > 96) then error end
    if (source.size() > 128) or (target.size() > 128) then error end
    build_level = build
    request_level = request
    mod_level = mod
    signed = is_signed
    capability = name.clone()
    source_domain = source.clone()
    target_domain = target.clone()

  fun allows(domain: String): Bool =>
    signed and (build_level == 5) and (request_level <= build_level) and
      (mod_level >= request_level) and (domain == target_domain) and
      (source_domain != target_domain)

primitive CrosedCapabilities
  fun level(name: String): U8 =>
    if (name == "observe.version") or (name == "observe.health") then 1
    elseif (name == "policy.request") or (name == "policy.config") then 2
    elseif (name == "transport.metadata") or (name == "transport.application") then 3
    elseif (name == "identity.assert") or (name == "identity.resolve") then 4
    elseif (name == "core.lifecycle") or (name == "core.hook") then 5
    else 0
    end

  fun authorize(grant: CrosedGrant, domain: String): Bool =>
    (level(grant.capability) > 0) and
      (level(grant.capability) <= grant.request_level) and
      grant.allows(domain)
