"""Object-capability authorization primitives for Crosed L5.

Tokens carry only immutable authority data; authorization is the intersection
of build level, signed request, per-plugin grant and domain policy.
"""
class val OCapGrant
  let level: U8
  let capabilities: Set[String] val
  let source_domain: String
  let target_domain: String

  new val create(level': U8, capabilities': Set[String] val,
    source: String, target: String) ?
    if level' > 5 or source.size() > 128 or target.size() > 128 then error end
    level = level'
    capabilities = capabilities'
    source_domain = source
    target_domain = target

  fun val allows(capability: String, requested_level: U8,
    domain: String): Bool =>
    (requested_level <= level) and (domain == target_domain) and
      capabilities.contains(capability)

primitive OCapAuthorize
  fun val intersection(build_level: U8, request_level: U8,
    request_caps: Set[String] val, plugin_caps: Set[String] val,
    domain_ok: Bool): OCapGrant ?
    if not domain_ok or request_level > build_level then error end
    let caps = recover val Set[String] end
    for cap in request_caps.values() do
      if plugin_caps.contains(cap) then caps.set(cap) end
    end
    OCapGrant(request_level.min(build_level), consume caps, "request", "plugin")?
