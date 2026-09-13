use "net"
use "files"
use "lib:sodium"
use @sodium_init[I32]()

actor Main
  let _env: Env
  new create(env: Env) =>
    _env = env
    if @sodium_init() < 0 then env.exitcode(2); return end
    try
      if (env.args.size() == 2) and (env.args(1)? == "--feature-report") then
        env.out.print(feature_report())
        return
      end
      if (env.args.size() == 3) and ((env.args(1)? == "--config") or
        (env.args(1)? == "--check-config")) then
        ConfigReader(FileAuth(env.root), env.args(2)?, this, env.args(1)? == "--check-config", false)
        return
      end
      if (env.args.size() == 4) and (env.args(1)? == "--config") and (env.args(3)? == "--debug") then
        ConfigReader(FileAuth(env.root), env.args(2)?, this, false, true)
        return
      end
    end
    env.err.print("shadow6-pony --config FILE | --check-config FILE | --feature-report")
    env.exitcode(2)

  be configured(config: Configuration val, check: Bool, debug: Bool) =>
    if check then _env.out.print("configuration is valid")
    else
      Runtime(NetAuth(_env.root), config, _env.out, _env.err, this, debug)
    end

  be failed() =>
    _env.err.print("shadow6-pony: configuration, bind or handshake failed")
    _env.exitcode(2)

  fun feature_report(): String =>
    let compiled = ifdef "crosed_l5" then "true" else "false" end
    let level = ifdef "crosed_l5" then "5" else "0" end
    let app = ifdef "crosed_l5" then "true" else "false" end
    let qubes = ifdef "crosed_l5" then "true" else "false" end
    let caps = ifdef "crosed_l5" then
      "[\"core.hook\",\"core.lifecycle\",\"identity.assert\",\"identity.resolve\",\"observe.health\",\"observe.version\",\"policy.config\",\"policy.request\",\"transport.application\",\"transport.metadata\"]"
    else "[]" end
    "{\"core\":\"shadow6-pony\",\"version\":\"1.0.0\",\"crosed_compiled\":" +
      compiled + ",\"crosed_max_level\":" + level +
      ",\"app_transport\":" + app + ",\"qubes_isolation\":" + qubes +
      ",\"gate_compiled\":false,\"gate_enabled_by_default\":false,\"utf8\":true,\"transport\":\"udp\",\"crosed_capabilities\":" + caps + "}"
