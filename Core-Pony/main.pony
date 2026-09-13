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
        ConfigReader(FileAuth(env.root), env.args(2)?, this, env.args(1)? == "--check-config")
        return
      end
    end
    env.err.print("shadow6-pony --config FILE | --check-config FILE | --feature-report")
    env.exitcode(2)

  be configured(config: Configuration val, check: Bool) =>
    if check then _env.out.print("configuration is valid")
    else
      Runtime(NetAuth(_env.root), config, _env.out, this)
    end

  be failed() =>
    _env.err.print("shadow6-pony: configuration, bind or handshake failed")
    _env.exitcode(2)

  fun feature_report(): String =>
    "{\"core\":\"shadow6-pony\",\"version\":\"1.0.0\",\"crosed_compiled\":" +
      "false" +
      ",\"crosed_max_level\":0" +
      ",\"app_transport\":false" +
      ",\"qubes_isolation\":false,\"gate_compiled\":false,\"gate_enabled_by_default\":false,\"utf8\":true,\"crosed_capabilities\":[]}" 
