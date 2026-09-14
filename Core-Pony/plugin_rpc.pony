use "backpressure"
use "files"
use "process"

class iso PluginRPCNotify is ProcessNotify
  let _main: Main
  var _stdout: Array[U8] iso = recover iso Array[U8] end
  var _stderr: Array[U8] iso = recover iso Array[U8] end
  var _overflow: Bool = false

  new iso create(main: Main) => _main = main

  fun ref stdout(process: ProcessMonitor ref, data: Array[U8] iso) =>
    if (_stdout.size() + data.size()) > PluginRPCLimits.max_output() then
      _overflow = true
      process.dispose()
    else
      _stdout.append(consume data)
    end

  fun ref stderr(process: ProcessMonitor ref, data: Array[U8] iso) =>
    if _stderr.size() < PluginRPCLimits.max_error() then
      let available = PluginRPCLimits.max_error() - _stderr.size()
      if data.size() > available then data.truncate(available) end
      _stderr.append(consume data)
    end

  fun ref failed(process: ProcessMonitor ref, err: ProcessError) =>
    _main.plugin_failed("plugin manager pipe failure")

  fun ref dispose(process: ProcessMonitor ref, status: ProcessExitStatus) =>
    if _overflow then
      _main.plugin_failed("plugin RPC output exceeded its bound")
      return
    end
    match status
    | let exited: Exited =>
      if exited.exit_code() == 0 then
        let output = _stdout = recover iso Array[U8] end
        _main.plugin_done(consume output)
      else
        let errors = _stderr = recover iso Array[U8] end
        _main.plugin_failed(String.from_array(consume errors))
      end
    else
      _main.plugin_failed("plugin manager terminated abnormally")
    end

primitive PluginRPCLimits
  fun max_request(): USize => 65_536
  fun max_output(): USize => 1_048_576
  fun max_error(): USize => 4_096

primitive PluginRPC
  fun start(env: Env, main: Main, id: String, capability: String,
    request: String): Bool
  =>
    ifdef "crosed_l5" then
      if (not _id(id)) or (not _capability(capability)) or
        (request.size() == 0) or (request.size() > PluginRPCLimits.max_request()) or
        request.contains(String.from_array([U8(0)]))
      then return false end
      let auth = FileAuth(env.root)
      let path = FilePath(auth, "Plugin-System/shadow6_plugins.py")
      let args: Array[String] val =
        recover val
          ["shadow6_plugins.py"; "rpc"; id; capability; request]
        end
      let vars: Array[String] val =
        recover val ["PATH=/usr/bin:/bin"; "LANG=C.UTF-8"; "PYTHONIOENCODING=utf-8"] end
      match StartProcess(StartProcessAuth(env.root),
        ApplyReleaseBackpressureAuth(env.root), PluginRPCNotify(main), path,
        args, vars)
      | let monitor: ProcessMonitor => monitor.done_writing(); true
      else false
      end
    else
      false
    end

  fun _id(value: String): Bool =>
    if (value.size() < 2) or (value.size() > PluginLimits.max_id()) then return false end
    try
      var i: USize = 0
      while i < value.size() do
        let c = value(i)?
        if not (((c >= 'a') and (c <= 'z')) or
          ((i > 0) and (c >= '0') and (c <= '9')) or
          ((i > 0) and (c == '-')))
        then return false end
        i = i + 1
      end
      true
    else false end

  fun _capability(value: String): Bool =>
    (value == "game.local") or (value == "hook.mtd.before") or
      (value == "hook.mtd.after") or (value == "rpc.target.authorize") or
      (value == "telemetry.read") or
      (value == "slot.lifecycle.before-start") or
      (value == "slot.lifecycle.after-stop") or
      (value == "slot.config.validate") or
      (value == "slot.transport.observe") or
      (value == "slot.transport.transform") or
      (value == "slot.protocol.factory") or
      (value == "slot.chat.filter") or
      (value == "slot.identity.verify") or
      (value == "slot.security.policy") or
      (value == "slot.telemetry.sink") or
      (value == "slot.assistant.eye") or
      (value == "slot.assistant.hand") or
      (value == "slot.init.decorate") or
      (value == "slot.ui.panel")
