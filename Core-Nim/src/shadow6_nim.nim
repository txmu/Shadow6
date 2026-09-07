import std/os
import strictjson, crypto, crosed, configuration, runtime

proc main() =
  let args = commandLineParams()
  if args == @["--feature-report"]: echo canonical(features())
  elif args == @["--gen-key"]:
    let seed = randomHex(32)
    echo canonical(%*{"private_key":seed,"public_key":publicKey(seed)})
  elif args.len == 4 and args[0] == "--crosed-request" and args[2] == "--crosed-trust":
    echo canonical(negotiate(args[1],args[3]))
  elif args.len in [2,3] and args[0] == "--config":
    require(args.len == 2 or args[2] in ["--check-config","--daemon"])
    let doc = strictJson(readOwned(args[1]))
    configuration.validate(doc)
    if args.len == 3 and args[2] == "--check-config": echo "Configuration valid for shadow6-nim"
    else: runtime.run(doc)
  elif args == @["--help"]:
    echo "shadow6-nim --config FILE [--check-config|--daemon] | --feature-report | --gen-key | --crosed-request FILE --crosed-trust FILE"
  else: raise newException(ValueError,"invalid command; use --help")

try: main()
except CatchableError as error:
  stderr.writeLine("shadow6-nim: request rejected: " & error.msg)
  quit(1)
