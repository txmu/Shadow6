module Main

import System
import Data.String
import Data.List
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.Documents
import Shadow6.Protocol
import Shadow6.Features
import Shadow6.SecurityTests

%default total

data Command = FeatureReport | Version | Help | Run | LoopbackTest
             | UdpLoopback Bits16 Bits32 | Authorize String String | SecurityTest | NativeSelfTest
             | NativeClient String Bits32 String Bits32 Bits32 String Bits32
             | NativeAgent String Bits32 String Bits32 String Bits32 String Bits32 | Unknown
             | NativeChain Int String Bits32 String Bits32 String Bits32 String Bits32

unsigned : String -> Maybe Integer
unsigned s = if null (unpack s) || not (all (\c => c >= '0' && c <= '9') (unpack s)) || length s > 10
  then Nothing else Just (cast s)

parseArgs : List String -> Command
parseArgs [] = Run
parseArgs ["run"] = Run
parseArgs ["--feature-report"] = FeatureReport
parseArgs ["--version"] = Version
parseArgs ["--help"] = Help
parseArgs ["-h"] = Help
parseArgs ["--loopback-test"] = LoopbackTest
parseArgs ["--security-test"] = SecurityTest
parseArgs ["--native-self-test"] = NativeSelfTest
parseArgs ["--chain", role, bindIP, bindPort, peerIP, peerPort, targetIP, targetPort, keyPath, limit] =
  case (unsigned bindPort, unsigned peerPort, unsigned targetPort, unsigned limit) of
    (Just b, Just p, Just t, Just n) =>
      if b > 0 && b <= 65535 && p > 0 && p <= 65535 && t > 0 && t <= 65535 && n > 0 && n <= 1000000 && elem role ["broker", "client", "agent"]
        then NativeChain (if role == "broker" then 3 else if role == "client" then 4 else 5) bindIP (cast b) peerIP (cast p) targetIP (cast t) keyPath (cast n)
        else Unknown
    _ => Unknown
parseArgs ["--authorize", request, trust] = Authorize request trust
parseArgs ["--udp-loopback", port, limit] = case (unsigned port, unsigned limit) of
  (Just p, Just n) => if p <= 65535 && n > 0 && n <= 10000 then UdpLoopback (cast p) (cast n) else Unknown
  _ => Unknown
parseArgs ["--native-client", bindIP, bindPort, peerIP, peerPort, appPort, keyPath, limit] =
  case (unsigned bindPort, unsigned peerPort, unsigned appPort, unsigned limit) of
    (Just b, Just p, Just a, Just n) => if b > 0 && b <= 65535 && p > 0 && p <= 65535 && a > 0 && a <= 65535 && n > 0 && n <= 1000000
      then NativeClient bindIP (cast b) peerIP (cast p) (cast a) keyPath (cast n) else Unknown
    _ => Unknown
parseArgs ["--native-agent", bindIP, bindPort, peerIP, peerPort, targetIP, targetPort, keyPath, limit] =
  case (unsigned bindPort, unsigned peerPort, unsigned targetPort, unsigned limit) of
    (Just b, Just p, Just t, Just n) => if b > 0 && b <= 65535 && p > 0 && p <= 65535 && t > 0 && t <= 65535 && n > 0 && n <= 1000000
      then NativeAgent bindIP (cast b) peerIP (cast p) targetIP (cast t) keyPath (cast n) else Unknown
    _ => Unknown
parseArgs _ = Unknown

reportError : String -> IO ()
reportError message = putStrLn ("Error: " ++ message) >> exitFailure

runLoopback : IO ()
runLoopback = do
  result <- secureLoopbackTest
  case result of
    Ok () => putStrLn "secure loopback integration: PASS"
    Err e => reportError e

runUDP : Bits16 -> Bits32 -> IO ()
runUDP port limit = do
  result <- daemonLoop port limit
  case result of
    Ok n => putStrLn ("udp loopback handled " ++ show n ++ " datagrams")
    Err e => reportError e

runNative : Int -> String -> Bits32 -> String -> Bits32 -> String -> Bits32 -> String -> Bits32 -> IO ()
runNative role bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit = do
  result <- nativeRelay role bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit
  case result of
    Ok n => putStrLn (if role == 3 then "native broker forwarded " ++ show n ++ " bounded frames"
                     else "native relay completed " ++ show n ++ " authenticated transactions")
    Err e => reportError e

main : IO ()
main = do
  args <- getArgs
  initialized <- initCrypto
  case initialized of
    Err e => reportError e
    Ok () => case parseArgs (drop 1 args) of
      FeatureReport => putStrLn (serializeFeatureReport featureReport)
      Version => putStrLn ("Shadow6 Core-Idris " ++ CORE_VERSION ++ "\nDependent-type checks with libsodium cryptography")
      Help => do
        putStrLn "Shadow6 Core-Idris"
        putStrLn "run | --feature-report | --version | --loopback-test | --security-test"
        putStrLn "--udp-loopback PORT PACKET_LIMIT | --authorize REQUEST_FILE TRUST_FILE"
        putStrLn "--native-client BIND_IP BIND_PORT AGENT_IP AGENT_PORT APP_PORT KEY_FILE PACKET_LIMIT"
        putStrLn "--native-agent BIND_IP BIND_PORT CLIENT_IP CLIENT_PORT TARGET_IP TARGET_PORT KEY_FILE PACKET_LIMIT"
        putStrLn "--chain ROLE BIND_IP BIND_PORT PEER_IP PEER_PORT TARGET_IP TARGET_PORT CONFIG LIMIT"
      Run => runUDP 0 10000
      LoopbackTest => runLoopback
      UdpLoopback port limit => runUDP port limit
      SecurityTest => securityTests
      NativeSelfTest => do
        result <- nativeSelfTest
        case result of
          Ok () => putStrLn "native authenticated framing: PASS"
          Err e => reportError e
      NativeClient bindIP bindPort peerIP peerPort appPort keyPath limit =>
        runNative 1 bindIP bindPort peerIP peerPort "127.0.0.1" appPort keyPath limit
      NativeAgent bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit =>
        runNative 2 bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit
      NativeChain role bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit =>
        runNative role bindIP bindPort peerIP peerPort targetIP targetPort keyPath limit
      Authorize request trust => do
        result <- authorizeDocuments request trust
        case result of
          Err e => reportError e
          Ok response => putStrLn ("granted " ++ response.modId ++ " L" ++ show (levelToNat response.grantedLevel))
      Unknown => reportError "Invalid arguments; use --help"
