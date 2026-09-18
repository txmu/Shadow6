module Main

import System
import Data.String
import Data.List
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.Documents
import Shadow6.Features
import Shadow6.SecurityTests

%default total

data Command = FeatureReport | Version | Help | Run | LoopbackTest
             | UdpLoopback Bits16 Bits32 | Authorize String String | SecurityTest | Unknown

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
parseArgs ["--authorize", request, trust] = Authorize request trust
parseArgs ["--udp-loopback", port, limit] = case (unsigned port, unsigned limit) of
  (Just p, Just n) => if p <= 65535 && n > 0 && n <= 10000 then UdpLoopback (cast p) (cast n) else Unknown
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
      Run => runUDP 0 10000
      LoopbackTest => runLoopback
      UdpLoopback port limit => runUDP port limit
      SecurityTest => securityTests
      Authorize request trust => do
        result <- authorizeDocuments request trust
        case result of
          Err e => reportError e
          Ok response => putStrLn ("granted " ++ response.modId ++ " L" ++ show (levelToNat response.grantedLevel))
      Unknown => reportError "Invalid arguments; use --help"
