module Shadow6.SecurityTests

import System
import Data.Vect
import Data.Buffer
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.Security
import Shadow6.StrictJSON

%default total

check : String -> Bool -> IO ()
check name True = pure ()
check name False = putStrLn ("FAIL: " ++ name) >> exitFailure

success : Result e a -> Bool
success (Ok _) = True
success (Err _) = False

-- Keep a large negative-test length out of the caller's dependent return type.
-- Otherwise elaboration constructs a million-element Vect type needlessly.
checkRandomBound : Nat -> IO ()
checkRandomBound size = do
  oversized <- randomBytes size
  check "random bound" (not (success oversized))

export
securityTests : IO ()
securityTests = do
  check "L5 equality" (compare L5 L5 == EQ)
  let window = MkTimingWindow 1000 5 100
  check "circular timing" (timingValid 5999 window && timingValid 5005 window && not (timingValid 5500 window))
  check "negative timing" (not (timingValid (-1) window))
  check "excessive tolerance" (not (timingValid 5005 (MkTimingWindow 1000 5 500)))
  case validateTimingChannel 5999 window of
    Nothing => check "timing proof" False
    Just _ => pure ()
  check "valid JSON" (success (parseStrictJSON "{\"k\":[true,false,null,-42,\"\\uD83D\\uDE00\"]}"))
  let invalidDocuments : List String =
        ["{\"k\":1,\"k\":2}", "{\"k\":1,\"\\u006b\":2}", "[1,]", "{\"a\":1,}", "1.5", "1e2", "01", "9007199254740992", "\"\\uD800\"", "true false"]
  traverse_ (\s => check ("invalid JSON: " ++ s) (not (success (parseStrictJSON s))))
    invalidDocuments
  check "unknown schema field" (not (success (exactObject ["version"] (JObject [("extra", JNull)]))))
  let tracker = newNonceTracker 1
  let (full, accepted) = checkNonce tracker (replicate 16 1)
  let (_, repeated) = checkNonce full (replicate 16 1)
  let (_, evicted) = checkNonce full (replicate 16 2)
  check "no replay eviction" (accepted && not repeated && not evicted)
  hash <- sha256 (the (Vect 0 Bits8) [])
  case hash of
    Err e => check e False
    Ok digest => check "SHA256 vector" (bytesHex (toList digest) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  random <- randomBytes 32
  check "random allocation" (success random)
  checkRandomBound 1048577
  let ctx = MkSecurityContext L0 [] 0 0
  allocated <- allocateBounded ctx 32
  case allocated of
    Err e => check e False
    Ok (_, buffer) => do
      setBits8 buffer 0 123
      secureZero buffer
      byte <- getBits8 buffer 0
      check "wipe original buffer" (byte == 0)
  putStrLn "Idris security checks: PASS"
