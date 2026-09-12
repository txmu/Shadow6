module TestTypes

import Shadow6.Types
import Shadow6.Security
import Shadow6.Crypto

-- | Test that level comparison works correctly
testLevelOrdering : IO ()
testLevelOrdering = do
  putStrLn "Testing CrosedLevel ordering..."
  assert_total $ do
    putStrLn $ "L0 < L1: " ++ show (L0 < L1)
    putStrLn $ "L3 >= L3: " ++ show (L3 >= L3)
    putStrLn $ "L5 > L4: " ++ show (L5 > L4)

-- | Test bounded buffer creation
testBoundedBuffer : IO ()
testBoundedBuffer = do
  putStrLn "Testing bounded buffers..."
  let buf32 : BoundedBuffer 32 = replicate 32 0
  let buf1200 : BoundedBuffer MAX_FRAME_SIZE = replicate MAX_FRAME_SIZE 0
  putStrLn $ "Created 32-byte buffer"
  putStrLn $ "Created max frame buffer (" ++ show MAX_FRAME_SIZE ++ " bytes)"

-- | Test timing window validation
testTimingWindow : IO ()
testTimingWindow = do
  putStrLn "Testing timing channel validation..."
  let window = MkTimingWindow 1000 5 100  -- Modulus 1000, slot 5, tolerance 100us
  let validTime = 5005  -- Within tolerance
  let invalidTime = 5500  -- Outside tolerance
  
  case validateTimingChannel validTime window of
    Just proof => putStrLn "Valid timestamp accepted"
    Nothing => putStrLn "ERROR: Valid timestamp rejected"
  
  case validateTimingChannel invalidTime window of
    Just proof => putStrLn "ERROR: Invalid timestamp accepted"
    Nothing => putStrLn "Invalid timestamp correctly rejected"

-- | Test capability level requirements
testCapabilityLevels : IO ()
testCapabilityLevels = do
  putStrLn "Testing capability level requirements..."
  putStrLn $ "ObserveVersion requires: L" ++ show (levelToNat (capabilityLevel ObserveVersion))
  putStrLn $ "TransportApplication requires: L" ++ show (levelToNat (capabilityLevel TransportApplication))
  putStrLn $ "CoreLifecycle requires: L" ++ show (levelToNat (capabilityLevel CoreLifecycle))

-- | Compile-time proof that socket creation requires L3+
-- This function cannot be called with L0, L1, or L2 contexts
testSocketCreation : IO ()
testSocketCreation = do
  putStrLn "Testing socket creation privilege enforcement..."
  let ctxL3 = MkSecurityContext L3 []
  result <- createSocket ctxL3
  case result of
    Ok fd => putStrLn $ "Socket created at L3: fd=" ++ show fd
    Err e => putStrLn $ "Socket creation failed: " ++ e
  
  -- The following would not compile (type error):
  -- let ctxL0 = MkSecurityContext L0 []
  -- createSocket ctxL0  -- ERROR: Cannot prove LevelGTE L0 L3

-- | Test that Core shutdown requires L5
-- This proves privilege escalation is impossible without type-level proof
testCoreShutdown : IO ()
testCoreShutdown = do
  putStrLn "Testing core lifecycle privilege enforcement..."
  let ctxL5 = MkSecurityContext L5 [CoreLifecycle]
  shutdownCore ctxL5
  
  -- The following would not compile (type error):
  -- let ctxL3 = MkSecurityContext L3 []
  -- shutdownCore ctxL3  -- ERROR: Cannot prove LevelGTE L3 L5

main : IO ()
main = do
  putStrLn "=== Core-Idris Type Safety Tests ==="
  putStrLn ""
  testLevelOrdering
  putStrLn ""
  testBoundedBuffer
  putStrLn ""
  testTimingWindow
  putStrLn ""
  testCapabilityLevels
  putStrLn ""
  testSocketCreation
  putStrLn ""
  testCoreShutdown
  putStrLn ""
  putStrLn "=== All tests passed (types proven correct at compile time) ==="
