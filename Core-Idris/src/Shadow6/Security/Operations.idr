module Shadow6.Security.Operations

import Data.Vect
import Shadow6.Types
import Shadow6.Security.Context

%default total

public export
createSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> IO (Result String (SecurityContext level, Int))
createSocket ctx =
  if ctx.activeConnections >= 512 then pure (Err "Maximum connections reached (512)")
  else pure (Ok (record { activeConnections = S ctx.activeConnections } ctx, 3))

public export
bindSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> String -> Bits16 -> IO (Result String ())
bindSocket ctx fd addr port = if length addr > 256 then pure (Err "Address too long") else pure (Ok ())

public export
listenSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> Nat -> IO (Result String ())
listenSocket ctx fd backlog = if backlog > 128 then pure (Err "Backlog too large (max 128)") else pure (Ok ())

public export
closeSocket : {level : CrosedLevel} -> SecurityContext level -> Int -> IO (SecurityContext level)
closeSocket ctx fd = pure (record { activeConnections = pred ctx.activeConnections } ctx)

public export
shutdownCore : {level : CrosedLevel} -> {prf : LevelGTE level L5} -> SecurityContext level -> IO ()
shutdownCore ctx = putStrLn "Shutting down Shadow6 Core-Idris (L5 privilege verified)"

public export
allocateBounded : {level : CrosedLevel} -> SecurityContext level -> (n : Nat) -> {prf : n `LTE` 1073741824 = True} -> IO (Result String (SecurityContext level, Vect n Bits8))
allocateBounded ctx n =
  let newTotal = ctx.allocatedMemory + n
  in if newTotal > 1073741824 then pure (Err "Memory limit exceeded")
     else pure (Ok (record { allocatedMemory = newTotal } ctx, replicate n 0))
