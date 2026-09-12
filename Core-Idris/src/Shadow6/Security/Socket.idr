module Shadow6.Security.Socket

import Shadow6.Types
import Shadow6.Security.Context

%default total

public export
createSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> IO (Result String (SecurityContext level, Int))
createSocket ctx = if ctx.activeConnections >= 512 then pure (Err "Maximum connections reached (512)") else pure (Ok (record { activeConnections = S ctx.activeConnections } ctx, 3))

public export
bindSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> String -> Bits16 -> IO (Result String ())
bindSocket ctx fd addr port = if length addr > 256 then pure (Err "Address too long") else pure (Ok ())

public export
listenSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> Nat -> IO (Result String ())
listenSocket ctx fd backlog = if backlog > 128 then pure (Err "Backlog too large (max 128)") else pure (Ok ())

public export
closeSocket : {level : CrosedLevel} -> SecurityContext level -> Int -> IO (SecurityContext level)
closeSocket ctx fd = pure (record { activeConnections = pred ctx.activeConnections } ctx)
