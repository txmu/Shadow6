module Shadow6.Security.Socket

import Shadow6.Types
import Shadow6.Features
import Shadow6.Security.Context

%default total

%foreign "C:idris_socket_create,libsodium_ffi"
prim__create : PrimIO Int
%foreign "C:idris_socket_op,libsodium_ffi"
prim__socketOp : Int -> Int -> String -> Bits32 -> PrimIO Int

permitted : SecurityContext level -> Bool
permitted ctx = COMPILED_CROSED_LEVEL >= L3 && ctx.currentLevel >= L3 &&
  elem "transport.metadata" ctx.capabilities

public export
createSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> IO (Result String (SecurityContext level, Int))
createSocket ctx =
  if not (permitted ctx) || ctx.activeConnections >= 512 then pure (Err "Socket capability or connection limit denied")
  else do
    handle <- primIO prim__create
    pure (if handle < 0 then Err "Socket allocation failed" else Ok ({ activeConnections := S ctx.activeConnections } ctx, handle))

public export
bindSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> String -> Bits16 -> IO (Result String ())
bindSocket ctx handle addr port =
  if not (permitted ctx) || addr /= "127.0.0.1" then pure (Err "Only authorized loopback binding is allowed")
  else do
    rc <- primIO (prim__socketOp handle 0 addr (cast port))
    pure (if rc == 0 then Ok () else Err "Socket bind failed")

public export
listenSocket : {level : CrosedLevel} -> {prf : LevelGTE level L3} -> SecurityContext level -> Int -> Nat -> IO (Result String ())
listenSocket ctx handle backlog =
  if not (permitted ctx) || backlog == 0 || backlog > 128 then pure (Err "Invalid listener policy or backlog")
  else do
    rc <- primIO (prim__socketOp handle 1 "" (cast backlog))
    pure (if rc == 0 then Ok () else Err "Socket listen failed")

public export
closeSocket : {level : CrosedLevel} -> SecurityContext level -> Int -> IO (Result String (SecurityContext level))
closeSocket ctx handle = do
  rc <- primIO (prim__socketOp handle 2 "" 0)
  pure (if rc == 0 then Ok ({ activeConnections := minus ctx.activeConnections 1 } ctx)
        else Err "Unknown or already closed socket handle")
