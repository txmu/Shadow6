module Shadow6.Security.Lifecycle

import Shadow6.Types
import Shadow6.Features
import Shadow6.Security.Context

%default total

%foreign "C:idris_shutdown,libsodium_ffi"
prim__shutdown : PrimIO ()

public export
shutdownCore : {level : CrosedLevel} -> {prf : LevelGTE level L5} -> SecurityContext level -> IO (Result String ())
shutdownCore ctx =
  if COMPILED_CROSED_LEVEL /= L5 || ctx.currentLevel /= L5 || not (elem "core.lifecycle" ctx.capabilities)
  then pure (Err "Lifecycle capability denied")
  else do
    primIO prim__shutdown
    pure (Ok ())
