module Shadow6.Security.Lifecycle

import Shadow6.Types
import Shadow6.Security.Context

%default total

public export
shutdownCore : {level : CrosedLevel} -> {prf : LevelGTE level L5} -> SecurityContext level -> IO ()
shutdownCore ctx = putStrLn "Shutting down Shadow6 Core-Idris (L5 privilege verified)"
