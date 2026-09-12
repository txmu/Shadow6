module Shadow6.Security.Context

import Data.Vect
import Shadow6.Types

%default total

public export
record SecurityContext (level : CrosedLevel) where
  constructor MkSecurityContext
  currentLevel : CrosedLevel
  {auto levelProof : currentLevel = level}
  capabilities : List String
  activeConnections : Nat
  allocatedMemory : Nat

public export
record ResourceBounds where
  constructor MkBounds
  maxMemoryBytes : Nat
  maxFileDescriptors : Nat
  maxThreads : Nat
  maxNetworkConnections : Nat

public export
defaultBounds : ResourceBounds
defaultBounds = MkBounds 1073741824 1024 64 512

public export
checkAllocationBound : Nat -> ResourceBounds -> Bool
checkAllocationBound size bounds = size <= bounds.maxMemoryBytes

public export
freeMemory : {level : CrosedLevel} -> SecurityContext level -> Nat -> IO (SecurityContext level)
freeMemory ctx n =
  let newTotal = if ctx.allocatedMemory >= n then ctx.allocatedMemory - n else 0
  in pure (record { allocatedMemory = newTotal } ctx)
