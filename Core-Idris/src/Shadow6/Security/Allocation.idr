module Shadow6.Security.Allocation

import Data.Buffer
import Shadow6.Types
import Shadow6.Security.Context

%default total

-- Real byte storage; a List Bits8 would consume many times the accounted size.
public export
allocateBounded : {level : CrosedLevel} -> SecurityContext level -> (n : Nat) -> IO (Result String (SecurityContext level, Buffer))
allocateBounded ctx n =
  if n == 0 || n > 1048576 || ctx.allocatedMemory + n > 1073741824
  then pure (Err "Memory limit exceeded")
  else do
    Just buffer <- newBuffer (cast n)
      | Nothing => pure (Err "Buffer allocation failed")
    pure (Ok ({ allocatedMemory := ctx.allocatedMemory + n } ctx, buffer))
