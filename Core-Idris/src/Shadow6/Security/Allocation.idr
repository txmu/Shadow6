module Shadow6.Security.Allocation

import Data.Vect
import Shadow6.Types
import Shadow6.Security.Context

%default total

public export
allocateBounded : {level : CrosedLevel} -> SecurityContext level -> (n : Nat) -> {prf : n `LTE` 1073741824 = True} -> IO (Result String (SecurityContext level, Vect n Bits8))
allocateBounded ctx n =
  let newTotal = ctx.allocatedMemory + n
  in if newTotal > 1073741824 then pure (Err "Memory limit exceeded") else pure (Ok (record { allocatedMemory = newTotal } ctx, replicate n 0))
