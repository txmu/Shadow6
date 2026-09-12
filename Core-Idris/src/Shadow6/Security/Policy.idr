module Shadow6.Security.Policy

import Data.List
import Data.Vect
import Shadow6.Types

%default total

public export
data DomainLabel = RedDomain | OrangeDomain | YellowDomain | GreenDomain | BlueDomain

public export
Eq DomainLabel where
  RedDomain == RedDomain = True
  OrangeDomain == OrangeDomain = True
  YellowDomain == YellowDomain = True
  GreenDomain == GreenDomain = True
  BlueDomain == BlueDomain = True
  _ == _ = False

public export
record NonceTracker where
  constructor MkTracker
  seenNonces : List (Vect 16 Bits8)
  maxSize : Nat

public export
checkNonce : NonceTracker -> Vect 16 Bits8 -> (NonceTracker, Bool)
checkNonce tracker nonce =
  if nonce `elem` tracker.seenNonces then (tracker, False)
  else (record { seenNonces = take tracker.maxSize (nonce :: tracker.seenNonces) } tracker, True)

public export
newNonceTracker : Nat -> NonceTracker
newNonceTracker maxSize = MkTracker [] maxSize

public export
validateBoundedString : (max : Nat) -> String -> Result String String
validateBoundedString max str =
  if length str > max then Err ("String too long") else Ok str
