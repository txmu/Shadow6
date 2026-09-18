module Shadow6.Security.Policy

import Data.List
import Data.Vect
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.StrictJSON

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
Show DomainLabel where
  show RedDomain = "red"
  show OrangeDomain = "orange"
  show YellowDomain = "yellow"
  show GreenDomain = "green"
  show BlueDomain = "blue"

public export
record SecureFileDescriptor where
  constructor MkSecureFile
  path : String
  isRegularFile : Bool
  isNotSymlink : Bool
  ownerOnly : Bool
  mode : Bits32
  contents : List Bits8

public export
MODE_0600 : Bits32
MODE_0600 = 0o600

public export
MODE_0644 : Bits32
MODE_0644 = 0o644

%foreign "C:idris_read_secure_hex,libsodium_ffi"
prim__readSecure : String -> PrimIO String

public export
validateSecureFile : String -> IO (Result String SecureFileDescriptor)
validateSecureFile path =
  if length path == 0 || length path > 4095 || elem '\0' (unpack path)
  then pure (Err "Invalid secure file path")
  else do
    raw <- primIO (prim__readSecure path)
    pure $ case hexBytes raw of
      Err _ => Err "File must be bounded, regular, owner-controlled, unlinked and mode 0600"
      Ok bytes => Ok (MkSecureFile path True True True MODE_0600 bytes)

public export
record DomainPolicy where
  constructor MkPolicy
  source : DomainLabel
  target : DomainLabel
  allowed : Bool

public export
checkDomainPolicy : List DomainPolicy -> DomainLabel -> DomainLabel -> Bool
checkDomainPolicy [] src tgt = False
checkDomainPolicy (p :: ps) src tgt =
  if p.source == src && p.target == tgt then p.allowed else checkDomainPolicy ps src tgt

public export
defaultDomainPolicies : List DomainPolicy
defaultDomainPolicies = [
  MkPolicy RedDomain RedDomain True,
  MkPolicy OrangeDomain RedDomain True,
  MkPolicy OrangeDomain OrangeDomain True,
  MkPolicy YellowDomain RedDomain True,
  MkPolicy YellowDomain OrangeDomain True,
  MkPolicy YellowDomain YellowDomain True,
  MkPolicy GreenDomain RedDomain True,
  MkPolicy GreenDomain OrangeDomain True,
  MkPolicy GreenDomain YellowDomain True,
  MkPolicy GreenDomain GreenDomain True,
  MkPolicy BlueDomain RedDomain True,
  MkPolicy BlueDomain OrangeDomain True,
  MkPolicy BlueDomain YellowDomain True,
  MkPolicy BlueDomain GreenDomain True,
  MkPolicy BlueDomain BlueDomain True
]

public export
validateStrictJSON : String -> Result String ()
validateStrictJSON json = case parseStrictJSON json of
  Err e => Err e
  Ok _ => Ok ()

public export
validateUTF8 : String -> Bool
validateUTF8 str = all (\c => ord c >= 0 && ord c <= 0x10ffff && not (ord c >= 0xd800 && ord c <= 0xdfff)) (unpack str)

public export
sanitizeForLog : String -> String
sanitizeForLog str = pack (map sanitizeChar (unpack str))
  where
    sanitizeChar : Char -> Char
    sanitizeChar c = if ord c < 32 || ord c == 127 || (ord c >= 0x202a && ord c <= 0x202e) || (ord c >= 0x2066 && ord c <= 0x2069) then ' ' else c

public export
record NonceTracker where
  constructor MkTracker
  seenNonces : List (Vect 16 Bits8)
  maxSize : Nat

public export
checkNonce : NonceTracker -> Vect 16 Bits8 -> (NonceTracker, Bool)
checkNonce tracker nonce =
  if (nonce `elem` tracker.seenNonces) || (length tracker.seenNonces >= tracker.maxSize) then (tracker, False)
  else ({ seenNonces := nonce :: tracker.seenNonces } tracker, True)

public export
newNonceTracker : Nat -> NonceTracker
newNonceTracker maxSize = MkTracker [] maxSize

public export
validateBoundedString : (max : Nat) -> String -> Result String String
validateBoundedString max str =
  if length str > max then Err ("String too long") else Ok str
