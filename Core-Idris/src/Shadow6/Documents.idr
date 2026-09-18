module Shadow6.Documents

import Data.List
import Data.Vect
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.Protocol
import Shadow6.StrictJSON
import Shadow6.Security.Policy

%default total

field : String -> List (String, StrictJSON) -> Result String StrictJSON
field key fields = maybe (Err ("Missing field: " ++ key)) Ok (lookup key fields)

text : StrictJSON -> Result String String
text (JString s) = Ok s
text _ = Err "Expected string"

integer : StrictJSON -> Result String Integer
integer (JInteger n) = Ok n
integer _ = Err "Expected integer"

strings : StrictJSON -> Result String (List String)
strings (JArray xs) = traverse text xs
strings _ = Err "Expected string array"

level : Integer -> Result String CrosedLevel
level 0 = Ok L0
level 1 = Ok L1
level 2 = Ok L2
level 3 = Ok L3
level 4 = Ok L4
level 5 = Ok L5
level _ = Err "Invalid Crosed level"

domain : String -> Result String DomainLabel
domain "red" = Ok RedDomain
domain "orange" = Ok OrangeDomain
domain "yellow" = Ok YellowDomain
domain "green" = Ok GreenDomain
domain "blue" = Ok BlueDomain
domain _ = Err "Unknown domain label"

rule : StrictJSON -> Result String DomainPolicy
rule input = do
  fields <- exactObject ["source", "target", "allowed"] input
  source <- field "source" fields >>= text >>= domain
  target <- field "target" fields >>= text >>= domain
  allowed <- field "allowed" fields
  case allowed of
    JBool permitted => Ok (MkPolicy source target permitted)
    _ => Err "Expected Boolean policy decision"

rules : StrictJSON -> Result String (List DomainPolicy)
rules (JArray xs) = if length xs > 25 then Err "Too many domain rules" else traverse rule xs
rules _ = Err "Expected domain policy array"

export
requestDocument : String -> Result String CrosedRequest
requestDocument source = do
  parsed <- parseStrictJSON source
  fields <- exactObject ["version", "mod_id", "nonce", "issued_at", "requested_level", "capabilities", "source_domain", "target_domain", "payload_hash", "signature"] parsed
  version <- field "version" fields >>= integer
  if version /= 1 then Err "Unknown request version" else do
    modId <- field "mod_id" fields >>= text
    nonce <- field "nonce" fields >>= text >>= fixedHex 16
    issued <- field "issued_at" fields >>= integer
    requested <- field "requested_level" fields >>= integer >>= level
    caps <- field "capabilities" fields >>= strings
    src <- field "source_domain" fields >>= text
    dst <- field "target_domain" fields >>= text
    hash <- field "payload_hash" fields >>= text >>= fixedHex 32
    signature <- field "signature" fields >>= text >>= fixedHex 64
    Ok (MkCrosedRequest 1 modId nonce issued requested caps (Just src) (Just dst) hash signature)

export
trustDocument : String -> Result String TrustEntry
trustDocument source = do
  parsed <- parseStrictJSON source
  fields <- exactObject ["version", "mod_id", "pubkey", "max_level", "capabilities", "allowed_domains", "source_domain", "target_domain", "domain_policies", "replay_path"] parsed
  version <- field "version" fields >>= integer
  if version /= 1 then Err "Unknown trust version" else do
    key <- field "pubkey" fields >>= text >>= fixedHex 32
    modId <- field "mod_id" fields >>= text
    maxLevel <- field "max_level" fields >>= integer >>= level
    caps <- field "capabilities" fields >>= strings
    domains <- field "allowed_domains" fields >>= strings
    src <- field "source_domain" fields >>= text
    dst <- field "target_domain" fields >>= text
    policies <- field "domain_policies" fields >>= rules
    replay <- field "replay_path" fields >>= text
    Ok (MkTrustEntry key modId maxLevel caps domains src dst policies replay)

-- Security documents use ASCII JSON; Unicode values may use JSON escapes.
readDocument : String -> IO (Result String String)
readDocument path = do
  result <- validateSecureFile path
  pure $ case result of
    Err e => Err e
    Ok file => if length file.contents > 65536 || any (> 127) file.contents
      then Err "Security document must be bounded ASCII JSON"
      else Ok (pack (map (chr . cast) file.contents))

export
authorizeDocuments : String -> String -> IO (Result String CrosedResponse)
authorizeDocuments requestPath trustPath = do
  request <- readDocument requestPath
  trust <- readDocument trustPath
  case (request >>= requestDocument, trust >>= trustDocument) of
    (Ok r, Ok t) => validateCrosedRequest r t
    (Err e, _) => pure (Err e)
    (_, Err e) => pure (Err e)
