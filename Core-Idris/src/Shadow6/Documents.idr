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
requestDocument : String -> IO (Result String CrosedRequest)
requestDocument source = do
  case parseStrictJSON source of
    Err e => pure (Err e)
    Ok parsed => case exactObject ["version", "mod_id", "nonce", "issued_at", "requested_level", "capabilities", "source_domain", "target_domain", "payload", "signature"] parsed of
      Err e => pure (Err e)
      Ok fields => do
        let version = field "version" fields >>= integer
        if version /= Ok 1 then pure (Err "Unknown request version") else do
          let modId = field "mod_id" fields >>= text
          let nonce = field "nonce" fields >>= text >>= fixedHex 16
          let issued = field "issued_at" fields >>= integer
          let requested = field "requested_level" fields >>= integer >>= level
          let caps = field "capabilities" fields >>= strings
          let src = field "source_domain" fields >>= text
          let dst = field "target_domain" fields >>= text
          let payload = field "payload" fields
          let signature = field "signature" fields >>= text >>= fixedHex 64
          case (modId, nonce, issued, requested, caps, src, dst, payload, signature) of
            (Ok m, Ok n, Ok i, Ok r, Ok c, Ok s, Ok d, Ok p, Ok sig) => do
              let payloadStr = canonicalJSON p
              let (len ** vec) = protocolToVect (stringToUtf8 payloadStr)
              hashResult <- sha256 vec
              case hashResult of
                Err e => pure (Err e)
                Ok hash => pure (Ok (MkCrosedRequest 1 m n i r c (if s == "" then Nothing else Just s) (if d == "" then Nothing else Just d) hash sig))
            _ => pure (Err "Invalid request fields")

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
  requestRes <- readDocument requestPath
  trustRes <- readDocument trustPath
  case (requestRes, trustRes) of
    (Ok reqStr, Ok trustStr) => do
      reqParsed <- requestDocument reqStr
      case (reqParsed, trustDocument trustStr) of
        (Ok r, Ok t) => validateCrosedRequest r t
        (Err e, _) => pure (Err e)
        (_, Err e) => pure (Err e)
    (Err e, _) => pure (Err e)
    (_, Err e) => pure (Err e)
