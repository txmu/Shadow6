module Shadow6.Protocol

import Data.Vect
import Data.Fin
import Data.Bits
import Data.List
import Data.String
import Data.SortedMap
import Shadow6.Types
import Shadow6.Crypto
import Shadow6.Features
import Shadow6.Security.Policy
import Shadow6.StrictJSON

%default total

-- | Crosed request structure
public export
record CrosedRequest where
  constructor MkCrosedRequest
  version : Nat
  modId : String
  nonce : Vect 16 Bits8
  issuedAt : Integer
  requestedLevel : CrosedLevel
  capabilities : List String
  sourceDomain : Maybe String
  targetDomain : Maybe String
  payloadHash : Vect 32 Bits8
  signature : Ed25519Signature

-- | Trust configuration for Mods
public export
record TrustEntry where
  constructor MkTrustEntry
  pubkey : Ed25519PublicKey
  modId : String
  maxLevel : CrosedLevel
  allowedCapabilities : List String
  allowedDomains : List String
  sourceDomain : String
  targetDomain : String
  domainPolicies : List DomainPolicy
  replayPath : String

-- | Crosed response
public export
record CrosedResponse where
  constructor MkCrosedResponse
  modId : String
  grantedLevel : CrosedLevel
  grantedCapabilities : List String
  status : String
  reason : Maybe String

-- | Capability name to level mapping
capabilityMinLevel : String -> Maybe CrosedLevel
capabilityMinLevel "observe.version" = Just L1
capabilityMinLevel "observe.health" = Just L1
capabilityMinLevel "policy.request" = Just L2
capabilityMinLevel "policy.config" = Just L2
capabilityMinLevel "transport.metadata" = Just L3
capabilityMinLevel "transport.application" = Just L3
capabilityMinLevel "identity.assert" = Just L4
capabilityMinLevel "identity.resolve" = Just L4
capabilityMinLevel "core.lifecycle" = Just L5
capabilityMinLevel "core.hook" = Just L5
capabilityMinLevel _ = Nothing

-- | Sort strings (bubble sort for totality)
sortStrings : List String -> List String
sortStrings [] = []
sortStrings (x :: xs) = insert x (sortStrings xs)
  where
    insert : String -> List String -> List String
    insert y [] = [y]
    insert y (z :: zs) = if y <= z then y :: z :: zs else z :: insert y zs

protocolHexDigit : Bits8 -> Char
protocolHexDigit n =
  if n < 10 then chr (ord '0' + cast n) else chr (ord 'a' + cast (n - 10))

protocolByteToHex : Bits8 -> String
protocolByteToHex b =
  let hi = (b `shiftR` 4) .&. 0x0f
      lo = b .&. 0x0f
  in pack [protocolHexDigit hi, protocolHexDigit lo]

protocolToHex : {n : Nat} -> Vect n Bits8 -> String
protocolToHex vec = concat (map protocolByteToHex (toList vec))

export
protocolToVect : List Bits8 -> (n : Nat ** Vect n Bits8)
protocolToVect [] = (0 ** [])
protocolToVect (x :: xs) =
  let (n ** rest) = protocolToVect xs
  in (S n ** x :: rest)

-- Signed identifiers are deliberately ASCII, making their JSON spelling and
-- UTF-8/NFC representation unique across implementations.
validName : String -> Bool
validName name = length name > 0 && length name <= 64 &&
  all (\c => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') (unpack name)

quote : String -> String
quote s = "\"" ++ s ++ "\""

-- Sorted, portable JSON with domains covered by the signature. The previous
-- delimiter/hash/padding format is intentionally not accepted.
export
computeSignedPayload : CrosedRequest -> String
computeSignedPayload req =
  "{\"capabilities\":[" ++ concat (intersperse "," (map quote (sortStrings req.capabilities))) ++
  "],\"issued_at\":" ++ show req.issuedAt ++ ",\"mod_id\":" ++ quote req.modId ++
  ",\"nonce\":" ++ quote (protocolToHex req.nonce) ++
  ",\"payload_hash\":" ++ quote (protocolToHex req.payloadHash) ++
  ",\"requested_level\":" ++ show (levelToNat req.requestedLevel) ++
  ",\"source_domain\":" ++ maybe "null" quote req.sourceDomain ++
  ",\"target_domain\":" ++ maybe "null" quote req.targetDomain ++ ",\"version\":1}"

%foreign "C:idris_reserve_nonce,libsodium_ffi"
prim__reserve : String -> String -> String -> PrimIO Int

label : String -> Maybe DomainLabel
label "red" = Just RedDomain
label "orange" = Just OrangeDomain
label "yellow" = Just YellowDomain
label "green" = Just GreenDomain
label "blue" = Just BlueDomain
label _ = Nothing

domainsAllowed : CrosedRequest -> TrustEntry -> Bool
domainsAllowed req trust = case (req.sourceDomain, req.targetDomain) of
  (Just source, Just target) =>
    validName source && validName target && source == trust.sourceDomain && target == trust.targetDomain &&
    elem target trust.allowedDomains &&
    (if COMPILED_QUBES_ISOLATION then case (label source, label target) of
       (Just src, Just dst) => checkDomainPolicy trust.domainPolicies src dst
       _ => False
     else source == target)
  _ => False

export
validateCrosedRequest : CrosedRequest -> TrustEntry -> IO (Result String CrosedResponse)
validateCrosedRequest req trust = do
  now <- currentTime
  if req.version /= 1 || not (validName req.modId) || req.modId /= trust.modId || now <= 0 ||
     req.issuedAt < 0 || req.issuedAt > 9007199254740991 || abs (now - req.issuedAt) > 300
    then pure (Err "Invalid version, Mod identity or expired timestamp")
    else if req.requestedLevel == L0 || req.requestedLevel > COMPILED_CROSED_LEVEL || req.requestedLevel > trust.maxLevel
    then pure (Err "Requested level exceeds build or Mod policy")
    else if null req.capabilities || length req.capabilities > 10 ||
            length (nub req.capabilities) /= length req.capabilities ||
            not (all (allowed req trust) req.capabilities) || not (domainsAllowed req trust)
    then pure (Err "Capability or domain policy denied")
    else if length trust.replayPath == 0 || length trust.replayPath > 4095 || elem '\0' (unpack trust.replayPath)
    then pure (Err "Invalid replay state path")
    else case protocolToVect (map (cast . ord) (unpack (computeSignedPayload req))) of
      (n ** signedData) => do
        result <- verifyEd25519 req.signature signedData trust.pubkey
        case result of
          Err e => pure (Err e)
          Ok () => do
            reserved <- primIO (prim__reserve trust.replayPath (protocolToHex trust.pubkey) (protocolToHex req.nonce))
            pure (if reserved /= 0 then Err "Replay detected or replay ledger unavailable"
                  else Ok (MkCrosedResponse req.modId req.requestedLevel (sortStrings req.capabilities) "granted" Nothing))
  where
    allowed : CrosedRequest -> TrustEntry -> String -> Bool
    allowed r t cap = elem cap t.allowedCapabilities && elem cap featureReport.crosedCapabilities &&
      case capabilityMinLevel cap of
        Just level => r.requestedLevel >= level
        Nothing => False

-- | UDP packet with timing channel validation
public export
record TimingChannelPacket where
  constructor MkTimingPacket
  timestamp : Integer
  window : TimingWindow
  timingProof : TimestampProof
  payload : NetworkFrame

-- | Parse timing-channel UDP packet
export
parseTimingPacket : Integer -> 
                    TimingWindow -> 
                    List Bits8 -> 
                    Result String TimingChannelPacket
parseTimingPacket timestamp window bytes =
  case validateTimingChannel timestamp window of
    Nothing => Err ("Timestamp " ++ show timestamp ++ " outside valid timing window")
    Just timingProof =>
      case parseFrame bytes of
        Err e => Err ("Frame parse error: " ++ e)
        Ok frame => Ok (MkTimingPacket timestamp window timingProof frame)

-- | AEAD connection state
public export
record AEADConnection where
  constructor MkAEADConn
  key : AES256Key
  noncePrefix : Vect 4 Bits8
  sendCounter : Nat
  recvCounter : Nat
