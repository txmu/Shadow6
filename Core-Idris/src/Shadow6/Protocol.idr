module Shadow6.Protocol

import Data.Vect
import Data.Fin
import Data.List
import Data.String
import Data.SortedMap
import Shadow6.Types
import Shadow6.Crypto

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
  maxLevel : CrosedLevel
  allowedCapabilities : List String
  allowedDomains : List String

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

protocolToVect : List Bits8 -> (n : Nat ** Vect n Bits8)
protocolToVect [] = (0 ** [])
protocolToVect (x :: xs) =
  let (n ** rest) = protocolToVect xs
  in (S n ** x :: rest)

protocolExtendHash : Vect 32 Bits8 -> IO (Vect 256 Bits8)
protocolExtendHash hash = pure (hash ++ replicate 224 0)

-- | Compute canonical signed payload for Crosed request
computeSignedPayload : CrosedRequest -> IO (Vect 256 Bits8)
computeSignedPayload req = do
  let sortedCaps = sortStrings req.capabilities
  let capsStr = concat (intersperse "," sortedCaps)
  
  -- Build canonical string: version|modId|nonce|issuedAt|level|caps|hash
  let nonceHex = protocolToHex req.nonce
  let hashHex = protocolToHex req.payloadHash
  
  let canonical = show req.version ++ "|" ++
                  req.modId ++ "|" ++
                  nonceHex ++ "|" ++
                  show req.issuedAt ++ "|" ++
                  show (levelToNat req.requestedLevel) ++ "|" ++
                  capsStr ++ "|" ++
                  hashHex
  
  -- SHA-256 hash of canonical representation
  let bytes = map cast (unpack canonical)
  case protocolToVect bytes of
    (n ** vec) => sha256 vec >>= protocolExtendHash

-- | Validate Crosed request with full signature verification
export
validateCrosedRequest : CrosedRequest -> 
                        TrustEntry -> 
                        IO (Result String CrosedResponse)
validateCrosedRequest req trust = do
  -- Check timestamp freshness (5 minute window)
  -- In production: get current time and check |now - issuedAt| < 300
  
  -- Compute canonical signed payload
  signedData <- computeSignedPayload req
  
  -- Verify Ed25519 signature
  sigResult <- verifyEd25519 req.signature signedData trust.pubkey
  
  case sigResult of
    Err e => pure (Err ("Signature verification failed: " ++ e))
    Ok () => do
      -- Grant intersection of requested and allowed
      let grantedLevel = minLevel req.requestedLevel trust.maxLevel
      let grantedCaps = filter (\c => elem c trust.allowedCapabilities) req.capabilities
      
      -- Validate all granted capabilities meet level requirement
      let validCaps = filter (meetsLevelReq grantedLevel) grantedCaps
      
      -- Check domain policy if specified
      case req.targetDomain of
        Just target => 
          if not (elem target trust.allowedDomains)
          then pure (Err ("Target domain not allowed: " ++ target))
          else buildResponse validCaps grantedLevel
        Nothing => buildResponse validCaps grantedLevel
  where
    minLevel : CrosedLevel -> CrosedLevel -> CrosedLevel
    minLevel a b = if a <= b then a else b
    
    meetsLevelReq : CrosedLevel -> String -> Bool
    meetsLevelReq level cap =
      case capabilityMinLevel cap of
        Nothing => False
        Just reqLevel => level >= reqLevel
    
    buildResponse : List String -> CrosedLevel -> IO (Result String CrosedResponse)
    buildResponse caps level = pure (Ok (MkCrosedResponse
      req.modId
      level
      (sortStrings caps)
      "granted"
      Nothing))

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
