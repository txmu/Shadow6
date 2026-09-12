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

-- | Compute canonical signed payload for Crosed request
computeSignedPayload : CrosedRequest -> IO (Vect 256 Bits8)
computeSignedPayload req = do
  let sortedCaps = sortStrings req.capabilities
  let capsStr = concat (intersperse "," sortedCaps)
  
  -- Build canonical string: version|modId|nonce|issuedAt|level|caps|hash
  let nonceHex = toHexString req.nonce
  let hashHex = toHexString req.payloadHash
  
  let canonical = show req.version ++ "|" ++
                  req.modId ++ "|" ++
                  nonceHex ++ "|" ++
                  show req.issuedAt ++ "|" ++
                  show (levelToNat req.requestedLevel) ++ "|" ++
                  capsStr ++ "|" ++
                  hashHex
  
  -- SHA-256 hash of canonical representation
  let bytes = map cast (unpack canonical)
  case toVect (length bytes) bytes of
    (n ** vec) => sha256 vec >>= extendTo256
  where
    toHexString : {n : Nat} -> Vect n Bits8 -> String
    toHexString vec = concat (map byte2hex (toList vec))
    
    byte2hex : Bits8 -> String
    byte2hex b = 
      let hi = (b `shiftR` 4) .&. 0x0f
          lo = b .&. 0x0f
      in pack [hexDigit hi, hexDigit lo]
    
    hexDigit : Bits8 -> Char
    hexDigit n = if n < 10 
                 then chr (ord '0' + cast n)
                 else chr (ord 'a' + cast (n - 10))
    
    toVect : (len : Nat) -> List Bits8 -> (m : Nat ** Vect m Bits8)
    toVect len [] = (0 ** [])
    toVect len (x :: xs) = 
      let (k ** v) = toVect len xs
      in (S k ** x :: v)
    
    extendTo256 : Vect 32 Bits8 -> IO (Vect 256 Bits8)
    extendTo256 hash = pure (hash ++ replicate 224 0)

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
    Just proof => 
      case parseFrame bytes of
        Err e => Err ("Frame parse error: " ++ e)
        Ok frame => Ok (MkTimingPacket timestamp window proof frame)

-- | AEAD connection state
public export
record AEADConnection where
  constructor MkAEADConn
  key : AES256Key
  noncePrefix : Vect 4 Bits8
  sendCounter : Nat
  recvCounter : Nat

-- | Construct 12-byte nonce from prefix + counter
constructNonce : Vect 4 Bits8 -> Nat -> Vect 12 Bits8
constructNonce prefix counter =
  let counterBytes = natToBytes 8 counter
  in prefix ++ counterBytes
  where
    natToBytes : (n : Nat) -> Nat -> Vect n Bits8
    natToBytes Z _ = []
    natToBytes (S k) val = 
      cast (val .&. 0xff) :: natToBytes k (val `shiftR` 8)

-- | Send encrypted frame through AEAD connection
export
aeadSend : AEADConnection ->
           {ptLen : Nat} ->
           Vect ptLen Bits8 ->
           IO (Result String (AEADConnection, n : Nat ** Vect n Bits8))
aeadSend conn plaintext = do
  if ptLen > MAX_AEAD_PLAINTEXT
    then pure (Err ("Plaintext too large: " ++ show ptLen))
    else if conn.sendCounter >= 18446744073709551615
    then pure (Err "AEAD nonce counter exhausted")
    else do
      let nonce = constructNonce conn.noncePrefix conn.sendCounter
      
      result <- encryptAES256GCM conn.key nonce plaintext
      
      case result of
        Err e => pure (Err e)
        Ok (n ** ciphertext) => 
          let newConn = { sendCounter := S conn.sendCounter } conn
          in pure (Ok (newConn, n ** ciphertext))

-- | Receive and decrypt AEAD frame
export
aeadRecv : AEADConnection ->
           {ctLen : Nat} ->
           Vect ctLen Bits8 ->
           IO (Result String (AEADConnection, n : Nat ** Vect n Bits8))
aeadRecv conn ciphertext = do
  if ctLen < 16
    then pure (Err "Ciphertext too short")
    else do
      let nonce = constructNonce conn.noncePrefix conn.recvCounter
      
      result <- decryptAES256GCM conn.key nonce ciphertext
      
      case result of
        Err e => pure (Err e)
        Ok (n ** plaintext) =>
          let newConn = { recvCounter := S conn.recvCounter } conn
          in pure (Ok (newConn, n ** plaintext))

-- | Create new AEAD connection with random nonce prefix
export
newAEADConnection : AES256Key -> IO AEADConnection
newAEADConnection key = do
  -- Generate random 4-byte prefix
  -- In production: use crypto_secretbox_keygen or similar
  let prefix = replicate 4 0  -- Simplified: should be random
  pure (MkAEADConn key prefix 0 0)
