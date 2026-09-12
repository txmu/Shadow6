module Shadow6.Types

import Data.Vect
import Data.Fin
import Data.Nat

%default total

-- | Security levels from 0 (default) to 5 (full Crosed)
public export
data CrosedLevel = L0 | L1 | L2 | L3 | L4 | L5

public export
Eq CrosedLevel where
  L0 == L0 = True
  L1 == L1 = True
  L2 == L2 = True
  L3 == L3 = True
  L4 == L4 = True
  L5 == L5 = True
  _ == _ = False

public export
Ord CrosedLevel where
  compare L0 L0 = EQ
  compare L0 _ = LT
  compare L1 L0 = GT
  compare L1 L1 = EQ
  compare L1 _ = LT
  compare L2 L0 = GT
  compare L2 L1 = GT
  compare L2 L2 = EQ
  compare L2 _ = LT
  compare L3 L0 = GT
  compare L3 L1 = GT
  compare L3 L2 = GT
  compare L3 L3 = EQ
  compare L3 _ = LT
  compare L4 L0 = GT
  compare L4 L1 = GT
  compare L4 L2 = GT
  compare L4 L3 = GT
  compare L4 L4 = EQ
  compare L4 _ = LT
  compare L5 _ = GT

public export
levelToNat : CrosedLevel -> Nat
levelToNat L0 = 0
levelToNat L1 = 1
levelToNat L2 = 2
levelToNat L3 = 3
levelToNat L4 = 4
levelToNat L5 = 5

-- | Type-level proof that a level is at least minimum required
public export
data LevelGTE : (current : CrosedLevel) -> (required : CrosedLevel) -> Type where
  LGTE : {current : CrosedLevel} -> {required : CrosedLevel} ->
         {auto prf : levelToNat current >= levelToNat required = True} ->
         LevelGTE current required

-- | Bounded byte vector with compile-time length constraint
public export
BoundedBuffer : Nat -> Type
BoundedBuffer n = Vect n Bits8

-- | Network frame with proven max size (1200 bytes UDP safety)
public export
MAX_FRAME_SIZE : Nat
MAX_FRAME_SIZE = 1200

public export
NetworkFrame : Type
NetworkFrame = (n : Nat ** (LTE n MAX_FRAME_SIZE, BoundedBuffer n))

-- | AEAD plaintext maximum (1 MiB)
public export
MAX_AEAD_PLAINTEXT : Nat
MAX_AEAD_PLAINTEXT = 1048576

-- | Timing window parameters for timing-channel UDP
public export
record TimingWindow where
  constructor MkTimingWindow
  modulus : Nat
  slotId : Fin modulus  -- Slot ID must be < modulus
  toleranceMicros : Nat  -- Jitter tolerance in microseconds

-- | Timestamp with modular arithmetic proof
public export
record TimestampProof where
  constructor MkTimestampProof
  timestampMicros : Integer
  window : TimingWindow
  -- Proof that timestamp mod modulus == slotId
  valid : (cast timestampMicros `mod` cast window.modulus = cast (finToNat window.slotId))

-- | Safe index into bounded buffer - prevents out-of-bounds access
public export
safeIndex : {n : Nat} -> Vect n a -> Fin n -> a
safeIndex xs i = index i xs

-- | Capability names at type level
public export
data Capability = ObserveVersion | ObserveHealth
                | PolicyRequest | PolicyConfig
                | TransportMetadata | TransportApplication
                | IdentityAssert | IdentityResolve
                | CoreLifecycle | CoreHook

public export
Eq Capability where
  ObserveVersion == ObserveVersion = True
  ObserveHealth == ObserveHealth = True
  PolicyRequest == PolicyRequest = True
  PolicyConfig == PolicyConfig = True
  TransportMetadata == TransportMetadata = True
  TransportApplication == TransportApplication = True
  IdentityAssert == IdentityAssert = True
  IdentityResolve == IdentityResolve = True
  CoreLifecycle == CoreLifecycle = True
  CoreHook == CoreHook = True
  _ == _ = False

public export
capabilityLevel : Capability -> CrosedLevel
capabilityLevel ObserveVersion = L1
capabilityLevel ObserveHealth = L1
capabilityLevel PolicyRequest = L2
capabilityLevel PolicyConfig = L2
capabilityLevel TransportMetadata = L3
capabilityLevel TransportApplication = L3
capabilityLevel IdentityAssert = L4
capabilityLevel IdentityResolve = L4
capabilityLevel CoreLifecycle = L5
capabilityLevel CoreHook = L5

-- | Proven capability grant - type enforces level requirement
public export
data CapabilityGrant : (cap : Capability) -> (level : CrosedLevel) -> Type where
  Grant : {cap : Capability} -> {level : CrosedLevel} ->
          {auto prf : LevelGTE level (capabilityLevel cap)} ->
          CapabilityGrant cap level

-- | Ed25519 public key (32 bytes)
public export
Ed25519PublicKey : Type
Ed25519PublicKey = Vect 32 Bits8

-- | Ed25519 signature (64 bytes)
public export
Ed25519Signature : Type
Ed25519Signature = Vect 64 Bits8

-- | Nonce (16 bytes minimum)
public export
Nonce : Type
Nonce = Vect 16 Bits8

-- | AES-256 key
public export
AES256Key : Type
AES256Key = Vect 32 Bits8

-- | Result type for operations that can fail
public export
data Result : Type -> Type -> Type where
  Ok : a -> Result e a
  Err : e -> Result e a

public export
Functor (Result e) where
  map f (Ok x) = Ok (f x)
  map _ (Err e) = Err e

public export
Applicative (Result e) where
  pure = Ok
  (Ok f) <*> (Ok x) = Ok (f x)
  (Err e) <*> _ = Err e
  _ <*> (Err e) = Err e

public export
Monad (Result e) where
  (Ok x) >>= f = f x
  (Err e) >>= _ = Err e
