module Shadow6.Crypto

import Data.Vect
import Data.Fin
import Data.Bits
import Data.Buffer
import Decidable.Equality
import Shadow6.Types

%default total

%foreign "C:idris_sodium_init,libsodium_ffi"
prim__init : PrimIO Int
%foreign "C:idris_crypto_hex,libsodium_ffi"
prim__crypto : Int -> String -> String -> String -> String -> PrimIO String
%foreign "C:idris_random_hex,libsodium_ffi"
prim__random : Bits32 -> PrimIO String
%foreign "C:idris_now,libsodium_ffi"
prim__now : PrimIO Bits64
%foreign "C:idris_secure_loopback_test,libsodium_ffi"
prim__loopback : PrimIO Int
%foreign "C:idris_daemon_loop,libsodium_ffi"
prim__daemon : Bits16 -> Bits32 -> PrimIO Int

public export
bytesHex : List Bits8 -> String
bytesHex bytes = concat (map encode bytes)
  where
    digit : Bits8 -> Char
    digit n = if n < 10 then chr (ord '0' + cast n) else chr (ord 'a' + cast n - 10)
    encode : Bits8 -> String
    encode b = pack [digit (b `shiftR` 4), digit (b .&. 15)]

public export
hexBytes : String -> Result String (List Bits8)
hexBytes value = decode (unpack value)
  where
    digit : Char -> Maybe Bits8
    digit c = if c >= '0' && c <= '9' then Just (cast (ord c - ord '0'))
              else if c >= 'a' && c <= 'f' then Just (cast (ord c - ord 'a' + 10))
              else Nothing
    decode : List Char -> Result String (List Bits8)
    decode [] = Ok []
    decode (a :: b :: rest) = case (digit a, digit b, decode rest) of
      (Just hi, Just lo, Ok xs) => Ok ((hi * 16 + lo) :: xs)
      _ => Err "Invalid hex or cryptographic operation failed"
    decode _ = Err "Invalid hex length"

public export
listVect : List a -> (n : Nat ** Vect n a)
listVect [] = (0 ** [])
listVect (x :: xs) = let (n ** rest) = listVect xs in (S n ** x :: rest)

public export
fixedHex : (n : Nat) -> String -> Result String (Vect n Bits8)
fixedHex n text = case hexBytes text of
  Err e => Err e
  Ok bytes => case listVect bytes of
    (m ** values) => case decEq m n of
      Yes Refl => Ok values
      No _ => Err "Cryptographic output length mismatch"

export
initCrypto : IO (Result String ())
initCrypto = do
  rc <- primIO prim__init
  pure (if rc >= 0 then Ok () else Err "libsodium initialization failed")

-- Wipe the supplied mutable buffer itself, not a copy of an immutable Vect.
export
secureZero : Buffer -> IO ()
secureZero buf = do
  size <- rawSize buf
  clear 0 (cast size)
  where
    clear : Int -> Nat -> IO ()
    clear offset Z = pure ()
    clear offset (S n) = setByte buf offset 0 >> clear (offset + 1) n

export
currentTime : IO Integer
currentTime = map cast (primIO prim__now)

export
verifyEd25519 : {msgLen : Nat} -> Ed25519Signature -> Vect msgLen Bits8 -> Ed25519PublicKey -> IO (Result String ())
verifyEd25519 sig msg key =
  if msgLen > MAX_AEAD_PLAINTEXT then pure (Err "Signed message too large")
  else do
    result <- primIO (prim__crypto 1 (bytesHex (toList key)) "" (bytesHex (toList msg)) (bytesHex (toList sig)))
    pure (if result == "ok" then Ok () else Err "Ed25519 signature verification failed")

export
validateTimingChannel : Integer -> TimingWindow -> Maybe TimestampProof
validateTimingChannel timestamp window = case decEq (timingValid timestamp window) True of
  Yes prf => Just (MkTimestampProof timestamp window prf)
  No _ => Nothing

export
parseFrame : List Bits8 -> Result String NetworkFrame
parseFrame bytes = if length bytes > MAX_FRAME_SIZE || null bytes then Err "Invalid frame length"
  else case listVect bytes of
    (n ** vec) => case isLTE n MAX_FRAME_SIZE of
      Yes prf => Ok (n ** (prf, vec))
      No _ => Err "Frame too large"

export
encryptAES256GCM : {ptLen : Nat} -> AES256Key -> Vect 12 Bits8 -> Vect ptLen Bits8 -> IO (Result String (n : Nat ** Vect n Bits8))
encryptAES256GCM key nonce plaintext =
  if ptLen > MAX_AEAD_PLAINTEXT then pure (Err "Plaintext too large")
  else do
    result <- primIO (prim__crypto 2 (bytesHex (toList key)) (bytesHex (toList nonce)) (bytesHex (toList plaintext)) "")
    pure $ case fixedHex (ptLen + 16) result of
      Err e => Err e
      Ok bytes => Ok (ptLen + 16 ** bytes)

export
decryptAES256GCM : {ctLen : Nat} -> AES256Key -> Vect 12 Bits8 -> Vect ctLen Bits8 -> IO (Result String (n : Nat ** Vect n Bits8))
decryptAES256GCM key nonce ciphertext =
  if ctLen < 16 || ctLen > MAX_AEAD_PLAINTEXT + 16 then pure (Err "Invalid ciphertext length")
  else do
    result <- primIO (prim__crypto 3 (bytesHex (toList key)) (bytesHex (toList nonce)) (bytesHex (toList ciphertext)) "")
    pure $ case fixedHex (minus ctLen 16) result of
      Err e => Err e
      Ok bytes => Ok (minus ctLen 16 ** bytes)

export
sha256 : {n : Nat} -> Vect n Bits8 -> IO (Result String (Vect 32 Bits8))
sha256 input = if n > MAX_AEAD_PLAINTEXT then pure (Err "Hash input too large") else do
  result <- primIO (prim__crypto 0 "" "" (bytesHex (toList input)) "")
  pure (fixedHex 32 result)

export
randomBytes : (n : Nat) -> IO (Result String (Vect n Bits8))
randomBytes n = if n > MAX_AEAD_PLAINTEXT then pure (Err "Random output too large") else do
  result <- primIO (prim__random (cast n))
  pure (fixedHex n result)

export
secureLoopbackTest : IO (Result String ())
secureLoopbackTest = do
  rc <- primIO prim__loopback
  pure (if rc == 0 then Ok () else Err ("Secure loopback failed: " ++ show rc))

export
daemonLoop : Bits16 -> Bits32 -> IO (Result String Int)
daemonLoop port limit = do
  rc <- primIO (prim__daemon port limit)
  pure (if rc < 0 then Err "Loopback UDP operation failed" else Ok rc)
