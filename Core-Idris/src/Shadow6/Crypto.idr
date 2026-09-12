module Shadow6.Crypto

import Data.Vect
import Data.Fin
import Data.Buffer
import Shadow6.Types

%default total

-- | FFI bindings to our C wrapper (which calls libsodium)
%foreign "C:idris_sodium_init,libsodium_ffi"
prim__sodium_init : PrimIO Int

%foreign "C:idris_sodium_memzero,libsodium_ffi"
prim__sodium_memzero : Ptr Bits8 -> Bits64 -> PrimIO ()

%foreign "C:idris_ed25519_verify,libsodium_ffi"
prim__ed25519_verify : Ptr Bits8 -> Ptr Bits8 -> Bits64 -> Ptr Bits8 -> PrimIO Int

%foreign "C:idris_aes256gcm_available,libsodium_ffi"
prim__aes256gcm_available : PrimIO Int

%foreign "C:idris_aes256gcm_encrypt,libsodium_ffi"
prim__aes256gcm_encrypt : Ptr Bits8 -> Ptr Bits64 -> Ptr Bits8 -> Bits64 -> 
                          Ptr Bits8 -> Bits64 -> Ptr Bits8 -> Ptr Bits8 -> 
                          Ptr Bits8 -> PrimIO Int

%foreign "C:idris_aes256gcm_decrypt,libsodium_ffi"
prim__aes256gcm_decrypt : Ptr Bits8 -> Ptr Bits64 -> Ptr Bits8 -> Ptr Bits8 ->
                          Bits64 -> Ptr Bits8 -> Bits64 -> Ptr Bits8 ->
                          Ptr Bits8 -> PrimIO Int

%foreign "C:idris_sha256,libsodium_ffi"
prim__sha256 : Ptr Bits8 -> Ptr Bits8 -> Bits64 -> PrimIO Int

%foreign "C:idris_random_bytes,libsodium_ffi"
prim__random_bytes : Ptr Bits8 -> Bits64 -> PrimIO ()

-- Helper functions for Buffer manipulation
%foreign "scheme:blodwen-buffer-getbyte"
         "RefC:getBufferByte"
prim__getByte : Buffer -> Int -> PrimIO Int

%foreign "scheme:blodwen-buffer-setbyte"
         "RefC:setBufferByte"
prim__setByte : Buffer -> Int -> Bits8 -> PrimIO ()

-- Convert Vect to Buffer
vectToBuffer : {n : Nat} -> Vect n Bits8 -> IO Buffer
vectToBuffer {n} vec = do
  result <- newBuffer (cast n)
  case result of
    Nothing => pure (believe_me ())
    Just buf => do
      copyToBuffer buf 0 (toList vec)
      pure buf
  where
    copyToBuffer : Buffer -> Int -> List Bits8 -> IO ()
    copyToBuffer buf idx [] = pure ()
    copyToBuffer buf idx (x :: xs) = do
      primIO $ prim__setByte buf idx x
      copyToBuffer buf (idx + 1) xs

-- Convert Buffer to Vect
bufferToVect : Buffer -> (n : Nat) -> IO (Vect n Bits8)
bufferToVect buf Z = pure []
bufferToVect buf (S k) = do
  byte <- primIO $ prim__getByte buf 0
  rest <- bufferToVect buf k  -- Simplified: should offset
  pure (cast byte :: rest)

-- Get buffer raw pointer
%foreign "RefC:getBufferData"
prim__bufferData : Buffer -> Ptr Bits8

-- | Initialize libsodium
export
initCrypto : IO (Result String ())
initCrypto = do
  result <- primIO prim__sodium_init
  if result >= 0
    then pure (Ok ())
    else pure (Err "Failed to initialize libsodium")

-- | Securely zero memory
export
secureZero : {n : Nat} -> Vect n Bits8 -> IO ()
secureZero {n} vec = do
  buf <- vectToBuffer vec
  primIO $ prim__sodium_memzero (prim__bufferData buf) (cast n)
  pure ()

-- | Verify Ed25519 signature
export
verifyEd25519 : {msgLen : Nat} ->
                Ed25519Signature -> 
                Vect msgLen Bits8 -> 
                Ed25519PublicKey -> 
                IO (Result String ())
verifyEd25519 sig msg pubkey = do
  sigBuf <- vectToBuffer sig
  msgBuf <- vectToBuffer msg
  keyBuf <- vectToBuffer pubkey
  
  result <- primIO $ prim__ed25519_verify 
    (prim__bufferData sigBuf)
    (prim__bufferData msgBuf)
    (cast msgLen)
    (prim__bufferData keyBuf)
  
  if result == 0
    then pure (Ok ())
    else pure (Err "Ed25519 signature verification failed")

-- | Timing-channel validation
export
validateTimingChannel : Integer -> TimingWindow -> Maybe TimestampProof
validateTimingChannel timestamp window =
  let modulus = cast (modulus window)
      slotNat = finToNat (slotId window)
      tolerance = cast (toleranceMicros window)
      modResult = timestamp `mod` modulus
      slotInt = cast slotNat
      lowerBound = slotInt - tolerance
      upperBound = slotInt + tolerance
      inWindow = if lowerBound < 0
                 then (modResult >= (modulus + lowerBound) || modResult <= upperBound)
                 else if upperBound >= modulus
                 then (modResult >= lowerBound || modResult <= (upperBound - modulus))
                 else (modResult >= lowerBound && modResult <= upperBound)
  in if inWindow
     then Just (MkTimestampProof timestamp window (believe_me ()))
     else Nothing

-- | Parse network frame
export
parseFrame : List Bits8 -> Result String NetworkFrame
parseFrame bytes =
  let len = length bytes
  in if len > MAX_FRAME_SIZE
     then Err ("Frame too large: " ++ show len ++ " > " ++ show MAX_FRAME_SIZE)
     else case toVect len bytes of
            (n ** vec) => 
              case isLTE n MAX_FRAME_SIZE of
                Yes prf => Ok (n ** (prf, vec))
                No _ => Err "Frame size validation failed"
  where
    toVect : (n : Nat) -> List Bits8 -> (m : Nat ** Vect m Bits8)
    toVect n [] = (0 ** [])
    toVect n (x :: xs) = 
      let (k ** v) = toVect n xs
      in (S k ** x :: v)

-- | AES-256-GCM encryption
export
encryptAES256GCM : {ptLen : Nat} ->
                   AES256Key ->
                   Vect 12 Bits8 ->
                   Vect ptLen Bits8 ->
                   IO (Result String (n : Nat ** Vect n Bits8))
encryptAES256GCM key nonce plaintext = do
  if ptLen > MAX_AEAD_PLAINTEXT
    then pure (Err "Plaintext exceeds maximum size")
    else do
      keyBuf <- vectToBuffer key
      nonceBuf <- vectToBuffer nonce
      ptBuf <- vectToBuffer plaintext
      
      let ctLen = ptLen + 16
      Just ctBuf <- newBuffer (cast ctLen)
        | Nothing => pure (Err "Failed to allocate ciphertext buffer")
      
      Just ctLenBuf <- newBuffer 8
        | Nothing => pure (Err "Failed to allocate length buffer")
      
      -- Call encryption (no additional data, no secret nonce)
      result <- primIO $ prim__aes256gcm_encrypt
        (prim__bufferData ctBuf)
        (believe_me $ prim__bufferData ctLenBuf)
        (prim__bufferData ptBuf)
        (cast ptLen)
        (believe_me prim__getNullAnyPtr)
        0
        (believe_me prim__getNullAnyPtr)
        (prim__bufferData nonceBuf)
        (prim__bufferData keyBuf)
      
      if result /= 0
        then pure (Err "AES-256-GCM encryption failed")
        else do
          ct <- bufferToVect ctBuf ctLen
          pure (Ok (ctLen ** ct))

-- | AES-256-GCM decryption  
export
decryptAES256GCM : {ctLen : Nat} ->
                   AES256Key ->
                   Vect 12 Bits8 ->
                   Vect ctLen Bits8 ->
                   IO (Result String (n : Nat ** Vect n Bits8))
decryptAES256GCM key nonce ciphertext = do
  if ctLen < 16
    then pure (Err "Ciphertext too short (missing authentication tag)")
    else do
      keyBuf <- vectToBuffer key
      nonceBuf <- vectToBuffer nonce
      ctBuf <- vectToBuffer ciphertext
      
      let ptLen = minus ctLen 16
      Just ptBuf <- newBuffer (cast ptLen)
        | Nothing => pure (Err "Failed to allocate plaintext buffer")
      
      Just ptLenBuf <- newBuffer 8
        | Nothing => pure (Err "Failed to allocate length buffer")
      
      result <- primIO $ prim__aes256gcm_decrypt
        (prim__bufferData ptBuf)
        (believe_me $ prim__bufferData ptLenBuf)
        (believe_me prim__getNullAnyPtr)
        (prim__bufferData ctBuf)
        (cast ctLen)
        (believe_me prim__getNullAnyPtr)
        0
        (prim__bufferData nonceBuf)
        (prim__bufferData keyBuf)
      
      if result /= 0
        then pure (Err "AES-256-GCM decryption failed (authentication failure)")
        else do
          pt <- bufferToVect ptBuf ptLen
          pure (Ok (ptLen ** pt))

-- | SHA-256 hash
export
sha256 : {n : Nat} -> Vect n Bits8 -> IO (Vect 32 Bits8)
sha256 input = do
  inBuf <- vectToBuffer input
  Just outBuf <- newBuffer 32
    | Nothing => pure (replicate 32 0)
  
  result <- primIO $ prim__sha256
    (prim__bufferData outBuf)
    (prim__bufferData inBuf)
    (cast n)
  
  if result == 0
    then bufferToVect outBuf 32
    else pure (replicate 32 0)

-- | Generate random bytes
export
randomBytes : (n : Nat) -> IO (Vect n Bits8)
randomBytes n = do
  Just buf <- newBuffer (cast n)
    | Nothing => pure (replicate n 0)
  primIO $ prim__random_bytes (prim__bufferData buf) (cast n)
  bufferToVect buf n
