(* Cryptography is deliberately delegated to the configured authenticated TLS
   transport. This module carries no native Core bytes and never implements a
   second cipher or protocol. *)
type state = Unauthenticated | Authenticated
let random_nonce () = Bytes.init 32 (fun _ -> Char.chr (Random.int 256))
let tag ~key bytes = Digestif.SHA256.hmac_string ~key (Bytes.to_string bytes) |> Digestif.SHA256.to_raw_string
let equal a b = String.length a = String.length b &&
  let v = ref 0 in for i = 0 to String.length a - 1 do v := !v lor (Char.code a.[i] lxor Char.code b.[i]) done; !v = 0
let authenticate ~key ~nonce response = equal (tag ~key nonce) (Bytes.to_string response)
