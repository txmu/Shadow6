(* Transcript authentication and HKDF-SHA256; ciphers/key exchange use libsodium. *)
let random_nonce () =
  let fd = Unix.openfile "/dev/urandom" [Unix.O_RDONLY; Unix.O_CLOEXEC] 0 in
  Fun.protect ~finally:(fun () -> Unix.close fd) (fun () ->
    let result = Bytes.create 32 in
    let rec read off = if off < 32 then
      let n = Unix.read fd result off (32-off) in
      if n = 0 then failwith "entropy unavailable" else read (off+n)
    in read 0; result)
let tag ~key bytes = Digestif.SHA256.hmac_string ~key (Bytes.to_string bytes) |> Digestif.SHA256.to_raw_string
let equal a b = String.length a = String.length b &&
  let v = ref 0 in for i = 0 to String.length a - 1 do v := !v lor (Char.code a.[i] lxor Char.code b.[i]) done; !v = 0
let proof ~key domain a b = tag ~key (Bytes.concat Bytes.empty [Bytes.of_string domain; a; b]) |> Bytes.of_string
let authenticate ~key ~nonce response = equal (tag ~key nonce) (Bytes.to_string response)
let derive ~salt ~material ~info =
  let prk = tag ~key:salt material in
  tag ~key:prk (Bytes.of_string (info ^ "\001")) |> Bytes.of_string
