(* Small bindings to libsodium; wire framing/admission stay in OCaml. *)
type state = { raw:bytes; sending:bool; mutable active:bool }
external keypair : unit -> bytes * bytes = "s6epe_keypair"
external session_keys : bool -> bytes -> bytes -> bytes -> bytes * bytes = "s6epe_session_keys"
external seal : bytes -> bytes -> bytes -> bytes -> bytes = "s6epe_seal"
external open_capsule : bytes -> bytes -> bytes -> bytes -> bytes = "s6epe_open"
external init_push_raw : bytes -> bytes * bytes = "s6epe_init_push"
external init_pull_raw : bytes -> bytes -> bytes = "s6epe_init_pull"
external push_raw : bytes -> bytes -> bytes -> int -> bytes = "s6epe_push"
external pull_raw : bytes -> bytes -> bytes -> bytes * int = "s6epe_pull"

let message = 0
let rekey = 2
let final = 3
let overhead = 17
let header_bytes = 24
let close state = state.active <- false; Bytes.fill state.raw 0 (Bytes.length state.raw) '\000'

let init_push key =
  let raw, header = init_push_raw key in
  {raw; sending=true; active=true}, header
let init_pull key header = {raw=init_pull_raw key header; sending=false; active=true}
let push state ad payload tag =
  if not state.active || not state.sending then invalid_arg "inactive sending state";
  try let cipher = push_raw state.raw ad payload tag in
    if tag = final then state.active <- false; cipher
  with error -> state.active <- false; Bytes.fill state.raw 0 (Bytes.length state.raw) '\000'; raise error
let pull state ad cipher =
  if not state.active || state.sending then invalid_arg "inactive receiving state";
  try let payload, tag = pull_raw state.raw ad cipher in
    if tag = final then state.active <- false; payload, tag
  with error -> state.active <- false; Bytes.fill state.raw 0 (Bytes.length state.raw) '\000'; raise error
